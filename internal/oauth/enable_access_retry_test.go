package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	tdauth "github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tgerr"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// retryingLogin fakes telegram.Login's re-asking (#900): a code other than
// goodCode is asked for again with a code_invalid Reprompt, up to
// telegram.LoginCodeAttempts codes, after which the flow ends with
// PHONE_CODE_INVALID. When goodPw is set the password step behaves the same
// way. Every code the login received is recorded in codes.
type retryingLogin struct {
	goodCode, goodPw string

	mu    sync.Mutex
	codes []string
}

func (l *retryingLogin) received() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.codes...)
}

func (l *retryingLogin) fn() LoginFunc {
	return func(ctx context.Context, apiID int, apiHash string, store *db.Store,
		uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		cfgs ...telegram.LoginConfig,
	) (int64, string, string, error) {
		promptCtx := ctx
		for attempt := 1; ; attempt++ {
			code, err := askCode(promptCtx)
			if err != nil {
				return 0, "", "", err
			}
			l.mu.Lock()
			l.codes = append(l.codes, code)
			l.mu.Unlock()
			if code == l.goodCode {
				break
			}
			if attempt == telegram.LoginCodeAttempts {
				return 0, "", "", fmt.Errorf("sign in: %w", tgerr.New(400, "PHONE_CODE_INVALID"))
			}
			promptCtx = telegram.WithReprompt(ctx, telegram.Reprompt{
				Reason: telegram.RepromptCodeInvalid, AttemptsLeft: telegram.LoginCodeAttempts - attempt,
			})
		}
		if l.goodPw != "" {
			promptCtx = ctx
			for attempt := 1; ; attempt++ {
				pw, err := askPassword(promptCtx)
				if err != nil {
					return 0, "", "", err
				}
				if pw == l.goodPw {
					break
				}
				if attempt == telegram.LoginPasswordAttempts {
					return 0, "", "", fmt.Errorf("check 2FA password: %w", tdauth.ErrPasswordInvalid)
				}
				promptCtx = telegram.WithReprompt(ctx, telegram.Reprompt{
					Reason: telegram.RepromptBadPassword, AttemptsLeft: telegram.LoginPasswordAttempts - attempt,
				})
			}
		}
		if err := handOverSession(cfgs, []byte("fake-mtproto-session")); err != nil {
			return 0, "", "", err
		}
		return 500100101, "Dana", "dana_tg", nil
	}
}

// startRetryFlow drives the synthetic Dana persona to the code screen.
func startRetryFlow(t *testing.T, l *retryingLogin) (*Server, *chi.Mux, string) {
	t.Helper()
	srv, mux := newEnableTestServer(t, l.fn())
	es := driveToPhone(t, mux)
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render the code screen: %d %s", rec.Code, rec.Body.String())
	}
	return srv, mux, es
}

func hasAudit(t *testing.T, srv *Server, tool string) bool {
	t.Helper()
	ctx := context.Background()
	uid, _ := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	entries, err := srv.store.ListAuditFor(ctx, uid, 50, time.Time{})
	if err != nil {
		t.Fatalf("ListAuditFor: %v", err)
	}
	for _, e := range entries {
		if e.ToolName == tool {
			return true
		}
	}
	return false
}

// The code reaches telegram.Login as its digits only, so a spaced or pasted
// code is not burned as a wrong one; input with no digits is still "no code".
func TestEnableCode_KeepsOnlyDigits(t *testing.T) {
	l := &retryingLogin{goodCode: "12345"}
	_, mux, es := startRetryFlow(t, l)

	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"code"}})
	if body := rec.Body.String(); !strings.Contains(body, "Enter the code Telegram sent you.") {
		t.Fatalf("a code with no digits must re-ask without reaching Telegram: %s", body)
	}
	if got := l.received(); len(got) != 0 {
		t.Fatalf("login received %q for an input with no digits", got)
	}

	rec = postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"Login code: 12 345."}})
	authCodeRedirect(t, rec)
	if got := l.received(); len(got) != 1 || got[0] != "12345" {
		t.Fatalf("login received %q, want [12345]", got)
	}
}

// A wrong code keeps the user on the code screen of the same flow, and the
// right code then completes it without a second SendCode.
func TestEnableCode_WrongThenRightCodeInOneFlow(t *testing.T) {
	l := &retryingLogin{goodCode: "12345"}
	srv, mux, es := startRetryFlow(t, l)
	flowBefore := getEnableSession(t, srv, es).flow

	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"54321"}})
	body := rec.Body.String()
	if !strings.Contains(body, "/oauth/telegram/enable_access/code") {
		t.Fatalf("a wrong code with attempts left must stay on the code screen: %s", body)
	}
	if !strings.Contains(body, "That code did not match, try again (2 attempts left).") {
		t.Errorf("code screen missing the retry notice: %s", body)
	}
	if !hasAudit(t, srv, "connect:retry:code_invalid") {
		t.Errorf("the retry must be audited as connect:retry:code_invalid")
	}
	if hasAudit(t, srv, "connect:failed:code_invalid") {
		t.Errorf("a retry must not be audited as a failed flow")
	}
	if sess := getEnableSession(t, srv, es); sess.step != stepCode || sess.flow != flowBefore {
		t.Errorf("after a wrong code: step=%v, same flow=%v; want stepCode on the same flow", sess.step, sess.flow == flowBefore)
	}

	rec = postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}})
	authCodeRedirect(t, rec)
	if got := l.received(); fmt.Sprint(got) != "[54321 12345]" {
		t.Errorf("login received %v, want [54321 12345]", got)
	}
}

// When the last attempt is used up the flow ends and the user is sent back to
// the phone screen, as before #900.
func TestEnableCode_AttemptsExhaustedEndsTheFlow(t *testing.T) {
	l := &retryingLogin{goodCode: "12345"}
	srv, mux, es := startRetryFlow(t, l)

	var rec *httptest.ResponseRecorder
	for i := 0; i < telegram.LoginCodeAttempts; i++ {
		rec = postForm(t, mux, "/oauth/telegram/enable_access/code",
			url.Values{"es": {es}, "code": {"00000"}})
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/oauth/telegram/enable_access/start") || !strings.Contains(body, "not accepted") {
		t.Fatalf("exhausted attempts must land on the phone screen with the rejection: %s", body)
	}
	if !hasAudit(t, srv, "connect:failed:code_invalid") {
		t.Errorf("the ended flow must be audited as connect:failed:code_invalid")
	}
}

// A wrong 2FA password keeps the user on the password screen of the same
// flow, and the right one then completes it.
func TestEnablePassword_WrongThenRightPasswordInOneFlow(t *testing.T) {
	l := &retryingLogin{goodCode: "12345", goodPw: "hunter2"}
	srv, mux, es := startRetryFlow(t, l)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}}); !strings.Contains(rec.Body.String(), "enable_access/password") {
		t.Fatalf("code did not render the 2FA screen: %s", rec.Body.String())
	}
	rec := postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {es}, "password": {"hunter1"}})
	body := rec.Body.String()
	if !strings.Contains(body, "/oauth/telegram/enable_access/password") {
		t.Fatalf("a wrong password with attempts left must stay on the password screen: %s", body)
	}
	if !strings.Contains(body, "That password did not match, try again (2 attempts left).") {
		t.Errorf("password screen missing the retry notice: %s", body)
	}
	if !hasAudit(t, srv, "connect:retry:bad_password") {
		t.Errorf("the retry must be audited as connect:retry:bad_password")
	}

	rec = postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {es}, "password": {"hunter2"}})
	authCodeRedirect(t, rec)
}

// The code screen says where the code actually arrives: a message from
// "Telegram" in the app rather than an SMS, without promising it never is
// one: Telegram falls back to SMS when no other session is active (#900).
func TestEnableCodePage_SaysCodeArrivesInTheApp(t *testing.T) {
	rec := httptest.NewRecorder()
	renderEnableCode(rec, enableCodePage{Issuer: "https://tg.mctl.ai", EnableToken: "tok", Phone: "+14155551234"})
	body := rec.Body.String()
	for _, want := range []string{"usually arrives", "message from <strong>Telegram</strong>", "inside the Telegram app", "rather than by SMS"} {
		if !strings.Contains(body, want) {
			t.Errorf("code screen missing %q: %s", want, body)
		}
	}
}

func TestRepromptMessages(t *testing.T) {
	for _, tc := range []struct {
		got, want string
	}{
		{codeRepromptMsg(telegram.Reprompt{Reason: telegram.RepromptCodeInvalid, AttemptsLeft: 1}), "That code did not match, try again (1 attempt left)."},
		{codeRepromptMsg(telegram.Reprompt{Reason: telegram.RepromptAuthRestart, AttemptsLeft: 3}), "Telegram restarted the sign-in and sent you a new code. Enter the new code."},
		{passwordRepromptMsg(telegram.Reprompt{Reason: telegram.RepromptBadPassword, AttemptsLeft: 2}), "That password did not match, try again (2 attempts left)."},
	} {
		if tc.got != tc.want {
			t.Errorf("got %q, want %q", tc.got, tc.want)
		}
	}
}

// restartDuringPasswordLogin fakes telegram.Login hitting AUTH_RESTART in the
// 2FA check after one wrong password: it restarts the sign-in and asks for the
// new code with an auth_restart Reprompt, as runPhoneFlow does. The new code
// then completes the flow (the stub does not ask for the password again).
func restartDuringPasswordLogin() LoginFunc {
	return func(ctx context.Context, apiID int, apiHash string, store *db.Store,
		uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		cfgs ...telegram.LoginConfig,
	) (int64, string, string, error) {
		if _, err := askCode(ctx); err != nil {
			return 0, "", "", err
		}
		if _, err := askPassword(ctx); err != nil {
			return 0, "", "", err
		}
		// Wrong password, then Telegram answers the second check with AUTH_RESTART.
		if _, err := askPassword(telegram.WithReprompt(ctx, telegram.Reprompt{
			Reason: telegram.RepromptBadPassword, AttemptsLeft: telegram.LoginPasswordAttempts - 1,
		})); err != nil {
			return 0, "", "", err
		}
		code, err := askCode(telegram.WithReprompt(ctx, telegram.Reprompt{
			Reason: telegram.RepromptAuthRestart, AttemptsLeft: telegram.LoginCodeAttempts,
		}))
		if err != nil {
			return 0, "", "", err
		}
		if code != "67890" {
			return 0, "", "", fmt.Errorf("sign in: %w", tgerr.New(400, "PHONE_CODE_INVALID"))
		}
		if err := handOverSession(cfgs, []byte("fake-mtproto-session")); err != nil {
			return 0, "", "", err
		}
		return 500100101, "Dana", "dana_tg", nil
	}
}

// An AUTH_RESTART during the 2FA check sends a new code; the password POST
// must move the user to the code screen to enter it, not wait out
// enableSignInWait while the flow is parked asking for that code.
func TestEnablePassword_AuthRestartMovesToCodeStep(t *testing.T) {
	srv, mux := newEnableTestServer(t, restartDuringPasswordLogin())
	es := driveToPhone(t, mux)
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render the code screen: %s", rec.Body.String())
	}
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}}); !strings.Contains(rec.Body.String(), "enable_access/password") {
		t.Fatalf("code did not render the 2FA screen: %s", rec.Body.String())
	}
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {es}, "password": {"hunter1"}}); !strings.Contains(rec.Body.String(), "That password did not match") {
		t.Fatalf("wrong password did not re-render the password screen: %s", rec.Body.String())
	}

	start := time.Now()
	rec := postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {es}, "password": {"hunter2"}})
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("password POST took %s: it waited for the timeout instead of following the restart", d)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="/oauth/telegram/enable_access/code"`) {
		t.Fatalf("AUTH_RESTART during the password check must render the code screen: %s", body)
	}
	if !strings.Contains(body, "Telegram restarted the sign-in and sent you a new code.") {
		t.Errorf("code screen missing the new-code notice: %s", body)
	}
	if !hasAudit(t, srv, "connect:retry:auth_restart") {
		t.Errorf("the restart must be audited as connect:retry:auth_restart")
	}
	if hasAudit(t, srv, "connect:failed:timeout") {
		t.Errorf("the restart must not be audited as a timeout")
	}

	rec = postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"67890"}})
	authCodeRedirect(t, rec)
}
