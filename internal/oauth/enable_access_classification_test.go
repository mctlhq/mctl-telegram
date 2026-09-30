package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	tdauth "github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tgerr"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// observedBadPasswordErr reproduces the wrapped error telegram.Login surfaces
// for a rejected 2FA password: gotd/td's telegram/auth.Flow.password wraps
// its own exported auth.ErrPasswordInvalid sentinel with the message "sign in
// with password", giving the literal observed string "sign in with password:
// invalid password" (see requirements.md's Open questions and design.md).
func observedBadPasswordErr() error {
	return fmt.Errorf("sign in with password: %w", tdauth.ErrPasswordInvalid)
}

// TestShortReason_BadPasswordAndAuthRestart is T9: the new AUTH_RESTART and
// bad_password arms map to their tokens, and every pre-existing mapping is
// unchanged.
func TestShortReason_BadPasswordAndAuthRestart(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"phone_invalid", tgerr.New(400, "PHONE_NUMBER_INVALID"), "phone_invalid"},
		{"code_invalid", tgerr.New(400, "PHONE_CODE_INVALID"), "code_invalid"},
		{"code_expired", tgerr.New(400, "PHONE_CODE_EXPIRED"), "code_expired"},
		{"flood_wait", tgerr.New(420, "FLOOD_WAIT_3"), "flood_wait"},
		{"timeout_deadline", context.DeadlineExceeded, "timeout"},
		{"timeout_canceled", context.Canceled, "timeout"},
		{"local_mode_active", db.ErrAccountModeConflict, "local_mode_active"},
		{"identity_mismatch", errors.New("resolved to a different Telegram account than expected"), "identity_mismatch"},
		{"identity_cleanup_timeout", errIdentityCleanupTimeout, "identity_cleanup_timeout"},
		{"unknown_nil", nil, "unknown"},
		{"unknown_other", errors.New("some other failure"), "unknown"},
		// New arms (issue-695).
		{"auth_restart", tgerr.New(500, "AUTH_RESTART"), "auth_restart"},
		{"bad_password_observed_string", observedBadPasswordErr(), "bad_password"},
		{"bad_password_sentinel_direct", tdauth.ErrPasswordInvalid, "bad_password"},
		{"bad_password_hash_invalid_substring", errors.New("check password: PASSWORD_HASH_INVALID"), "bad_password"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shortReason(tc.err); got != tc.want {
				t.Errorf("shortReason(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestFriendlyErr_BadPasswordAndAuthRestart confirms the matching friendlyErr
// wording, and that neither message echoes the raw error string.
func TestFriendlyErr_BadPasswordAndAuthRestart(t *testing.T) {
	if got := friendlyErr(tgerr.New(500, "AUTH_RESTART")); got != "Telegram ended the sign-in session. Submit your phone number again to get a fresh code." {
		t.Errorf("friendlyErr(AUTH_RESTART) = %q", got)
	}
	if got := friendlyErr(observedBadPasswordErr()); got != "That two-step verification password was not accepted. Check it and try again." {
		t.Errorf("friendlyErr(bad password) = %q", got)
	}
	// Every pre-existing mapping is unaffected.
	if got := friendlyErr(tgerr.New(400, "PHONE_NUMBER_INVALID")); !strings.Contains(got, "phone number is not valid") {
		t.Errorf("friendlyErr(PHONE_NUMBER_INVALID) regressed: %q", got)
	}
}

// stubLoginBadPassword fakes telegram.Login rejecting the 2FA password with
// the literal observed error string.
func stubLoginBadPassword() LoginFunc {
	return func(ctx context.Context, apiID int, apiHash string, store *db.Store,
		uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		_ ...telegram.LoginConfig,
	) (int64, string, string, error) {
		if _, err := askCode(ctx); err != nil {
			return 0, "", "", err
		}
		if _, err := askPassword(ctx); err != nil {
			return 0, "", "", err
		}
		return 0, "", "", observedBadPasswordErr()
	}
}

// stubLoginAuthRestart fakes telegram.Login failing at SendCode with
// Telegram's AUTH_RESTART, before ever asking for a code.
func stubLoginAuthRestart() LoginFunc {
	return func(ctx context.Context, apiID int, apiHash string, store *db.Store,
		uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		_ ...telegram.LoginConfig,
	) (int64, string, string, error) {
		return 0, "", "", tgerr.New(500, "AUTH_RESTART")
	}
}

// TestEnablePassword_WrongPassword_AuditAndCopy is T10: a rejected 2FA
// password is audited as connect:failed:bad_password and rendered with the
// new wording (not the old "The password was not accepted: ... Start
// again." wrapper), reusing the existing synthetic Dana persona.
func TestEnablePassword_WrongPassword_AuditAndCopy(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLoginBadPassword())
	es := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}}); rec.Code != http.StatusOK {
		t.Fatalf("start: %d", rec.Code)
	}
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "enable_access/password") {
		t.Fatalf("code did not render 2FA screen: %d %s", rec.Code, rec.Body.String())
	}

	rec := postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {es}, "password": {"wrong-password"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("password: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// The user lands on the phone step, so the copy must send them back
	// through phone + code rather than promise a password retry that the
	// already-exited login flow cannot accept.
	if !strings.Contains(body, badPasswordRestartMsg) {
		t.Errorf("expected the restart wording for bad_password, got: %s", body)
	}
	if strings.Contains(body, "Check it and try again") {
		t.Errorf("phone-step page promises a password retry it cannot offer: %s", body)
	}
	if strings.Contains(body, "invalid password") {
		t.Errorf("rendered page leaked the raw gotd error string: %s", body)
	}

	ctx := context.Background()
	uid, _ := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	entries, err := srv.store.ListAuditFor(ctx, uid, 10, time.Time{})
	if err != nil {
		t.Fatalf("ListAuditFor: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.ToolName == "connect:failed:bad_password" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an audit entry connect:failed:bad_password, got: %+v", entries)
	}
}

// TestEnableStart_AuthRestart_AuditLabel is T11: telegram.Login failing with
// AUTH_RESTART at the phone step is audited as connect:failed:auth_restart
// and rendered with the restart wording on the phone step (phone pre-filled).
func TestEnableStart_AuthRestart_AuditLabel(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLoginAuthRestart())
	es := driveToPhone(t, mux)

	rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "Telegram rejected the request") {
		t.Errorf("AUTH_RESTART is framed as a rejection (double wrapper): %s", body)
	}
	if !strings.Contains(body, "Telegram ended the sign-in session") {
		t.Errorf("expected the auth_restart wording on the phone step, got: %s", body)
	}
	if !strings.Contains(body, "+14155551234") {
		t.Errorf("expected the phone step to keep the phone field pre-filled, got: %s", body)
	}

	ctx := context.Background()
	uid, _ := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	entries, err := srv.store.ListAuditFor(ctx, uid, 10, time.Time{})
	if err != nil {
		t.Fatalf("ListAuditFor: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.ToolName == "connect:failed:auth_restart" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an audit entry connect:failed:auth_restart, got: %+v", entries)
	}
}

// TestAuthRestartAtCodeStep_NotDoubleFramed is T1: AUTH_RESTART surfacing
// after the SMS code was submitted (Telegram raises it from auth.signIn, so
// the code step is the step that actually sees it — see design.md) must
// render exactly friendlyErr's instruction, not the code step's generic
// "The code was not accepted: ... Start again to get a fresh code." wrapper
// double-framed around it.
func TestAuthRestartAtCodeStep_NotDoubleFramed(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, tgerr.New(500, "AUTH_RESTART")))
	es := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen: %d %s", rec.Code, rec.Body.String())
	}

	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("code: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	const want = "Telegram ended the sign-in session. Submit your phone number again to get a fresh code."
	if n := strings.Count(body, want); n != 1 {
		t.Errorf("expected %q exactly once, found %d times in: %s", want, n, body)
	}
	if strings.Contains(body, "The code was not accepted") {
		t.Errorf("AUTH_RESTART at the code step is still double-framed: %s", body)
	}
	if strings.Contains(body, "Start again to get a fresh code") {
		t.Errorf("AUTH_RESTART at the code step repeats the restart instruction: %s", body)
	}

	ctx := context.Background()
	uid, _ := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	entries, err := srv.store.ListAuditFor(ctx, uid, 10, time.Time{})
	if err != nil {
		t.Fatalf("ListAuditFor: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.ToolName == "connect:failed:auth_restart" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an audit entry connect:failed:auth_restart, got: %+v", entries)
	}
}

// TestAuthRestartAtPasswordStep_NotDoubleFramed is T2: AUTH_RESTART surfacing
// after the 2FA password was submitted must render exactly friendlyErr's
// instruction through handleEnablePassword's generic fallback arm, not the
// "The password was not accepted: ... Start again." wrapper double-framed
// around it.
func TestAuthRestartAtPasswordStep_NotDoubleFramed(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(true, tgerr.New(500, "AUTH_RESTART")))
	es := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen: %d %s", rec.Code, rec.Body.String())
	}
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "enable_access/password") {
		t.Fatalf("code did not render 2FA screen: %d %s", rec.Code, rec.Body.String())
	}

	rec := postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {es}, "password": {"whatever"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("password: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	const want = "Telegram ended the sign-in session. Submit your phone number again to get a fresh code."
	if n := strings.Count(body, want); n != 1 {
		t.Errorf("expected %q exactly once, found %d times in: %s", want, n, body)
	}
	if strings.Contains(body, "The password was not accepted") {
		t.Errorf("AUTH_RESTART at the password step is still double-framed: %s", body)
	}

	ctx := context.Background()
	uid, _ := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	entries, err := srv.store.ListAuditFor(ctx, uid, 10, time.Time{})
	if err != nil {
		t.Fatalf("ListAuditFor: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.ToolName == "connect:failed:auth_restart" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an audit entry connect:failed:auth_restart, got: %+v", entries)
	}
}

// TestFramedLoginErr_TableTest is the second half of T2: a table over the
// three step handlers' exact prefix/suffix pairs, proving non-AUTH_RESTART
// errors keep the legacy wording byte-for-byte while AUTH_RESTART always
// collapses to the bare friendlyErr instruction.
func TestFramedLoginErr_TableTest(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		suffix string
	}{
		{"phone step", "Telegram rejected the request: ", " Try again."},
		{"code step", "The code was not accepted: ", " Start again to get a fresh code."},
		{"password step", "The password was not accepted: ", " Start again."},
	}
	authRestartErr := tgerr.New(500, "AUTH_RESTART")
	otherErr := tgerr.New(400, "PHONE_NUMBER_INVALID")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := framedLoginErr(tc.prefix, authRestartErr, tc.suffix), friendlyErr(authRestartErr); got != want {
				t.Errorf("framedLoginErr(%q, AUTH_RESTART, %q) = %q, want bare friendlyErr %q", tc.prefix, tc.suffix, got, want)
			}
			want := tc.prefix + friendlyErr(otherErr) + tc.suffix
			if got := framedLoginErr(tc.prefix, otherErr, tc.suffix); got != want {
				t.Errorf("framedLoginErr(%q, PHONE_NUMBER_INVALID, %q) = %q, want %q", tc.prefix, tc.suffix, got, want)
			}
		})
	}
}

// TestIsBadPasswordErr_Nil pins that the predicate is nil-safe like its
// siblings, so a future caller that skips the nil guard cannot panic.
func TestIsBadPasswordErr_Nil(t *testing.T) {
	if isBadPasswordErr(nil) {
		t.Error("isBadPasswordErr(nil) = true, want false")
	}
}
