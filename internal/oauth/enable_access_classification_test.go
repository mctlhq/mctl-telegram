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
	if !strings.Contains(body, "That two-step verification password was not accepted. Enter your phone number again to get a fresh login code.") {
		t.Errorf("expected the new bad_password wording, got: %s", body)
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
