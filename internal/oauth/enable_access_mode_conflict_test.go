package oauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// TestEnableAccess_LocalModeConflict_SurfacesSpecificMessage reproduces the
// issue-492 race: a user reaches the enable_access phone/code flow while
// their account has no active row (or an active hosted row), but by the time
// the background login goroutine calls SaveSession, self-service activation
// has provisioned an active mode='local' row for the same user. SaveSession
// must refuse with db.ErrAccountModeConflict, and the next polled step page
// must render the specific Local Bridge message instead of a generic
// "save session" failure, with the audit log recording
// "connect:failed:local_mode_active".
func TestEnableAccess_LocalModeConflict_SurfacesSpecificMessage(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	es := driveToPhone(t, mux)

	// Advance to the code screen before the local row exists, mirroring a
	// hosted login already in flight when self-service activation lands.
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen: %d %s", rec.Code, rec.Body.String())
	}

	// Simulate the race: self-service activation provisions an active
	// mode='local' row for the same widget-proven user (210408407) while the
	// phone/code flow above is still in progress.
	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 210408407, "MashkovD", "Dmitry")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 210408407, "MashkovD", "Dmitry"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	// Submitting the code now runs telegram.Login (stub) then SaveSession,
	// which must refuse because the active row is now mode='local'.
	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}})
	// The terminal error screen (renderEnableError), not the retryable phone
	// step: restarting the flow cannot clear a mode conflict.
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code step after local-mode conflict = %d (want 400 error screen); body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Local Bridge") || !strings.Contains(body, "back to hosted mode") {
		t.Fatalf("expected the local-mode-conflict message, got: %s", body)
	}
	if strings.Contains(body, "Start again") {
		t.Errorf("mode conflict is terminal; page must not offer a retry: %s", body)
	}
	if strings.Contains(body, "save session:") {
		t.Errorf("rendered the generic save-session error instead of the specific message: %s", body)
	}

	entries, err := srv.store.ListAuditFor(ctx, uid, 10, time.Time{})
	if err != nil {
		t.Fatalf("ListAuditFor: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.ToolName == "connect:failed:local_mode_active" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("audit log missing connect:failed:local_mode_active entry; got %+v", entries)
	}

	// The local row itself must be untouched by the refused SaveSession.
	mode, err := srv.store.GetAccountMode(ctx, uid)
	if err != nil {
		t.Fatalf("GetAccountMode: %v", err)
	}
	if mode != db.ModeLocal {
		t.Errorf("mode after refused SaveSession = %q, want %q", mode, db.ModeLocal)
	}

	// The refusal is not enough on its own: telegram.Login persists its
	// session bytes through the gotd SessionStore before SaveSession is ever
	// called, so the local row's blob has already been overwritten by the time
	// the guard fires. Those bytes must be dropped, or the hosted worker can
	// act as the user through a row the operator believes is bridge-only.
	var sessionEncrypted []byte
	if scanErr := srv.store.DB.QueryRowContext(ctx,
		`SELECT session_encrypted FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL AND mode = $2`,
		uid, db.ModeLocal,
	).Scan(&sessionEncrypted); scanErr != nil {
		t.Fatalf("read local row: %v", scanErr)
	}
	if sessionEncrypted != nil {
		t.Errorf("local row still holds the hosted login's session bytes after a refused SaveSession")
	}
}

// TestEnableAccess_LocalModeConflict_RefusedBeforeLogin covers the common case
// the race test above cannot: the local row already exists when the user hits
// /start. Here the flow must be refused BEFORE telegram.Login runs at all —
// once it runs it has already written over the bridge's session bytes, and the
// best any later guard can do is clean up after the damage.
func TestEnableAccess_LocalModeConflict_RefusedBeforeLogin(t *testing.T) {
	inner := stubLogin(false, nil)
	var loginCalled atomic.Bool
	srv, mux := newEnableTestServer(t, func(ctx context.Context, apiID int, apiHash string,
		store *db.Store, uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		cfgs ...telegram.LoginConfig,
	) (int64, string, string, error) {
		loginCalled.Store(true)
		return inner(ctx, apiID, apiHash, store, uid, phone, askCode, askPassword, cfgs...)
	})
	es := driveToPhone(t, mux)

	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 210408407, "MashkovD", "Dmitry")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 210408407, "MashkovD", "Dmitry"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("start with an active local account = %d (want 400 error screen); body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "Local Bridge") {
		t.Fatalf("expected the local-mode-conflict message, got: %s", body)
	}
	if loginCalled.Load() {
		t.Error("telegram login ran despite an active local account; the bridge session was already overwritten")
	}

	entries, err := srv.store.ListAuditFor(ctx, uid, 10, time.Time{})
	if err != nil {
		t.Fatalf("ListAuditFor: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.ToolName == "connect:failed:local_mode_active" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("audit log missing connect:failed:local_mode_active entry; got %+v", entries)
	}
}
