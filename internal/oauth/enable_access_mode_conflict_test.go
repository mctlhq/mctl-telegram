package oauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
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
	if rec.Code != http.StatusOK {
		t.Fatalf("code step after local-mode conflict = %d (want 200 phone screen); body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Local Bridge") || !strings.Contains(body, "hosted mode first") {
		t.Fatalf("expected the local-mode-conflict message, got: %s", body)
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
}
