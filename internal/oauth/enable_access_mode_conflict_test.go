package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

// TestEnableAccess_LocalModeConflict_RaceRefusalIsTerminal covers the branch
// startLoginFlow's own re-check actually lands in, which the code/password
// handlers' terminal screens never reach.
//
// When the re-check refuses, it sets lf.err and returns before lf.needCode is
// ever signalled, so lf.done closes first and handleEnableStart takes its
// `case <-lf.done` arm. That arm renders "Telegram rejected the request: ...
// Try again." and books the outcome as result="error" — a label reserved for
// real RPC failures like PHONE_NUMBER_INVALID. Telegram was never contacted,
// the condition is terminal, and "Try again" invites a loop against a guard
// that cannot clear.
//
// The race is driven deterministically by holding the uid login mutex: the
// pre-flight gate in handleEnableStart runs before startLoginFlow is called
// and passes (no local row yet), the flow goroutine then blocks on that mutex,
// and the local account is provisioned into exactly that window.
func TestEnableAccess_LocalModeConflict_RaceRefusalIsTerminal(t *testing.T) {
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
	esTok := driveToPhone(t, mux)

	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 210408407, "MashkovD", "Dmitry")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	// Announce the moment the flow goroutine is about to park on the uid
	// mutex. Set before the /start request below and never mutated after, so
	// the handler goroutine only ever reads it. Polling srv.enables[esTok].flow
	// instead would read a field handleEnableStart writes under es.lock while
	// this goroutine holds only srv.mu (which guards the map, not the entry) —
	// a data race, and CI runs `go test -race ./...`.
	parked := make(chan struct{})
	srv.loginFlowParked = sync.OnceFunc(func() { close(parked) })

	ul := srv.uidLoginMutex(uid)
	ul.Lock()

	type res struct{ rec *httptest.ResponseRecorder }
	done := make(chan res, 1)
	go func() {
		done <- res{postForm(t, mux, "/oauth/telegram/enable_access/start",
			url.Values{"es": {esTok}, "phone": {"+14155551234"}})}
	}()

	// Wait until handleEnableStart has passed its pre-flight gate and handed
	// off to the flow goroutine, which is now parked on the mutex we hold.
	select {
	case <-parked:
	case <-time.After(5 * time.Second):
		ul.Unlock()
		t.Fatal("handleEnableStart never reached startLoginFlow; the pre-flight gate refused instead, so this test is not exercising the re-check")
	}

	if err := srv.store.ProvisionLocalAccount(ctx, uid, 210408407, "MashkovD", "Dmitry"); err != nil {
		ul.Unlock()
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}
	ul.Unlock()

	rec := (<-done).rec
	body := rec.Body.String()
	if !strings.Contains(body, "Local Bridge") {
		t.Fatalf("race refusal did not surface the local-mode message; body=%s", body)
	}
	if strings.Contains(body, "Telegram rejected the request") {
		t.Errorf("race refusal rendered as a Telegram RPC failure; Telegram was never contacted. body=%s", body)
	}
	if strings.Contains(body, "Try again") {
		t.Errorf("race refusal offers a retry against a terminal condition. body=%s", body)
	}
	if loginCalled.Load() {
		t.Error("telegram login ran despite the local account winning the race; the bridge session would already be overwritten")
	}

	// The refusal must also leave the session on stepPhone. handleEnableStart
	// sets es.step = stepCode before the select it refuses in, and its
	// duplicate-/start guard keys on (stepCode, flow != nil) -- so without a
	// reset a resubmitted /start is handed a code screen for an SMS Telegram
	// was never asked to send, and returns from the guard before ever reaching
	// the pre-flight mode gate that would have refused it again.
	again := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}})
	againBody := again.Body.String()
	if strings.Contains(againBody, "enable_access/code") {
		t.Errorf("resubmitted /start after a terminal refusal rendered the code screen; body=%s", againBody)
	}
	if !strings.Contains(againBody, "Local Bridge") {
		t.Errorf("resubmitted /start did not re-refuse via the pre-flight mode gate; body=%s", againBody)
	}
}

// TestEnableAccess_TerminalRefusalInCodeStep_ResetsStep is the same property for
// handleEnableCode's terminal arm, which is reached on the other side of the
// window: the login already ran and SaveSession refused. Kept separate from the
// race test because it needs no goroutine -- the local row is provisioned after
// the code screen is on screen, so the refusal lands in the code handler.
func TestEnableAccess_TerminalRefusalInCodeStep_ResetsStep(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	esTok := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen: %d %s", rec.Code, rec.Body.String())
	}

	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 210408407, "MashkovD", "Dmitry")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 210408407, "MashkovD", "Dmitry"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {esTok}, "code": {"12345"}}); !strings.Contains(rec.Body.String(), "Local Bridge") {
		t.Fatalf("code step did not refuse with the local-mode message: %s", rec.Body.String())
	}

	// es.step was stepCode when the refusal rendered; if the terminal arm did
	// not reset it, this resubmit trips the duplicate-/start guard and gets a
	// code form back instead of the refusal.
	again := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}})
	againBody := again.Body.String()
	if strings.Contains(againBody, "enable_access/code") {
		t.Errorf("resubmitted /start after a terminal refusal rendered the code screen; body=%s", againBody)
	}
	if !strings.Contains(againBody, "Local Bridge") {
		t.Errorf("resubmitted /start did not re-refuse via the pre-flight mode gate; body=%s", againBody)
	}
}
