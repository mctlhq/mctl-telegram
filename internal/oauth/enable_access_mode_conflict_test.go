package oauth

import (
	"context"
	"errors"
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
	// mode='local' row for the same widget-proven user (500100101) while the
	// phone/code flow above is still in progress.
	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 500100101, "dana_tg", "Dana"); err != nil {
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
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 500100101, "dana_tg", "Dana"); err != nil {
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
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
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

	if err := srv.store.ProvisionLocalAccount(ctx, uid, 500100101, "dana_tg", "Dana"); err != nil {
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

// TestEnableAccess_TerminalRefusalInPasswordStep_ResetsStep is the third
// terminal arm. It is worth its own test rather than a table row: the reset
// here crosses a different starting step (stepPassword, not stepCode), so it
// takes a distinct path through both the duplicate-/start guard and
// handleEnablePassword's own step fallback.
func TestEnableAccess_TerminalRefusalInPasswordStep_ResetsStep(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(true, nil)) // 2FA path
	esTok := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen: %s", rec.Body.String())
	}
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {esTok}, "code": {"12345"}}); !strings.Contains(rec.Body.String(), "enable_access/password") {
		t.Fatalf("code did not render password screen: %s", rec.Body.String())
	}

	// The local row lands while the 2FA screen is up, so the refusal comes out
	// of handleEnablePassword rather than handleEnableCode.
	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 500100101, "dana_tg", "Dana"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {esTok}, "password": {"hunter2"}}); !strings.Contains(rec.Body.String(), "Local Bridge") {
		t.Fatalf("password step did not refuse with the local-mode message: %s", rec.Body.String())
	}

	// Route back in #1: /start. Must re-refuse through the pre-flight gate,
	// not hand back a code screen via the duplicate guard.
	again := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}})
	if body := again.Body.String(); strings.Contains(body, "enable_access/code") {
		t.Errorf("resubmitted /start after a terminal refusal rendered the code screen; body=%s", body)
	} else if !strings.Contains(body, "Local Bridge") {
		t.Errorf("resubmitted /start did not re-refuse via the pre-flight mode gate; body=%s", body)
	}

	// Route back in #2: re-POST the password step itself (browser back, or a
	// client reissuing its last request). The step fallback must show the
	// terminal screen, not "Please start again." — restarting cannot clear a
	// mode conflict, so inviting a retry is the wrong answer.
	replay := postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {esTok}, "password": {"hunter2"}})
	if body := replay.Body.String(); strings.Contains(body, "Please start again") {
		t.Errorf("password re-POST after a terminal refusal offered a retry; body=%s", body)
	} else if !strings.Contains(body, "Local Bridge") {
		t.Errorf("password re-POST did not re-render the terminal screen; body=%s", body)
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
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 500100101, "dana_tg", "Dana"); err != nil {
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

	// The other route back: re-POST the code step. Resetting es.step moved this
	// off handleEnableCode's happy path and onto its fallback, which offers
	// "Please start again." — so the fallback has to know the session is dead.
	replay := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {esTok}, "code": {"12345"}})
	if body := replay.Body.String(); strings.Contains(body, "Please start again") {
		t.Errorf("code re-POST after a terminal refusal offered a retry; body=%s", body)
	} else if !strings.Contains(body, "Local Bridge") {
		t.Errorf("code re-POST did not re-render the terminal screen; body=%s", body)
	}
}

// TestAbandonFlow_ResetsStepAndCancels drives the helper directly rather than
// through a handler, because two of its three effects are invisible from the
// outside once the third has happened.
//
// Clearing es.flow alone is enough to make the handler-level assertions above
// pass: the duplicate-/start guard and both step fallbacks are conjunctions
// that already fail on es.flow == nil, so mutating away the step reset leaves
// them green. That does not make the reset dead — es.step is the session's
// record of which screen the user is on, and renderEnablePhoneStep exists
// precisely so it never lags reality — but it does mean the HTTP tests cannot
// pin it, and an unpinned line is one refactor from being deleted as redundant.
//
// The cancel has the same problem in reverse: it only matters when the flow is
// still running, which is the enableSendCodeWait path, and by then no handler
// is looking.
func TestAbandonFlow_ResetsStepAndCancels(t *testing.T) {
	cancelled := false
	es := &enableSession{
		step: stepCode,
		flow: &loginFlow{cancel: func() { cancelled = true }},
	}

	es.abandonFlow()

	if es.step != stepPhone {
		t.Errorf("step = %v, want stepPhone: a session left on stepCode claims a screen the user is not on", es.step)
	}
	if es.flow != nil {
		t.Error("flow was not released")
	}
	if !cancelled {
		t.Error("a still-running flow was dropped without being cancelled; the enableSendCodeWait goroutine would outlive the request that ended it")
	}
}

// TestEnableAccess_ModeCheckFailure_IsNotTerminal covers the other half of the
// guard the mode-conflict tests exercise: the account-mode query failing rather
// than answering "local". The two halves deliberately do different things to
// the session — a conflict is terminal, a store outage is not — and that
// distinction had nothing pinning it.
func TestEnableAccess_ModeCheckFailure_IsNotTerminal(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	esTok := driveToPhone(t, mux)

	var fail atomic.Bool
	fail.Store(true)
	srv.modeCheckFn = func(context.Context, int64) (bool, error) {
		if fail.Load() {
			return false, errors.New("connection refused")
		}
		return false, nil
	}

	rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}})
	body := rec.Body.String()
	if !strings.Contains(body, "Could not verify this account") {
		t.Fatalf("mode-check failure did not surface its own wording; body=%s", body)
	}
	if strings.Contains(body, "Local Bridge") {
		t.Errorf("a store outage rendered as a mode conflict; body=%s", body)
	}
	if strings.Contains(body, "Telegram rejected the request") {
		t.Errorf("a store outage rendered as a Telegram RPC failure; Telegram was never contacted. body=%s", body)
	}
	// Retryable means the user gets their form back. The dead-end template
	// offers "Try again" on a page with nothing to try again with, and would
	// make this outcome indistinguishable from the terminal one.
	if !strings.Contains(body, "enable_access/start") {
		t.Errorf("a retryable refusal rendered the dead-end page instead of the phone form; body=%s", body)
	}
	if !strings.Contains(body, "+14155551234") {
		t.Errorf("the phone was not carried back into the form; body=%s", body)
	}

	// The refusal is retryable, so unlike a mode conflict it must not stick:
	// once the store answers again the same session has to be able to proceed.
	fail.Store(false)
	rec = postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}})
	if body := rec.Body.String(); !strings.Contains(body, "enable_access/code") {
		t.Errorf("retry after a recovered store did not reach the code screen; body=%s", body)
	}
}

// TestEnableAccess_TerminalMessageDoesNotOutliveItsCondition pins the other
// direction: a terminal refusal must not still be on file after the account is
// switched back to hosted and the same session successfully restarts. The step
// fallbacks read terminalMsg, so a stale one tells a user whose reconnect is
// now working that restarting cannot help.
func TestEnableAccess_TerminalMessageDoesNotOutliveItsCondition(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	esTok := driveToPhone(t, mux)

	var local atomic.Bool
	local.Store(true)
	srv.modeCheckFn = func(context.Context, int64) (bool, error) { return local.Load(), nil }

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "Local Bridge") {
		t.Fatalf("gate did not refuse while the account was local: %s", rec.Body.String())
	}

	// The operator switches the account back to hosted, inside the same es.
	local.Store(false)
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("restart after the flip did not reach the code screen: %s", rec.Body.String())
	}

	// Now drive a step fallback: the code form re-POSTed after the flow has
	// moved on. It must offer the retry, not replay the refusal from before.
	srv.mu.Lock()
	es := srv.enables[esTok]
	srv.mu.Unlock()
	es.lock.Lock()
	es.step = stepPhone // what the enableSignInWait arm leaves behind
	es.lock.Unlock()

	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {esTok}, "code": {"12345"}})
	if body := rec.Body.String(); strings.Contains(body, "Local Bridge") {
		t.Errorf("a stale terminal message told a user with a hosted account to stop trying; body=%s", body)
	}
}

// TestEnableAccess_ModeCheckFailure_DropsAStaleTerminalMessage is the same
// property reached through the arm that cannot re-derive the account state.
// A store failure knows only "unknown", and "unknown" must not outrank the
// retry it offers: leaving a cached refusal on file would let a step fallback
// replay it to an account that has since been switched back to hosted.
//
// This is also the pin for the hoisted clear at the top of handleEnableStart:
// the only /start calls below are the terminal refusal that sets the message
// and the mode-check failure that must drop it, so no successful pass-through
// can account for the message being gone. Deleting the hoisted clear turns
// this test red.
func TestEnableAccess_ModeCheckFailure_DropsAStaleTerminalMessage(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	esTok := driveToPhone(t, mux)

	mode := make(chan struct {
		local bool
		err   error
	}, 8)
	srv.modeCheckFn = func(context.Context, int64) (bool, error) {
		r := <-mode
		return r.local, r.err
	}

	// 1. Local row active -> terminal refusal, terminalMsg set.
	mode <- struct {
		local bool
		err   error
	}{true, nil}
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "Local Bridge") {
		t.Fatalf("gate did not refuse while the account was local: %s", rec.Body.String())
	}

	// 2. The account goes back to hosted, and 3. the next /start hits a store
	// blip, so the gate refuses without being able to say what the mode is.
	mode <- struct {
		local bool
		err   error
	}{false, errors.New("connection refused")}
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "Could not verify this account") {
		t.Fatalf("store blip did not render the retryable refusal: %s", rec.Body.String())
	}

	// 4. A code re-POST must now get the retry framing, not the refusal from
	// step 1 that nothing has been able to confirm since.
	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {esTok}, "code": {"12345"}})
	if body := rec.Body.String(); strings.Contains(body, "Local Bridge") {
		t.Errorf("a refusal the server could no longer confirm was replayed as fact; body=%s", body)
	}
}

// TestEnableAccess_StraySessionRepaired_WhenReloadFindsNothing covers an exit
// between the login and SaveSession that the repair used to miss: the login
// succeeds, but the reload finds no bytes and the flow returns before
// SaveSession — where the only repair used to hang.
//
// The precondition is the multi-active-row state ProvisionLocalAccount's own
// doc names: a local row provisioned in the window after the login returned.
// It carries a NULL blob and is the newest active row, so LoadSession answers
// nil, while the bytes the gotd SessionStore wrote a moment earlier sit on the
// older hosted row. Leaving them there is the whole failure this change
// exists to prevent — a hosted worker holding a live session for a user the
// operator believes is bridge-only.
func TestEnableAccess_StraySessionRepaired_WhenReloadFindsNothing(t *testing.T) {
	ctx := context.Background()
	var srv *Server

	srv, mux := newEnableTestServer(t, func(lctx context.Context, apiID int, apiHash string,
		store *db.Store, uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		_ ...telegram.LoginConfig,
	) (int64, string, string, error) {
		if _, err := askCode(lctx); err != nil {
			return 0, "", "", err
		}
		// gotd's SessionStore write. With no loaded row id it targets every
		// active row; here that is the hosted row created below.
		if err := store.UpdateSessionBlob(lctx, uid, []byte("fake-mtproto-session")); err != nil {
			return 0, "", "", err
		}
		// Self-service activation lands in the window between the login
		// returning and the reload. Direct SQL because ProvisionLocalAccount
		// refuses while another active row exists — that guard is exactly what
		// makes this state a race rather than a normal one.
		if _, err := store.DB.ExecContext(lctx,
			`INSERT INTO telegram_accounts(user_id, telegram_user_id, display_name, username,
			                               session_encrypted, mode, send_enabled, connected_at)
			 VALUES ($1, $2, $3, $4, NULL, $5, $6, CURRENT_TIMESTAMP)`,
			uid, 500100101, "Dana", "dana_tg", db.ModeLocal, false); err != nil {
			return 0, "", "", err
		}
		return 500100101, "Dana", "dana_tg", nil
	})
	esTok := driveToPhone(t, mux)

	uid, err := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	// The hosted row the login's bytes will land on.
	if err := srv.store.SaveSession(ctx, uid, []byte("previous-session"), 500100101, "Dana", "dana_tg"); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen: %s", rec.Body.String())
	}
	rec := postForm(t, mux, "/oauth/telegram/enable_access/code", url.Values{"es": {esTok}, "code": {"12345"}})

	// This is the discriminator, and it has to be checked: the SaveSession
	// path — which the old sentinel-gated code already covered — leaves the
	// same two rows in the same state, so both assertions below pass on it
	// too. Only the error text says which exit ran. Without this, a change to
	// LoadSessionWithID's row selection could silently re-point the test at
	// the path it says it is not exercising.
	if body := rec.Body.String(); !strings.Contains(body, "no session bytes were persisted") {
		t.Fatalf("the flow did not take the reload bail-out this test is named for; body=%s", body)
	}

	var blob []byte
	if err := srv.store.DB.QueryRowContext(ctx,
		`SELECT session_encrypted FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL AND mode = $2`, uid, db.ModeHosted).Scan(&blob); err != nil {
		t.Fatalf("read hosted row: %v", err)
	}
	if blob != nil {
		t.Error("the login's bytes survived a bail-out before SaveSession; a hosted worker could act as a user the operator believes is bridge-only")
	}
}

// TestEnableAccess_IdentityMismatch_DoesNotRevokeTheBridge covers the one exit
// where the deferred repair is not enough on its own, because the branch used
// to destroy the thing the repair protects.
//
// RevokeActiveSession is `WHERE user_id AND revoked_at IS NULL` — every active
// row. On the race this block assumes, that includes the bridge-only row, so
// the mismatch bail-out revoked a valid Local Bridge account. It also silenced
// the repair: both ClearStraySessionIfLocal's EXISTS and LoadSession filter on
// revoked_at IS NULL, so after the revoke there is nothing left to match.
//
// Both properties are asserted, because either one alone would pass on the old
// behaviour combined with the other bug.
func TestEnableAccess_IdentityMismatch_DoesNotRevokeTheBridge(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLoginWrongAccount())
	esTok := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen: %s", rec.Body.String())
	}

	// The bridge row lands in the race window, exactly as in the other
	// mode-conflict tests.
	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 500100101, "dana_tg", "Dana"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {esTok}, "code": {"12345"}})
	if body := rec.Body.String(); !strings.Contains(body, "different Telegram account") {
		t.Fatalf("mismatch was not reported to the user; body=%s", body)
	}

	var blob []byte
	if err := srv.store.DB.QueryRowContext(ctx,
		`SELECT session_encrypted FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL AND mode = $2`,
		uid, db.ModeLocal).Scan(&blob); err != nil {
		// sql.ErrNoRows here means the row was revoked, which is the bug.
		t.Fatalf("the bridge row is no longer active after an identity mismatch: %v", err)
	}
	if blob != nil {
		t.Error("the wrong account's session bytes survived on the bridge row; a later callback could issue a token backed by them")
	}
}

// TestEnableAccess_IdentityMismatch_UnknownRevokesTheBridge is the sibling
// DoesNotRevokeTheBridge does not cover: cErr != nil, the branch that answers
// "unknown" by revoking — i.e. by performing on purpose the destruction the
// rest of #492 exists to prevent. Dropping `local = false` or treating an
// unknown check as the local path leaves that test (and TelegramIDMismatch)
// green, because nothing else drives the error half of the seam.
func TestEnableAccess_IdentityMismatch_UnknownRevokesTheBridge(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLoginWrongAccount())
	esTok := driveToPhone(t, mux)

	// Fail only the identity-mismatch check (third call). The first two are
	// handleEnableStart's pre-flight gate and startLoginFlow's re-check;
	// those must pass so the flow reaches the mismatch branch. Assigned
	// before /start and never rewritten: a mid-flight write races with the
	// flow goroutine's reads (see Server.modeCheckFn).
	var checks atomic.Int32
	srv.modeCheckFn = func(context.Context, int64) (bool, error) {
		if checks.Add(1) >= 3 {
			return false, errors.New("boom")
		}
		return false, nil
	}

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen: %s", rec.Body.String())
	}

	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 500100101, "dana_tg", "Dana"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {esTok}, "code": {"12345"}})
	body := rec.Body.String()
	if !strings.Contains(body, "different Telegram account") {
		t.Fatalf("unknown fallback must still report the identity mismatch, not a revoke error; body=%s", body)
	}
	if strings.Contains(body, "revoke wrong-account") {
		t.Errorf("user saw the revoke error instead of the identity mismatch; body=%s", body)
	}
	if strings.Contains(body, "login attempt expired") {
		t.Errorf("unknown fallback rendered as a CodeTTL expiry; body=%s", body)
	}

	var n int
	if err := srv.store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL AND mode = $2`,
		uid, db.ModeLocal).Scan(&n); err != nil {
		t.Fatalf("count local rows: %v", err)
	}
	if n != 0 {
		t.Error("unknown-mode fallback left the bridge row active; that branch must revoke")
	}
}

// TestEnableAccess_IdentityMismatch_ExpiredFlowStillReportsMismatch pins the
// other half of the same branch: the check and the revoke/repair must not
// inherit bgCtx's CodeTTL deadline. On expiry the check would fail, local
// would flip to false, the revoke on the same dead context would fail too,
// and friendlyErr would render "the login attempt expired." instead of the
// identity mismatch — a different answer at second 59 and second 61 of the
// same flow for no reason the code states.
func TestEnableAccess_IdentityMismatch_ExpiredFlowStillReportsMismatch(t *testing.T) {
	srv, mux := newEnableTestServer(t, func(ctx context.Context, apiID int, apiHash string,
		store *db.Store, uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		_ ...telegram.LoginConfig,
	) (int64, string, string, error) {
		if _, err := askCode(ctx); err != nil {
			return 0, "", "", err
		}
		if err := store.UpdateSessionBlob(ctx, uid, []byte("wrong-account-session")); err != nil {
			return 0, "", "", err
		}
		// Wait out the flow's CodeTTL so the identity-mismatch branch runs
		// after bgCtx is dead. A fixed sleep would also expire it; waiting
		// on ctx.Done is what makes a too-generous TTL fail this test
		// instead of silently exercising the live-context path.
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
			return 0, "", "", errors.New("test: flow context still alive; not exercising the expired-deadline path")
		}
		return 999000111, "Someone Else", "someoneelse", nil
	}, func(c *Config) {
		c.CodeTTL = time.Second
	})
	esTok := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen (CodeTTL too short for the harness?): %s", rec.Body.String())
	}

	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 500100101, "dana_tg", "Dana"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {esTok}, "code": {"12345"}})
	body := rec.Body.String()
	if !strings.Contains(body, "different Telegram account") {
		t.Fatalf("expired flow context changed the identity-mismatch answer; body=%s", body)
	}
	if strings.Contains(body, "login attempt expired") {
		t.Errorf("identity mismatch on an expired CodeTTL rendered as a login expiry; body=%s", body)
	}

	var blob []byte
	if err := srv.store.DB.QueryRowContext(ctx,
		`SELECT session_encrypted FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL AND mode = $2`,
		uid, db.ModeLocal).Scan(&blob); err != nil {
		t.Fatalf("the bridge row is no longer active after an identity mismatch on an expired flow: %v", err)
	}
	if blob != nil {
		t.Error("the wrong account's session bytes survived on the bridge row")
	}
}

// TestEnableAccess_IdentityMismatch_LocalCleanupFailureSurfaces is the
// counterpart of the revoke arm's "A failed revoke must surface". The local
// half used to leave a failed ClearStraySessionIfLocal to the deferred
// repair, whose only failure handling is slog.Error, so lf.err still carried
// only the identity-mismatch message and nothing told the caller the cleanup
// did not happen.
func TestEnableAccess_IdentityMismatch_LocalCleanupFailureSurfaces(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLoginWrongAccount())
	esTok := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen: %s", rec.Body.String())
	}

	srv.clearStrayFn = func(context.Context, int64) error {
		return errors.New("repair timed out")
	}

	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 500100101, "dana_tg", "Dana"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {esTok}, "code": {"12345"}})
	body := rec.Body.String()
	if !strings.Contains(body, "clear wrong-account session") {
		t.Fatalf("a failed local cleanup was not surfaced; body=%s", body)
	}
}

// TestEnableAccess_IdentityMismatch_CleanupDeadlineIsNotLoginExpiry covers
// the class of bug switching off bgCtx was meant to kill: decisionCtx is
// still a 5s timeout, so a slow (or injected) revoke/clear can return
// DeadlineExceeded. Wrapping that with %w makes friendlyErr/shortReason
// treat it as login CodeTTL expiry and hide the cleanup failure.
func TestEnableAccess_IdentityMismatch_CleanupDeadlineIsNotLoginExpiry(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLoginWrongAccount())
	esTok := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen: %s", rec.Body.String())
	}

	srv.clearStrayFn = func(context.Context, int64) error {
		return context.DeadlineExceeded
	}

	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 500100101, "dana_tg", "Dana"); err != nil {
		t.Fatalf("ProvisionLocalAccount: %v", err)
	}

	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {esTok}, "code": {"12345"}})
	body := rec.Body.String()
	if strings.Contains(body, "login attempt expired") {
		t.Errorf("repair-budget DeadlineExceeded rendered as login CodeTTL expiry; body=%s", body)
	}
	if !strings.Contains(body, "clear wrong-account session") {
		t.Fatalf("cleanup failure was not surfaced; body=%s", body)
	}

	entries, err := srv.store.ListAuditFor(ctx, uid, 10, time.Time{})
	if err != nil {
		t.Fatalf("ListAuditFor: %v", err)
	}
	foundCleanup := false
	for _, e := range entries {
		if e.ToolName == "connect:failed:timeout" {
			t.Errorf("repair deadline booked as the generic login timeout tag; entries=%+v", entries)
		}
		if e.ToolName == "connect:failed:identity_cleanup_timeout" {
			foundCleanup = true
		}
	}
	if !foundCleanup {
		t.Errorf("audit log missing connect:failed:identity_cleanup_timeout; got %+v", entries)
	}
}
