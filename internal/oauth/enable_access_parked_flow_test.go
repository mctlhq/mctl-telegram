package oauth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// These tests pin mctl-telegram#859: an enable_access flow abandoned at the
// code screen used to hold the per-uid login mutex for the whole CodeTTL,
// and every later attempt for the same account -- made from a fresh wizard
// token, which handleEnableStart's same-session supersede never sees --
// queued behind it, timed out at the phone step, and sent a stray login
// code once the mutex finally freed.

// TestStartLoginFlow_NewAttemptSupersedesParkedFlowForSameUID: flow A parks
// in askCode; flow B for the same uid (a different enable session in
// production) must displace it within the handler's lock wait, not after
// A's CodeTTL. With the registry removed, A stays parked for the full 10s
// CodeTTL and B never reaches askCode in time.
func TestStartLoginFlow_NewAttemptSupersedesParkedFlowForSameUID(t *testing.T) {
	buf := captureEnableLog(t)
	srv, _ := newEnableTestServer(t, nil, func(c *Config) { c.CodeTTL = 10 * time.Second })
	srv.loginFn = stubLoginParksAtCode()

	a := srv.startLoginFlow(1, 500100101, "+14155551234", false, time.Now())
	select {
	case <-a.needCode:
	case <-time.After(2 * time.Second):
		t.Fatal("flow A never parked in askCode")
	}

	b := srv.startLoginFlow(1, 500100101, "+14155551234", false, time.Now())

	select {
	case <-a.done:
	case <-time.After(2 * time.Second):
		t.Fatal("flow A was not cancelled by flow B; it would hold the uid mutex until its CodeTTL expires")
	}
	if !a.superseded.Load() {
		t.Error("flow A must be marked superseded, so its exit logs as a restart rather than a failure")
	}
	if !errors.Is(a.err, context.Canceled) {
		t.Errorf("flow A err = %v, want context.Canceled", a.err)
	}
	select {
	case <-b.needCode:
	case <-time.After(2 * time.Second):
		t.Fatal("flow B never reached askCode: it is still queued behind the cancelled flow A")
	}
	if !strings.Contains(buf.String(), "enable: login flow superseded") {
		t.Errorf("expected the INFO supersession line for flow A; log:\n%s", buf.String())
	}

	// B is now the registered flow; A's exit must not have unregistered it.
	if v, ok := srv.loginFlows.Load(int64(1)); !ok || v.(*loginFlow) != b {
		t.Error("flow B is not the registered flow for the uid after A exited")
	}
	b.superseded.Store(true)
	b.cancel()
	waitForFlowDone(t, b, 2*time.Second)
	if _, ok := srv.loginFlows.Load(int64(1)); ok {
		t.Error("the last flow for the uid left its registry entry behind")
	}
}

// TestStartLoginFlow_CancelledWhileQueuedNeverCallsLogin: a flow cancelled
// while still waiting for the uid mutex must leave as soon as it gets the
// mutex, without touching the database or Telegram. Without the bgCtx check
// under the lock it reaches the account-mode query with a dead context and
// misreports a supersession as a mode-check failure.
func TestStartLoginFlow_CancelledWhileQueuedNeverCallsLogin(t *testing.T) {
	srv, _ := newEnableTestServer(t, nil, func(c *Config) { c.CodeTTL = 10 * time.Second })
	var loginCalled atomic.Bool
	srv.loginFn = func(ctx context.Context, apiID int, apiHash string, store *db.Store,
		uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		_ ...telegram.LoginConfig,
	) (int64, string, string, error) {
		loginCalled.Store(true)
		return 0, "", "", errors.New("unexpected: login called on a cancelled flow")
	}
	var modeChecked atomic.Bool
	srv.modeCheckFn = func(ctx context.Context, uid int64) (bool, error) {
		modeChecked.Store(true)
		return false, ctx.Err()
	}

	parked := make(chan struct{})
	srv.loginFlowParked = sync.OnceFunc(func() { close(parked) })
	ul := srv.uidLoginMutex(1)
	ul.Lock()

	lf := srv.startLoginFlow(1, 500100101, "+14155551234", false, time.Now())
	select {
	case <-parked:
	case <-time.After(2 * time.Second):
		ul.Unlock()
		t.Fatal("flow never queued on the uid mutex")
	}
	lf.superseded.Store(true)
	lf.cancel()
	ul.Unlock()

	waitForFlowDone(t, lf, 2*time.Second)
	if loginCalled.Load() {
		t.Error("loginFn ran for a flow cancelled while queued; in production that is the stray login code")
	}
	if modeChecked.Load() {
		t.Error("the account-mode query ran on a cancelled flow")
	}
	if !errors.Is(lf.err, context.Canceled) || errors.Is(lf.err, errModeCheckFailed) {
		t.Errorf("err = %v, want plain context.Canceled, not a mode-check failure", lf.err)
	}
}

// TestEnableAccess_SendCodeTimeout_CancelsFlow drives handleEnableStart's
// enableSendCodeWait arm: the user is shown the phone form again, so the
// flow that request launched must be cancelled rather than left queued on
// the uid mutex to send a code later. The mutex is held by the test for the
// whole request, standing in for the parked predecessor.
func TestEnableAccess_SendCodeTimeout_CancelsFlow(t *testing.T) {
	prev := enableSendCodeWait
	enableSendCodeWait = 150 * time.Millisecond
	t.Cleanup(func() { enableSendCodeWait = prev })

	var loginCalled atomic.Bool
	srv, mux := newEnableTestServer(t, func(ctx context.Context, apiID int, apiHash string, store *db.Store,
		uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		_ ...telegram.LoginConfig,
	) (int64, string, string, error) {
		loginCalled.Store(true)
		return 0, "", "", errors.New("unexpected: login called after the handler timed out")
	}, func(c *Config) { c.CodeTTL = 10 * time.Second })
	esTok := driveToPhone(t, mux)

	uid, err := srv.store.EnsureUserByTelegramID(context.Background(), 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	parked := make(chan struct{})
	srv.loginFlowParked = sync.OnceFunc(func() { close(parked) })
	ul := srv.uidLoginMutex(uid)
	ul.Lock()

	rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}})
	select {
	case <-parked:
	case <-time.After(2 * time.Second):
		ul.Unlock()
		t.Fatal("the flow never queued on the uid mutex")
	}
	if !strings.Contains(rec.Body.String(), "Timed out contacting Telegram") {
		ul.Unlock()
		t.Fatalf("expected the timeout phone form; body=%s", rec.Body.String())
	}

	v, ok := srv.loginFlows.Load(uid)
	if !ok {
		ul.Unlock()
		t.Fatal("the timed-out flow is not registered for the uid")
	}
	lf := v.(*loginFlow)
	// Release the stand-in predecessor. A cancelled flow exits under the
	// mutex without calling loginFn; one the handler forgot to cancel would
	// now proceed to send a code.
	ul.Unlock()
	waitForFlowDone(t, lf, 2*time.Second)
	if loginCalled.Load() {
		t.Error("handler timed out but left its flow running; it sent a login code once the mutex freed")
	}
	srv.mu.Lock()
	es := srv.enables[esTok]
	srv.mu.Unlock()
	es.lock.Lock()
	defer es.lock.Unlock()
	if es.flow != nil {
		t.Error("the session still references the abandoned flow; a code re-POST would feed it")
	}
	if es.step != stepPhone {
		t.Errorf("step = %v, want stepPhone after the timeout form", es.step)
	}
}

// TestStartLoginFlow_CodeTTLWhileQueuedLogsWarnNotError pins the review nit
// on #861: a flow whose CodeTTL expires while it is still queued on the uid
// mutex never ran anything, so it must not log "telegram login failed".
func TestStartLoginFlow_CodeTTLWhileQueuedLogsWarnNotError(t *testing.T) {
	buf := captureEnableLog(t)
	srv, _ := newEnableTestServer(t, nil, func(c *Config) { c.CodeTTL = 100 * time.Millisecond })
	srv.loginFn = stubLoginParksAtCode()

	parked := make(chan struct{})
	srv.loginFlowParked = sync.OnceFunc(func() { close(parked) })
	ul := srv.uidLoginMutex(1)
	ul.Lock()
	lf := srv.startLoginFlow(1, 500100101, "+14155551234", false, time.Now())
	select {
	case <-parked:
	case <-time.After(2 * time.Second):
		ul.Unlock()
		t.Fatal("flow never queued on the uid mutex")
	}
	time.Sleep(200 * time.Millisecond) // let CodeTTL expire while queued
	ul.Unlock()
	waitForFlowDone(t, lf, 2*time.Second)

	line := buf.String()
	if !strings.Contains(line, "enable: login flow expired before it started") {
		t.Errorf("expected the WARN never-started line; log:\n%s", line)
	}
	if strings.Contains(line, "enable: telegram login failed") {
		t.Errorf("a flow that never started must not log the ERROR line; log:\n%s", line)
	}
}
