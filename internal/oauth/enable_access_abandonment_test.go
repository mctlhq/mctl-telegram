package oauth

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// captureEnableLog swaps slog's default handler for a text handler writing
// to a buffer, restoring the previous default at test cleanup — same
// pattern as internal/oauth/registration_audit_test.go's captureLog.
func captureEnableLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// stubLoginParksAtCode fakes telegram.Login blocking forever in askCode,
// returning whatever error askCode's ctx eventually surfaces (a CodeTTL
// deadline, or a cancellation forced by the test). It never sends on
// codeCh, standing in for a user who walked away from the SMS-code prompt.
func stubLoginParksAtCode() LoginFunc {
	return func(ctx context.Context, apiID int, apiHash string, store *db.Store,
		uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		_ ...telegram.LoginConfig,
	) (int64, string, string, error) {
		if _, err := askCode(ctx); err != nil {
			return 0, "", "", err
		}
		return 0, "", "", errors.New("unexpected: askCode returned without a context error")
	}
}

// waitForFlowDone blocks until lf.done closes or the timeout elapses.
func waitForFlowDone(t *testing.T, lf *loginFlow, timeout time.Duration) {
	t.Helper()
	select {
	case <-lf.done:
	case <-time.After(timeout):
		t.Fatal("login flow did not complete in time")
	}
}

// TestStartLoginFlow_FloodWaitStillLogsError is T10's first case: a login
// failure that is neither a CodeTTL deadline nor a supersession must keep
// logging "enable: telegram login failed" at ERROR, even though the error
// text itself is Telegram's own FLOOD_WAIT shape.
func TestStartLoginFlow_FloodWaitStillLogsError(t *testing.T) {
	buf := captureEnableLog(t)
	srv, _ := newEnableTestServer(t, nil)
	floodErr := errors.New("FLOOD_WAIT_300")
	srv.loginFn = stubLogin(false, floodErr)

	lf := srv.startLoginFlow(1, 500100101, "+14155551234", false)
	// Feed the code so loginFn proceeds past askCode to the failure return.
	select {
	case <-lf.needCode:
	case <-time.After(2 * time.Second):
		t.Fatal("askCode never parked")
	}
	select {
	case lf.codeCh <- "12345":
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine never consumed the code")
	}
	waitForFlowDone(t, lf, 2*time.Second)

	line := buf.String()
	if !strings.Contains(line, "enable: telegram login failed") {
		t.Errorf("expected the ERROR line for a FLOOD_WAIT failure; log:\n%s", line)
	}
	if strings.Contains(line, "enable: onboarding abandoned") || strings.Contains(line, "enable: login flow superseded") {
		t.Errorf("a FLOOD_WAIT failure must not be reclassified; log:\n%s", line)
	}
}

// TestStartLoginFlow_CodeTTLDeadlineLogsAbandonment is T10's second case: a
// flow that times out on its own CodeTTL deadline while parked in askCode
// (nobody ever submits a code or cancels it) must log "enable: onboarding
// abandoned" at WARN, carrying the step it reached.
func TestStartLoginFlow_CodeTTLDeadlineLogsAbandonment(t *testing.T) {
	buf := captureEnableLog(t)
	srv, _ := newEnableTestServer(t, nil, func(c *Config) { c.CodeTTL = 60 * time.Millisecond })
	srv.loginFn = stubLoginParksAtCode()

	lf := srv.startLoginFlow(1, 500100101, "+14155551234", false)
	select {
	case <-lf.needCode:
	case <-time.After(2 * time.Second):
		t.Fatal("askCode never parked")
	}
	// Nobody sends on codeCh and nobody cancels — the flow must time out on
	// its own CodeTTL deadline.
	waitForFlowDone(t, lf, 2*time.Second)

	line := buf.String()
	if !strings.Contains(line, "enable: onboarding abandoned") {
		t.Errorf("expected the WARN abandonment line; log:\n%s", line)
	}
	if !strings.Contains(line, "step=code_requested") {
		t.Errorf("expected step=code_requested on the abandonment line; log:\n%s", line)
	}
	if strings.Contains(line, "enable: telegram login failed") {
		t.Errorf("an abandoned flow must not also log the ERROR line; log:\n%s", line)
	}
}

// TestStartLoginFlow_SupersededLogsInfoNotError is T10's third case and T11's
// race-pattern coverage: a live flow parked in askCode, cancelled by a
// simulated /start re-submission (superseded.Store(true) then cancel(), the
// exact sequence both call sites in enable_access.go use), must log "enable:
// login flow superseded" at INFO — never the ERROR or abandonment lines —
// and the step/superseded fields must survive concurrent access cleanly
// under `go test -race`.
func TestStartLoginFlow_SupersededLogsInfoNotError(t *testing.T) {
	buf := captureEnableLog(t)
	srv, _ := newEnableTestServer(t, nil, func(c *Config) { c.CodeTTL = 10 * time.Second })
	srv.loginFn = stubLoginParksAtCode()

	lf := srv.startLoginFlow(1, 500100101, "+14155551234", false)
	select {
	case <-lf.needCode:
	case <-time.After(2 * time.Second):
		t.Fatal("askCode never parked")
	}

	// Mirror the exact sequence handleEnableStart/abandonFlow use: mark
	// superseded before cancelling, from a different goroutine than the one
	// running the flow (an HTTP handler goroutine in production).
	lf.superseded.Store(true)
	lf.cancel()
	waitForFlowDone(t, lf, 2*time.Second)

	line := buf.String()
	if !strings.Contains(line, "enable: login flow superseded") {
		t.Errorf("expected the INFO supersession line; log:\n%s", line)
	}
	if !strings.Contains(line, "step=code_requested") {
		t.Errorf("expected step=code_requested on the supersession line; log:\n%s", line)
	}
	if strings.Contains(line, "enable: telegram login failed") || strings.Contains(line, "enable: onboarding abandoned") {
		t.Errorf("a superseded flow must not log ERROR or the abandonment WARN; log:\n%s", line)
	}
}
