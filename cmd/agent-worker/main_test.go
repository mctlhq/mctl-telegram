package main

import (
	"bytes"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestConfigureLogging_UsesJSONAndRedactsSensitiveFields(t *testing.T) {
	var out bytes.Buffer
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })

	configureLogging(&out)
	slog.Info("test", "body", "private message", "mode", "worker")

	got := out.String()
	if !strings.HasPrefix(got, "{") || !strings.Contains(got, `"mode":"worker"`) {
		t.Fatalf("log is not structured JSON: %s", got)
	}
	if strings.Contains(got, "private message") || !strings.Contains(got, "[redacted") {
		t.Fatalf("sensitive body was not redacted: %s", got)
	}
}

// TestEnvFloat_FailsLoudlyOnInvalidValue guards against the P2 finding that
// an operator-set-but-unparseable AGENT_MAX_BUDGET_USD silently fell back to
// 0 (== no cap), giving no indication the intended spending cap was never
// applied.
func TestEnvFloat_FailsLoudlyOnInvalidValue(t *testing.T) {
	t.Setenv("TEST_ENV_FLOAT", "not-a-number")
	if _, err := envFloat("TEST_ENV_FLOAT", 0); err == nil {
		t.Fatal("expected an error for an unparseable value")
	}
}

func TestEnvFloat_FailsLoudlyOnNaNAndInf(t *testing.T) {
	for _, raw := range []string{"NaN", "Inf", "+Inf", "-Inf"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("TEST_ENV_FLOAT", raw)
			if _, err := envFloat("TEST_ENV_FLOAT", 0); err == nil {
				t.Fatalf("expected an error for %q", raw)
			}
		})
	}
}

// TestEnvFloat_RejectsNegativeValues guards against a Codex finding:
// ClaudeInvoker.Run only adds --max-budget-usd when MaxBudgetUSD > 0, so a
// negative configured value silently behaved exactly like "unset" —
// turning an intended spending cap into an uncapped invocation with no
// indication anything was wrong.
func TestEnvFloat_RejectsNegativeValues(t *testing.T) {
	t.Setenv("TEST_ENV_FLOAT", "-5")
	if _, err := envFloat("TEST_ENV_FLOAT", 0); err == nil {
		t.Fatal("expected an error for a negative value")
	}
}

func TestEnvFloat_ReturnsDefaultWhenUnset(t *testing.T) {
	_ = os.Unsetenv("TEST_ENV_FLOAT")
	got, err := envFloat("TEST_ENV_FLOAT", 5)
	if err != nil {
		t.Fatalf("envFloat: %v", err)
	}
	if got != 5 {
		t.Fatalf("got = %v, want default 5", got)
	}
}

// TestRun_FailsFastOnHealthServerBindError guards against a Claude/Codex
// finding: run() previously didn't read healthErrCh until after
// worker.Loop(ctx) exited — normally only on shutdown — so a health server
// that failed to bind (port already in use, malformed AGENT_HEALTH_ADDR)
// left the pod running with no probe socket, failing every liveness/
// readiness check for its entire lifetime with no early signal. run() must
// now return the bind error immediately, before ever starting the poll
// loop (so it never calls the unreachable AGENT_API_BASE_URL below).
func TestRun_FailsFastOnHealthServerBindError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	defer ln.Close()

	t.Setenv("AGENT_API_BASE_URL", "http://127.0.0.1:1") // unreachable; run() must never get here
	t.Setenv("AGENT_API_TOKEN", "test-token")
	t.Setenv("AGENT_HEALTH_ADDR", ln.Addr().String())

	done := make(chan error, 1)
	go func() { done <- run() }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("run() = nil, want a bind error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run() did not fail fast on a health server bind conflict")
	}
}

func TestEnvFloat_ParsesValidValue(t *testing.T) {
	t.Setenv("TEST_ENV_FLOAT", "12.5")
	got, err := envFloat("TEST_ENV_FLOAT", 0)
	if err != nil {
		t.Fatalf("envFloat: %v", err)
	}
	if got != 12.5 {
		t.Fatalf("got = %v, want 12.5", got)
	}
}
