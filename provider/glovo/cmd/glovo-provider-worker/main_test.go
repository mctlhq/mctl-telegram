package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridgeclient/bridgefake"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/executor"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/leakcheck"
)

func credFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(p, []byte(leakcheck.Canaries[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func baseEnv(t *testing.T, url string, extra ...string) []string {
	t.Helper()
	return append([]string{"FAKE_ONLY=true", "HEALTH_ADDR=127.0.0.1:0", "MCTL_API_BASE_URL=" + url,
		"MCTL_BRIDGE_CREDENTIAL_FILE=" + credFile(t)}, extra...)
}

// T12 and T20: runtime gates, T18: config.
func TestRunRefusesBadStartup(t *testing.T) {
	base := baseEnv(t, "http://127.0.0.1:9")
	without := func(drop string) []string {
		var out []string
		for _, kv := range base {
			if !strings.HasPrefix(kv, drop+"=") {
				out = append(out, kv)
			}
		}
		return out
	}
	missing := filepath.Join(t.TempDir(), "no-such-file")
	cases := map[string][]string{
		"no FAKE_ONLY":              without("FAKE_ONLY"),
		"FAKE_ONLY=false":           append(without("FAKE_ONLY"), "FAKE_ONLY=false"),
		"GLOVO_SESSION_TOKEN":       append(append([]string{}, base...), "GLOVO_SESSION_TOKEN=x"),
		"GLOVO_BASE_URL":            append(append([]string{}, base...), "GLOVO_BASE_URL=http://127.0.0.1"),
		"TEMPORAL_HOSTPORT":         append(append([]string{}, base...), "TEMPORAL_HOSTPORT=localhost:7233"),
		"TEMPORAL_NAMESPACE":        append(append([]string{}, base...), "TEMPORAL_NAMESPACE=x"),
		"no base url":               without("MCTL_API_BASE_URL"),
		"base url with path":        append(without("MCTL_API_BASE_URL"), "MCTL_API_BASE_URL=https://api.mctl.ai/v1"),
		"non-loopback http":         append(without("MCTL_API_BASE_URL"), "MCTL_API_BASE_URL=http://api.mctl.ai"),
		"no credential file":        without("MCTL_BRIDGE_CREDENTIAL_FILE"),
		"missing credential file":   append(without("MCTL_BRIDGE_CREDENTIAL_FILE"), "MCTL_BRIDGE_CREDENTIAL_FILE="+missing),
		"claim max 0":               append(append([]string{}, base...), "BRIDGE_CLAIM_MAX=0"),
		"claim max 11":              append(append([]string{}, base...), "BRIDGE_CLAIM_MAX=11"),
		"poll interval too short":   append(append([]string{}, base...), "BRIDGE_POLL_INTERVAL=100ms"),
		"bad identity":              append(append([]string{}, base...), "BRIDGE_WORKER_IDENTITY=Provider:Glovo"),
		"identity without provider": append(append([]string{}, base...), "BRIDGE_WORKER_IDENTITY=glovo"),
		"stop timeout too long":     append(append([]string{}, base...), "WORKER_STOP_TIMEOUT=1h"),
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			err := run(context.Background(), env)
			if err == nil {
				t.Fatal("startup must be refused")
			}
			if strings.Contains(err.Error(), leakcheck.Canaries[0]) || strings.Contains(err.Error(), missing) {
				t.Fatalf("error leaks a value: %v", err)
			}
		})
	}
	err := run(context.Background(), cases["TEMPORAL_HOSTPORT"])
	if err == nil || !strings.Contains(err.Error(), "TEMPORAL_HOSTPORT") || strings.Contains(err.Error(), "7233") {
		t.Fatalf("temporal refusal must list the name only: %v", err)
	}
	err = run(context.Background(), cases["missing credential file"])
	if err == nil || !strings.Contains(err.Error(), "MCTL_BRIDGE_CREDENTIAL_FILE") {
		t.Fatalf("credential refusal must name the setting: %v", err)
	}
}

func TestConfigDefaults(t *testing.T) {
	c, err := LoadConfig(baseEnv(t, "https://api.mctl.ai"))
	if err != nil {
		t.Fatal(err)
	}
	if c.WorkerIdentity != "provider:glovo" || c.ClaimMax != 4 || c.StopTimeout != defaultStopTimeout || c.BaseURL.Host != "api.mctl.ai" {
		t.Fatalf("config = %+v", c)
	}
}

// The worker starts against the fake bridge, claims, serves its probes and
// stops cleanly on cancellation.
func TestRunAgainstFakeBridgeAndShutdown(t *testing.T) {
	f := bridgefake.New()
	defer f.Close()
	f.AddProvider(leakcheck.Canaries[0], "provider:glovo", "tnr_0123456789abcdef0123")
	id := f.Enqueue(bridgefake.Command("place_order_fake"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, baseEnv(t, f.URL())) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, _, _ := f.State(id); st == bridgefake.StatusCompleted {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if st, eff, _ := f.State(id); st != bridgefake.StatusCompleted || eff != bridgefake.EffectSucceeded {
		t.Fatalf("command not completed: %s %s", st, eff)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no clean exit")
	}
}

// The runbook carries the executor's outcome table verbatim.
func TestRunbookMatchesExecutorTable(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "runbooks", "glovo-provider-worker.md"))
	if err != nil {
		t.Skip("runbook not present in this checkout")
	}
	if !strings.Contains(string(b), executor.MarkdownTable()) {
		t.Fatal("docs/runbooks/glovo-provider-worker.md is out of date; regenerate the table with executor.MarkdownTable()")
	}
}
