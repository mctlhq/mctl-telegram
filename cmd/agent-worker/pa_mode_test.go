package main

import (
	"strings"
	"testing"
	"time"
)

func paEnv(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"AGENT_API_BASE_URL": "http://127.0.0.1:1/api/agent/v1", "AGENT_API_TOKEN": "pool-token",
		"AGENT_CREDENTIAL_DOMAIN_ID": "test-domain", "AGENT_RUNNER": "openai", "AGENT_WORKER_PA": "true",
		"AGENT_PA_BASE_URL": "http://127.0.0.1:1",
		"AGENT_MODEL":       "m", "AGENT_OPENAI_BASE_URL": "http://127.0.0.1:1", "AGENT_OPENAI_API_KEY": "k",
		"MODEL_INPUT_USD_PER_MTOK": "1", "MODEL_OUTPUT_USD_PER_MTOK": "2",
		"AGENT_OPENAI_MAX_OUTPUT_TOKENS": "1024", "AGENT_HEALTH_ADDR": "127.0.0.1:0",
	} {
		t.Setenv(k, v)
	}
}

// TestRun_PAModeFailsClosedPerSetting: each PA-mode setting is broken one
// at a time and run() refuses to start, naming it.
func TestRun_PAModeFailsClosedPerSetting(t *testing.T) {
	for _, tc := range []struct{ key, val, want string }{
		{"AGENT_WORKER_PA", "yes", "AGENT_WORKER_PA"},
		{"AGENT_RUNNER", "claude", "AGENT_RUNNER=openai"},
		{"AGENT_RUNNER", "", "AGENT_RUNNER=openai"},
		{"AGENT_PA_BASE_URL", "", "AGENT_PA_BASE_URL"},
		{"AGENT_PA_BASE_URL", "ftp://example.org", "AGENT_PA_BASE_URL"},
		{"AGENT_PA_BASE_URL", "https://example.org/api/agent/v1", "AGENT_PA_BASE_URL"},
		{"AGENT_PA_BASE_URL", "https://user:pw@example.org", "AGENT_PA_BASE_URL"},
		{"AGENT_PA_BASE_URL", "https://example.org?x=1", "AGENT_PA_BASE_URL"},
		{"AGENT_MODEL", "", "AGENT_MODEL"},
		{"AGENT_OPENAI_API_KEY", "", "AGENT_OPENAI_API_KEY"},
		{"MODEL_INPUT_USD_PER_MTOK", "0", "MODEL_INPUT_USD_PER_MTOK"},
		{"MODEL_OUTPUT_USD_PER_MTOK", "0", "MODEL_OUTPUT_USD_PER_MTOK"},
		{"AGENT_OPENAI_MAX_OUTPUT_TOKENS", "", "AGENT_OPENAI_MAX_OUTPUT_TOKENS"},
		{"AGENT_WORKER_CONCURRENCY", "0", "AGENT_WORKER_CONCURRENCY"},
	} {
		t.Run(tc.key+"="+tc.val, func(t *testing.T) {
			paEnv(t)
			t.Setenv(tc.key, tc.val)
			// A setting that is not refused starts the worker, which never
			// returns: that is a failure, reported instead of a hang.
			done := make(chan error, 1)
			go func() { done <- run() }()
			var err error
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("run() started instead of refusing %s", tc.key)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want an error naming %s", err, tc.want)
			}
		})
	}
}

func TestPAWorkerFromEnv(t *testing.T) {
	paEnv(t)
	t.Setenv("AGENT_PA_BASE_URL", "https://example.org/")
	w, err := paWorkerFromEnv("openai", "pool-token")
	if err != nil {
		t.Fatal(err)
	}
	if w.BaseURL != "https://example.org/" || w.PoolToken != "pool-token" || w.Health == nil ||
		w.Prices.InputUSDPerMTok != 1 || w.Prices.OutputUSDPerMTok != 2 || w.Concurrency != 1 {
		t.Fatalf("worker = %+v", w)
	}
}
