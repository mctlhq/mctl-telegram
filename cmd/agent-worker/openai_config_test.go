package main

import (
	"strings"
	"testing"
	"time"
)

func TestRun_OpenAIFailsFastWhenModelMissing(t *testing.T) {
	t.Setenv("AGENT_API_BASE_URL", "http://127.0.0.1:1")
	t.Setenv("AGENT_API_TOKEN", "poll-token")
	t.Setenv("AGENT_CREDENTIAL_DOMAIN_ID", "test-domain")
	t.Setenv("AGENT_RUNNER", "openai")
	t.Setenv("AGENT_MODEL", "")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "AGENT_MODEL is required") {
		t.Fatalf("err=%v want missing AGENT_MODEL", err)
	}
}

func TestRun_RejectsUnknownRunner(t *testing.T) {
	t.Setenv("AGENT_API_BASE_URL", "http://127.0.0.1:1")
	t.Setenv("AGENT_API_TOKEN", "poll-token")
	t.Setenv("AGENT_CREDENTIAL_DOMAIN_ID", "test-domain")
	t.Setenv("AGENT_RUNNER", "other")
	err := run()
	if err == nil || !strings.Contains(err.Error(), "AGENT_RUNNER must be claude or openai") {
		t.Fatalf("err=%v", err)
	}
}

func TestEnvDuration(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		want    time.Duration
		wantErr bool
	}{{"", 3 * time.Second, false}, {"1.5s", 1500 * time.Millisecond, false}, {"-1s", 0, true}, {"wat", 0, true}} {
		t.Run(tc.raw, func(t *testing.T) {
			t.Setenv("TEST_DURATION", tc.raw)
			got, err := envDuration("TEST_DURATION", 3*time.Second)
			if (err != nil) != tc.wantErr || (!tc.wantErr && got != tc.want) {
				t.Fatalf("got=%v err=%v want=%v err=%v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestRequiredEnvFloatRejectsNegativeAndNonFinite(t *testing.T) {
	for _, raw := range []string{"", "-1", "NaN", "Inf", "x"} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("TEST_PRICE", raw)
			if _, err := requiredEnvFloat("TEST_PRICE"); err == nil {
				t.Fatalf("%q accepted", raw)
			}
		})
	}
}

// Each OpenAI setting must fail closed on its own: the valid baseline below
// is broken one variable at a time and run() must refuse to start, naming it.
func TestRun_OpenAIFailsClosedPerSetting(t *testing.T) {
	base := map[string]string{
		"AGENT_API_BASE_URL": "http://127.0.0.1:1", "AGENT_API_TOKEN": "poll-token",
		"AGENT_CREDENTIAL_DOMAIN_ID": "test-domain", "AGENT_RUNNER": "openai",
		"AGENT_MODEL": "m", "AGENT_OPENAI_BASE_URL": "http://127.0.0.1:1", "AGENT_OPENAI_API_KEY": "k",
		"MODEL_INPUT_USD_PER_MTOK": "1", "MODEL_OUTPUT_USD_PER_MTOK": "2",
		"AGENT_MAX_TURNS": "12", "AGENT_OPENAI_MIN_INTERVAL": "0s",
	}
	cases := []struct{ key, val string }{
		{"AGENT_OPENAI_BASE_URL", ""},
		{"AGENT_OPENAI_API_KEY", ""},
		{"MODEL_INPUT_USD_PER_MTOK", ""},
		{"MODEL_OUTPUT_USD_PER_MTOK", ""},
		{"MODEL_INPUT_USD_PER_MTOK", "-1"},
		{"MODEL_OUTPUT_USD_PER_MTOK", "NaN"},
		{"AGENT_MAX_TURNS", "0"},
		{"AGENT_OPENAI_MIN_INTERVAL", "-1s"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.val, func(t *testing.T) {
			for k, v := range base {
				t.Setenv(k, v)
			}
			t.Setenv(tc.key, tc.val)
			err := run()
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("err=%v want an error naming %s", err, tc.key)
			}
		})
	}
}
