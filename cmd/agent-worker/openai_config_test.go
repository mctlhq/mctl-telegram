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
