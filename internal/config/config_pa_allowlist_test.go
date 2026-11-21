package config

import (
	"slices"
	"strings"
	"testing"
)

// TestLoadPA_AllowedPrincipals: PA_ALLOWED_PRINCIPALS is read only with the
// PA on; unset or empty allows nobody (an empty list, never everyone); a
// malformed entry refuses startup with an error that names the variable
// and carries no part of the value (#1318).
func TestLoadPA_AllowedPrincipals(t *testing.T) {
	enable := func(t *testing.T) {
		t.Setenv("PA_ENABLED", "true")
		setPAServerSecrets(t)
		t.Setenv("PA_BOT_TOKEN", testPABotToken)
		t.Setenv("PA_WEBHOOK_SECRET", testPASecret)
		t.Setenv("PA_WEBHOOK_URL", testPAWebhookURL)
		t.Setenv("TELEGRAM_LOGIN_BOT_TOKEN", testLoginBotToken)
	}
	for name, tc := range map[string]struct {
		v    string
		want []int64
	}{
		"unset or empty": {"", nil},
		"blank":          {"  ", nil},
		"one":            {"4242001", []int64{4242001}},
		"several":        {" 4242001, 4242002 ,4242001", []int64{4242001, 4242002}},
	} {
		t.Run(name, func(t *testing.T) {
			enable(t)
			t.Setenv(PAAllowedPrincipalsEnv, tc.v)
			c, err := Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if !slices.Equal(c.PAAllowedPrincipals, tc.want) {
				t.Fatalf("allowed %v, want %v", c.PAAllowedPrincipals, tc.want)
			}
		})
	}
	for _, bad := range []string{"4242001,", ",4242001", "4242001,,4242002", "0", "-4242001", "42420x1", "4242001;4242002", "99999999999999999999"} {
		t.Run("malformed "+bad, func(t *testing.T) {
			enable(t)
			t.Setenv(PAAllowedPrincipalsEnv, bad)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), PAAllowedPrincipalsEnv) {
				t.Fatalf("Load() error = %v, want a refusal naming %s", err, PAAllowedPrincipalsEnv)
			}
			if strings.Contains(err.Error(), "4242") || strings.Contains(err.Error(), "9999") {
				t.Fatalf("error carries the value: %v", err)
			}
		})
	}
	t.Run("PA off reads nothing", func(t *testing.T) {
		t.Setenv("PA_ENABLED", "")
		t.Setenv(PAAllowedPrincipalsEnv, "not-a-list")
		c, err := Load()
		if err != nil {
			t.Fatalf("PA off: %v", err)
		}
		if c.PAAllowedPrincipals != nil {
			t.Fatalf("PA off: allowlist read: %v", c.PAAllowedPrincipals)
		}
	})
}
