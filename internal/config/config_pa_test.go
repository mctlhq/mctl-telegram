package config

import (
	"strings"
	"testing"
)

// Synthetic Bot API tokens. Neither id is a real bot; both are checked with
// git grep to mean nothing else in this repository.
const (
	testPABotToken    = "7000000001:pa-test-token-not-real-0123456789"
	testLoginBotToken = "7000000002:login-test-token-not-real"
	testPASecret      = "pa_webhook_secret_for_tests_only_0123456789"
)

// TestLoadPA_FailClosed covers the PA master switch (threat model T11,
// S1-F2 in spirit for this one flag): anything but an explicit true is off,
// and off means the PA settings are not even read.
func TestLoadPA_FailClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value *string
	}{
		{"unset", nil},
		{"empty", ptr("")},
		{"unparseable", ptr("ture")},
		{"explicit false", ptr("false")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value != nil {
				t.Setenv("PA_ENABLED", *tc.value)
			}
			// Present but must be ignored while the PA is off.
			t.Setenv("PA_BOT_TOKEN", testPABotToken)
			t.Setenv("PA_WEBHOOK_SECRET", testPASecret)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if cfg.PAEnabled {
				t.Error("PAEnabled = true, want false")
			}
			if cfg.PABotToken != "" || cfg.PAWebhookSecret != "" {
				t.Error("PA secrets were read while PA_ENABLED is off")
			}
		})
	}
}

func TestLoadPA_Enabled(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Setenv("PA_ENABLED", "true")
		t.Setenv("PA_BOT_TOKEN", testPABotToken)
		t.Setenv("PA_WEBHOOK_SECRET", testPASecret)
		t.Setenv("TELEGRAM_LOGIN_BOT_TOKEN", testLoginBotToken)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if !cfg.PAEnabled || cfg.PABotToken != testPABotToken || cfg.PAWebhookSecret != testPASecret {
			t.Errorf("PA config not loaded: enabled=%v", cfg.PAEnabled)
		}
	})

	refusals := []struct {
		name, token, secret, login, want string
	}{
		{"no token", "", testPASecret, "", "PA_BOT_TOKEN"},
		{"malformed token", "not-a-token", testPASecret, "", "PA_BOT_TOKEN"},
		{"token without secret half", "7000000001:", testPASecret, "", "PA_BOT_TOKEN"},
		{"token secret half too short", "7000000001:short-half", testPASecret, "", "PA_BOT_TOKEN"},
		{"token secret half outside alphabet", "7000000001:pa-test-token-not-real-012345678!", testPASecret, "", "PA_BOT_TOKEN"},
		{"same bot as login bot", testPABotToken, testPASecret, "7000000001:other-half", "different bot"},
		{"no secret", testPABotToken, "", "", "PA_WEBHOOK_SECRET"},
		{"short secret", testPABotToken, strings.Repeat("s", MinPAWebhookSecretLen-1), "", "PA_WEBHOOK_SECRET"},
		{"secret outside alphabet", testPABotToken, strings.Repeat("s", MinPAWebhookSecretLen) + "!", "", "PA_WEBHOOK_SECRET"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PA_ENABLED", "true")
			t.Setenv("PA_BOT_TOKEN", tc.token)
			t.Setenv("PA_WEBHOOK_SECRET", tc.secret)
			t.Setenv("TELEGRAM_LOGIN_BOT_TOKEN", tc.login)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %v, want refusal mentioning %q", err, tc.want)
			}
			for _, secret := range []string{tc.token, tc.secret, tc.login} {
				if len(secret) > 12 && strings.Contains(err.Error(), secret) {
					t.Fatalf("Load() error echoes a credential: %v", err)
				}
			}
		})
	}
}

func ptr(s string) *string { return &s }
