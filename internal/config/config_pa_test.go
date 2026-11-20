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
	testPAWebhookURL  = "https://pa.example/pa/bot/webhook"
)

// Synthetic server secrets an enabled PA is built from (#1343).
const (
	testEncryptionKey = "0707070707070707070707070707070707070707070707070707070707070707"
	testSigningKey    = "pa-config-test-signing-key-not-real-0123456789"
)

// setPAServerSecrets sets the server secrets an enabled PA requires.
func setPAServerSecrets(t *testing.T) {
	t.Helper()
	t.Setenv("ENCRYPTION_KEY", testEncryptionKey)
	t.Setenv("AUTH_MODE", "local-jwt")
	t.Setenv("OAUTH_JWT_SIGNING_KEY", testSigningKey)
}

// TestLoadPA_ServerSecrets: an enabled PA refuses to load without
// ENCRYPTION_KEY (conversation-state sealer) or the OAuth signing key (pool
// and pa-job tokens), naming the variable and never its value. With the PA
// off neither is required.
func TestLoadPA_ServerSecrets(t *testing.T) {
	enable := func(t *testing.T) {
		t.Setenv("PA_ENABLED", "true")
		setPAServerSecrets(t)
		t.Setenv("PA_BOT_TOKEN", testPABotToken)
		t.Setenv("PA_WEBHOOK_SECRET", testPASecret)
		t.Setenv("PA_WEBHOOK_URL", testPAWebhookURL)
		t.Setenv("TELEGRAM_LOGIN_BOT_TOKEN", testLoginBotToken)
	}
	t.Run("control", func(t *testing.T) {
		enable(t)
		if _, err := Load(); err != nil {
			t.Fatalf("Load() error: %v", err)
		}
	})
	for _, tc := range []struct{ name, unset, want string }{
		{"no encryption key", "ENCRYPTION_KEY", "ENCRYPTION_KEY"},
		{"no signing key", "OAUTH_JWT_SIGNING_KEY", "OAUTH_JWT_SIGNING_KEY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enable(t)
			t.Setenv(tc.unset, "")
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %v, want refusal naming %s", err, tc.want)
			}
			for _, secret := range []string{testEncryptionKey, testSigningKey} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("Load() error echoes a credential: %v", err)
				}
			}
		})
	}
	// The signing key must be mctl-telegram's own: shared-hmac's shared
	// secret, or local-jwt's legacy fallback to it, is refused even when
	// set.
	t.Run("shared-hmac mode", func(t *testing.T) {
		enable(t)
		t.Setenv("AUTH_MODE", "shared-hmac")
		t.Setenv("OAUTH_JWT_SECRET", testSigningKey+"-shared")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "AUTH_MODE=local-jwt") {
			t.Fatalf("Load() error = %v, want refusal of the shared signing key", err)
		}
	})
	t.Run("legacy key only", func(t *testing.T) {
		enable(t)
		t.Setenv("OAUTH_JWT_SIGNING_KEY", "")
		t.Setenv("OAUTH_JWT_SECRET", testSigningKey+"-legacy")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "OAUTH_JWT_SIGNING_KEY") {
			t.Fatalf("Load() error = %v, want refusal of the legacy signing key", err)
		}
		if strings.Contains(err.Error(), testSigningKey) {
			t.Fatalf("Load() error echoes a credential: %v", err)
		}
	})
	t.Run("off ignores them", func(t *testing.T) {
		t.Setenv("PA_ENABLED", "false")
		t.Setenv("ENCRYPTION_KEY", "")
		t.Setenv("OAUTH_JWT_SIGNING_KEY", "")
		if _, err := Load(); err != nil {
			t.Fatalf("Load() error with PA off: %v", err)
		}
	})
}

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
			t.Setenv("PA_WEBHOOK_URL", testPAWebhookURL)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			if cfg.PAEnabled {
				t.Error("PAEnabled = true, want false")
			}
			if cfg.PABotToken != "" || cfg.PAWebhookSecret != "" || cfg.PAWebhookURL != "" {
				t.Error("PA secrets were read while PA_ENABLED is off")
			}
		})
	}
}

func TestLoadPA_Enabled(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		t.Setenv("PA_ENABLED", "true")
		setPAServerSecrets(t)
		t.Setenv("PA_BOT_TOKEN", testPABotToken)
		t.Setenv("PA_WEBHOOK_SECRET", testPASecret)
		t.Setenv("PA_WEBHOOK_URL", testPAWebhookURL)
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
			setPAServerSecrets(t)
			t.Setenv("PA_BOT_TOKEN", tc.token)
			t.Setenv("PA_WEBHOOK_SECRET", tc.secret)
			t.Setenv("PA_WEBHOOK_URL", testPAWebhookURL)
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

// TestLoadPA_WebhookURL: PA_WEBHOOK_URL is required when the PA is on and
// must be the https PA webhook path with nothing an attacker could smuggle
// into it; the getWebhookInfo monitor compares Telegram's URL against it.
func TestLoadPA_WebhookURL(t *testing.T) {
	enable := func(t *testing.T, u string) {
		t.Setenv("PA_ENABLED", "true")
		setPAServerSecrets(t)
		t.Setenv("PA_BOT_TOKEN", testPABotToken)
		t.Setenv("PA_WEBHOOK_SECRET", testPASecret)
		t.Setenv("TELEGRAM_LOGIN_BOT_TOKEN", testLoginBotToken)
		t.Setenv("PA_WEBHOOK_URL", u)
	}
	enable(t, testPAWebhookURL)
	cfg, err := Load()
	if err != nil || cfg.PAWebhookURL != testPAWebhookURL {
		t.Fatalf("url=%q err=%v", cfg.PAWebhookURL, err)
	}
	for _, bad := range []string{
		"",
		"http://pa.example/pa/bot/webhook",
		"https:///pa/bot/webhook",
		"https://user:pw@pa.example/pa/bot/webhook",
		"https://pa.example/pa/bot/webhook?x=1",
		"https://pa.example/pa/bot/webhook?",
		"https://pa.example/pa/bot/webhook#f",
		"https://pa.example/other",
		"pa.example/pa/bot/webhook",
	} {
		t.Run(bad, func(t *testing.T) {
			enable(t, bad)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "PA_WEBHOOK_URL") {
				t.Fatalf("Load() = %v, want a PA_WEBHOOK_URL refusal", err)
			}
		})
	}
}

func ptr(s string) *string { return &s }
