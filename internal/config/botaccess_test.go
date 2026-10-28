package config

import "testing"

func TestBotIDFromToken(t *testing.T) {
	for tok, want := range map[string]string{"123456:AAsynthetic": "123456"} {
		if got, ok := BotIDFromToken(tok); !ok || got != want {
			t.Errorf("%q: got %q %v", tok, got, ok)
		}
	}
	for _, tok := range []string{"", "123456", "12x:AA", ":AA"} {
		if _, ok := BotIDFromToken(tok); ok {
			t.Errorf("%q accepted", tok)
		}
	}
}

func TestLoginBotMatchesOIDCClient(t *testing.T) {
	cases := []struct {
		token, client, reason string
		ok                    bool
	}{
		{"123456:AAsynthetic", "123456", "", true},
		{"", "123456", "bot_token_unset", false},
		{"garbage", "123456", "bot_token_malformed", false},
		{"999:AAsynthetic", "123456", "bot_id_mismatch", false},
	}
	for _, tc := range cases {
		c := &Config{TelegramLoginBotToken: tc.token, TelegramOIDCClientID: tc.client}
		ok, reason := c.LoginBotMatchesOIDCClient()
		if ok != tc.ok || reason != tc.reason {
			t.Errorf("%q: got %v %q", tc.token, ok, reason)
		}
	}
}

// T12: the rollout flag reads as off when unset, empty or unparseable.
func TestBotAccessFlagDefaultsOff(t *testing.T) {
	for _, v := range []string{"", "maybe", "0", "false"} {
		t.Setenv("TELEGRAM_OIDC_BOT_ACCESS_ENABLED", v)
		if envBool("TELEGRAM_OIDC_BOT_ACCESS_ENABLED", false) {
			t.Errorf("%q read as on", v)
		}
	}
	t.Setenv("TELEGRAM_OIDC_BOT_ACCESS_ENABLED", "true")
	if !envBool("TELEGRAM_OIDC_BOT_ACCESS_ENABLED", false) {
		t.Error(`"true" read as off`)
	}
}
