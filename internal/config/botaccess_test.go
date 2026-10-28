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
