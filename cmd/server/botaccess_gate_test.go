package main

import (
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/config"
)

// T12: the scope request needs both the rollout flag and the same-bot match;
// a reason is reported only when the flag is on and the match fails.
func TestBotAccessEnabled_TruthTable(t *testing.T) {
	for _, tc := range []struct {
		name       string
		flag       bool
		token      string
		wantOn     bool
		wantReason string
	}{
		{"flag off, ids match", false, "123456:AAsynthetic", false, ""},
		{"flag off, token unset", false, "", false, ""},
		{"flag on, ids match", true, "123456:AAsynthetic", true, ""},
		{"flag on, mismatch", true, "999:AAsynthetic", false, "bot_id_mismatch"},
		{"flag on, unset", true, "", false, "bot_token_unset"},
		{"flag on, malformed", true, "garbage", false, "bot_token_malformed"},
	} {
		cfg := &config.Config{TelegramOIDCBotAccessEnabled: tc.flag, TelegramLoginBotToken: tc.token, TelegramOIDCClientID: "123456"}
		on, reason := botAccessEnabled(cfg)
		if on != tc.wantOn || reason != tc.wantReason {
			t.Errorf("%s: got (%v, %q), want (%v, %q)", tc.name, on, reason, tc.wantOn, tc.wantReason)
		}
	}
}
