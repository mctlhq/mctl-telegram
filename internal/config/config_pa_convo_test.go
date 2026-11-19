package config

import (
	"testing"
	"time"
)

// TestLoadPA_ConversationTTL: default 24h, bounded to [1m, 24h], and an
// unparseable or out-of-range value refuses to start rather than silently
// falling back to some other lifetime than the consent text promises.
func TestLoadPA_ConversationTTL(t *testing.T) {
	enable := func(t *testing.T) {
		t.Setenv("PA_ENABLED", "true")
		t.Setenv("PA_BOT_TOKEN", testPABotToken)
		t.Setenv("PA_WEBHOOK_SECRET", testPASecret)
		t.Setenv("PA_WEBHOOK_URL", testPAWebhookURL)
		t.Setenv("TELEGRAM_LOGIN_BOT_TOKEN", testLoginBotToken)
	}
	t.Run("default", func(t *testing.T) {
		enable(t)
		cfg, err := Load()
		if err != nil || cfg.PAConversationTTL != 24*time.Hour {
			t.Fatalf("ttl=%v err=%v, want 24h", cfg.PAConversationTTL, err)
		}
	})
	t.Run("set", func(t *testing.T) {
		enable(t)
		t.Setenv("PA_CONVERSATION_TTL", "6h")
		cfg, err := Load()
		if err != nil || cfg.PAConversationTTL != 6*time.Hour {
			t.Fatalf("ttl=%v err=%v, want 6h", cfg.PAConversationTTL, err)
		}
	})
	for _, bad := range []string{"25h", "0s", "30s", "-1h", "a day"} {
		t.Run("refused "+bad, func(t *testing.T) {
			enable(t)
			t.Setenv("PA_CONVERSATION_TTL", bad)
			if _, err := Load(); err == nil {
				t.Fatalf("PA_CONVERSATION_TTL=%q accepted", bad)
			}
		})
	}
	t.Run("not read while off", func(t *testing.T) {
		t.Setenv("PA_CONVERSATION_TTL", "a day")
		cfg, err := Load()
		if err != nil || cfg.PAConversationTTL != 0 {
			t.Fatalf("ttl=%v err=%v, want unread", cfg.PAConversationTTL, err)
		}
	})
}
