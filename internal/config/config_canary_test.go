package config

import (
	"strings"
	"testing"
)

// CANARY_TELEGRAM_IDS: unset guards nothing, a list is kept, and a malformed
// value stops startup rather than leaving the canary unguarded (issue #961).
func TestLoadCanaryTelegramIDs(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv("CANARY_TELEGRAM_IDS", "")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if len(cfg.CanaryTelegramIDs) != 0 {
			t.Fatalf("CanaryTelegramIDs = %v, want empty", cfg.CanaryTelegramIDs)
		}
	})
	t.Run("list", func(t *testing.T) {
		t.Setenv("CANARY_TELEGRAM_IDS", "7001, 7002")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if !cfg.CanaryTelegramIDs.Contains(7001) || !cfg.CanaryTelegramIDs.Contains(7002) || len(cfg.CanaryTelegramIDs) != 2 {
			t.Fatalf("CanaryTelegramIDs = %v, want {7001, 7002}", cfg.CanaryTelegramIDs)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		t.Setenv("CANARY_TELEGRAM_IDS", "7001,@alice")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "CANARY_TELEGRAM_IDS") {
			t.Fatalf("Load() error = %v, want a CANARY_TELEGRAM_IDS error", err)
		}
	})
}
