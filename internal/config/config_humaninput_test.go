package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadHumanInput(t *testing.T) {
	t.Run("default off", func(t *testing.T) {
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if cfg.HumanInputEnabled {
			t.Error("HUMAN_INPUT_ENABLED must default to false")
		}
		if cfg.HumanInputPollInterval != 30*time.Second {
			t.Errorf("HumanInputPollInterval = %s, want 30s", cfg.HumanInputPollInterval)
		}
	})
	t.Run("valid with work context", func(t *testing.T) {
		t.Setenv("WORK_CONTEXT_ENABLED", "true")
		t.Setenv("MCTL_SURFACE_TELEGRAM_TOKEN", "surface-token")
		t.Setenv("MCTL_WORK_ITEM_TENANT", "tenant-1")
		t.Setenv("HUMAN_INPUT_ENABLED", "true")
		t.Setenv("HUMAN_INPUT_POLL_INTERVAL", "15s")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if !cfg.HumanInputEnabled || cfg.HumanInputPollInterval != 15*time.Second {
			t.Errorf("got enabled=%v interval=%s", cfg.HumanInputEnabled, cfg.HumanInputPollInterval)
		}
	})
	t.Run("refused without work context", func(t *testing.T) {
		t.Setenv("HUMAN_INPUT_ENABLED", "true")
		_, err := Load()
		if err == nil || !strings.Contains(err.Error(), "WORK_CONTEXT_ENABLED") {
			t.Fatalf("Load() error = %v, want WORK_CONTEXT_ENABLED refusal", err)
		}
	})
	t.Run("refused below minimum interval", func(t *testing.T) {
		t.Setenv("WORK_CONTEXT_ENABLED", "true")
		t.Setenv("MCTL_SURFACE_TELEGRAM_TOKEN", "surface-token")
		t.Setenv("MCTL_WORK_ITEM_TENANT", "tenant-1")
		t.Setenv("HUMAN_INPUT_ENABLED", "true")
		t.Setenv("HUMAN_INPUT_POLL_INTERVAL", "5s")
		if _, err := Load(); err == nil {
			t.Fatal("Load() accepted a poll interval below 10s")
		}
	})
}
