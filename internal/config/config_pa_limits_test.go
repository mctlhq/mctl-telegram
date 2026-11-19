package config

import (
	"testing"
	"time"
)

// TestLoadPA_Limits: the run-loop limits default to the owner decisions,
// are read only when PA_ENABLED, and a bad value refuses to start rather
// than falling back to a default (#1313 slice d1).
func TestLoadPA_Limits(t *testing.T) {
	enable := func(t *testing.T) {
		t.Setenv("PA_ENABLED", "true")
		t.Setenv("PA_BOT_TOKEN", testPABotToken)
		t.Setenv("PA_WEBHOOK_SECRET", testPASecret)
		t.Setenv("TELEGRAM_LOGIN_BOT_TOKEN", testLoginBotToken)
	}
	t.Run("defaults", func(t *testing.T) {
		enable(t)
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.PARateMessages != 20 || cfg.PARateWindow != time.Hour || cfg.PAMaxContextTokens != 32000 ||
			cfg.PABudgetUSDJob != 0.25 || cfg.PABudgetUSDDay != 2 || cfg.PABudgetUSDMonth != 20 {
			t.Fatalf("defaults = %d/%v/%d/%v/%v/%v", cfg.PARateMessages, cfg.PARateWindow, cfg.PAMaxContextTokens,
				cfg.PABudgetUSDJob, cfg.PABudgetUSDDay, cfg.PABudgetUSDMonth)
		}
	})
	t.Run("set", func(t *testing.T) {
		enable(t)
		t.Setenv("PA_RATE_MESSAGES", "5")
		t.Setenv("PA_RATE_WINDOW", "10m")
		t.Setenv("PA_MAX_CONTEXT_TOKENS", "8000")
		t.Setenv("PA_BUDGET_USD_JOB", "0.1")
		t.Setenv("PA_BUDGET_USD_DAY", "1")
		t.Setenv("PA_BUDGET_USD_MONTH", "5")
		cfg, err := Load()
		if err != nil || cfg.PARateMessages != 5 || cfg.PARateWindow != 10*time.Minute || cfg.PAMaxContextTokens != 8000 ||
			cfg.PABudgetUSDJob != 0.1 || cfg.PABudgetUSDDay != 1 || cfg.PABudgetUSDMonth != 5 {
			t.Fatalf("cfg=%+v err=%v", cfg, err)
		}
	})
	for key, val := range map[string]string{
		"PA_RATE_MESSAGES":      "0",
		"PA_MAX_CONTEXT_TOKENS": "lots",
		"PA_RATE_WINDOW":        "1s",
		"PA_BUDGET_USD_JOB":     "-1",
		"PA_BUDGET_USD_DAY":     "NaN",
		"PA_BUDGET_USD_MONTH":   "0.1", // below the day cap
	} {
		t.Run("refuses "+key, func(t *testing.T) {
			enable(t)
			t.Setenv(key, val)
			if _, err := Load(); err == nil {
				t.Fatalf("%s=%s accepted", key, val)
			}
		})
	}
	t.Run("refuses a job dearer than the global day", func(t *testing.T) {
		enable(t)
		// The managed checks pass (its job cost is lowered to fit), so
		// only the PA check can refuse.
		t.Setenv("MANAGED_MAX_JOB_COST_USD", "0.1")
		t.Setenv("MANAGED_BUDGET_USD_GLOBAL_DAY", "0.2")
		if _, err := Load(); err == nil {
			t.Fatal("PA_BUDGET_USD_JOB above MANAGED_BUDGET_USD_GLOBAL_DAY accepted")
		}
	})
	t.Run("off reads nothing", func(t *testing.T) {
		t.Setenv("PA_ENABLED", "false")
		t.Setenv("PA_RATE_MESSAGES", "0")
		cfg, err := Load()
		if err != nil || cfg.PARateMessages != 0 {
			t.Fatalf("rate=%d err=%v, want unread", cfg.PARateMessages, err)
		}
	})
}
