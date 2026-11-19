package config

import (
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// TestLoadPA_Limits: the run-loop limits default to the owner decisions,
// are read only when PA_ENABLED, and a bad value refuses to start rather
// than falling back to a default (#1313 slice d1).
func TestLoadPA_Limits(t *testing.T) {
	enable := func(t *testing.T) {
		t.Setenv("PA_ENABLED", "true")
		t.Setenv("PA_BOT_TOKEN", testPABotToken)
		t.Setenv("PA_WEBHOOK_SECRET", testPASecret)
		t.Setenv("PA_WEBHOOK_URL", testPAWebhookURL)
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
		if cfg.PAMinTurnUSD != 0.005 {
			t.Fatalf("PA_MIN_TURN_COST_USD default = %v, want 0.005", cfg.PAMinTurnUSD)
		}
		if b := cfg.PABudget(); !b.Valid() || b.MinTurnUSD != 0.005 || !b.ClaimNotAfter.IsZero() {
			t.Fatalf("PABudget = %+v", b)
		}
	})
	// Owner decision 2026-11-19: MANAGED_CLAIM_NOT_AFTER ends PA claims
	// too, so the PA budget carries it.
	t.Run("MANAGED_CLAIM_NOT_AFTER reaches the PA budget", func(t *testing.T) {
		enable(t)
		t.Setenv("MANAGED_CLAIM_NOT_AFTER", "2030-06-15T00:00:00Z")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		want := time.Date(2030, 6, 15, 0, 0, 0, 0, time.UTC)
		b := cfg.PABudget()
		if !b.ClaimNotAfter.Equal(want) || b.ClaimsEnded(want.Add(-time.Second)) || !b.ClaimsEnded(want) {
			t.Fatalf("PA budget cutoff = %v", b.ClaimNotAfter)
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
		t.Setenv("PA_MIN_TURN_COST_USD", "0.01")
		cfg, err := Load()
		if err != nil || cfg.PARateMessages != 5 || cfg.PARateWindow != 10*time.Minute || cfg.PAMaxContextTokens != 8000 ||
			cfg.PABudgetUSDJob != 0.1 || cfg.PABudgetUSDDay != 1 || cfg.PABudgetUSDMonth != 5 || cfg.PAMinTurnUSD != 0.01 {
			t.Fatalf("cfg=%+v err=%v", cfg, err)
		}
	})
	for key, val := range map[string]string{
		"PA_MIN_TURN_COST_USD":  "0",
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
	// The floor of a run at its turn cap must fit the reservation:
	// 9 turns x 0.03 = 0.27 > 0.25, while 9 x 0.025 = 0.225 fits.
	t.Run("refuses a turn floor above the reservation", func(t *testing.T) {
		enable(t)
		t.Setenv("PA_MIN_TURN_COST_USD", "0.03")
		if _, err := Load(); err == nil {
			t.Fatal("PA_MIN_TURN_COST_USD x turn cap above PA_BUDGET_USD_JOB accepted")
		}
		t.Setenv("PA_MIN_TURN_COST_USD", "0.025")
		if _, err := Load(); err != nil {
			t.Fatalf("a floor that fits refused: %v", err)
		}
	})
	// Owner decision 2026-11-19 (P3-2): no absolute settlement ceiling. A
	// reservation above $1 loads, and its run settles up to 4x of it.
	t.Run("no absolute ceiling on a large reservation", func(t *testing.T) {
		enable(t)
		t.Setenv("MANAGED_BUDGET_USD_GLOBAL_DAY", "20")
		t.Setenv("PA_BUDGET_USD_JOB", "1.5")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("PA_BUDGET_USD_JOB=1.5 refused: %v", err)
		}
		b := cfg.PABudget()
		if !b.Valid() || b.PerJobUSD != 1.5 {
			t.Fatalf("budget %+v, want a valid 1.5 reservation", b)
		}
		if got := jobs.Settle(100, b.PerJobUSD, 1, b.MinTurnUSD); got != 6 {
			t.Fatalf("settled %v, want 6 (4 x 1.5, no clamp)", got)
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
