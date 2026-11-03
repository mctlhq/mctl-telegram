package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// budgetNow is a fixed mid-window clock so the tests never straddle UTC midnight.
var budgetNow = time.Date(2030, 6, 15, 12, 0, 0, 0, time.UTC)

func withBudget(s *Store, perJob, acctDay, acctMonth, globalDay float64) *Store {
	return s.WithManagedBudget(ManagedBudget{
		PerJobUSD: perJob, AccountDayUSD: acctDay, AccountMonthUSD: acctMonth, GlobalDayUSD: globalDay,
		Now: func() time.Time { return budgetNow },
	})
}

func setLoginID(t *testing.T, s *Store, uid, login int64) {
	t.Helper()
	if _, err := s.DB.Exec(`UPDATE users SET telegram_login_id = $1 WHERE id = $2`, login, uid); err != nil {
		t.Fatal(err)
	}
}

func usageRows(t *testing.T, s *Store, where string, args ...any) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM agent_usage WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func budgetNotifications(t *testing.T, s *Store, uid int64) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM owner_notifications WHERE user_id = $1 AND kind = $2`, uid, NotificationBudget).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func pausedUntil(t *testing.T, s *Store, uid int64) time.Time {
	t.Helper()
	p, err := s.GetAgentProfile(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	return p.BudgetPausedUntil
}

func claimOne(t *testing.T, s *Store, uid int64) []AgentJob {
	t.Helper()
	jobs, err := s.ClaimManagedAgentJobs(context.Background(), "pool", uid, 5, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	return jobs
}

func claimConcurrently(t *testing.T, s *Store, uids ...int64) int {
	t.Helper()
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	total := 0
	var firstErr error
	for i, uid := range uids {
		wg.Add(1)
		go func(i int, uid int64) {
			defer wg.Done()
			<-start
			jobs, err := s.ClaimManagedAgentJobs(context.Background(), fmt.Sprintf("pool-%d", i), uid, 2, 2)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			total += len(jobs)
		}(i, uid)
	}
	close(start)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("concurrent claim: %v", firstErr)
	}
	return total
}

// T1: the reservation caps hold when claims race. Mutation (account): drop the
// in-flight (reserved) term from usageSums/slots. Mutation (global): drop the
// global lock (Postgres run).
func TestManagedClaim_BudgetRace(t *testing.T) {
	t.Run("account_sqlite", func(t *testing.T) {
		s := withBudget(newTestStoreCrypted(t), 0.5, 0.5, 15, 20)
		uid := seedManagedAccount(t, s, "acct", RuntimeManaged, 2)
		if got := claimOne(t, s, uid); len(got) != 1 {
			t.Fatalf("first claim took %d jobs, want 1", len(got))
		}
		if got := claimOne(t, s, uid); len(got) != 0 {
			t.Fatalf("second claim took %d jobs, want 0", len(got))
		}
		if n := usageRows(t, s, `status = 'reserved' AND user_id = $1`, uid); n != 1 {
			t.Fatalf("reserved rows = %d, want 1", n)
		}
	})
	t.Run("global_sqlite", func(t *testing.T) {
		s := withBudget(newTestStoreCrypted(t), 0.5, 5, 15, 0.5)
		a := seedManagedAccount(t, s, "ga", RuntimeManaged, 1)
		b := seedManagedAccount(t, s, "gb", RuntimeManaged, 1)
		total := len(claimOne(t, s, a)) + len(claimOne(t, s, b))
		if total != 1 {
			t.Fatalf("claimed %d jobs under a global cap of one", total)
		}
	})
	t.Run("account_postgres", func(t *testing.T) {
		s := withBudget(newFreshSchemaPostgresStore(t), 0.5, 0.5, 15, 20)
		uid := seedManagedAccount(t, s, "pg-acct", RuntimeManaged, 2)
		if got := claimConcurrently(t, s, uid, uid); got != 1 {
			t.Fatalf("claimed %d jobs, want 1", got)
		}
		if n := usageRows(t, s, `status = 'reserved'`); n != 1 {
			t.Fatalf("reserved rows = %d, want 1", n)
		}
	})
	t.Run("global_postgres", func(t *testing.T) {
		for round := 0; round < 10; round++ {
			s := withBudget(newFreshSchemaPostgresStore(t), 0.5, 5, 15, 0.5)
			a := seedManagedAccount(t, s, "pg-ga", RuntimeManaged, 1)
			b := seedManagedAccount(t, s, "pg-gb", RuntimeManaged, 1)
			if got := claimConcurrently(t, s, a, b); got != 1 {
				t.Fatalf("round %d: claimed %d jobs under a global cap of one", round, got)
			}
		}
	})
}

// T2. Mutation: skip the status update to settled in RecordAgentJobUsage.
func TestReservation_SettledOnCost(t *testing.T) {
	ctx := context.Background()
	s := withBudget(newTestStoreCrypted(t), 0.5, 0.6, 15, 20)
	uid := seedManagedAccount(t, s, "settle", RuntimeManaged, 2)
	jobs := claimOne(t, s, uid)
	if len(jobs) != 1 {
		t.Fatalf("claim: %d", len(jobs))
	}
	// Reserved at 0.50: 0.10 of the 0.60 cap is left, no room for a job.
	if got := claimOne(t, s, uid); len(got) != 0 {
		t.Fatalf("claim over the reservation took %d jobs", len(got))
	}
	j := jobs[0]
	out, err := s.RecordAgentJobUsage(ctx, uid, j.ID, j.Attempts, Usage{CostUSD: 0.02, Model: "m", Runner: "openai", InputTokens: 10, OutputTokens: 5})
	if err != nil || out != UsageRecorded {
		t.Fatalf("settle: %v %v", out, err)
	}
	var status, runtime string
	var cost float64
	if err := s.DB.QueryRow(`SELECT status, cost_usd, runtime FROM agent_usage WHERE job_id = $1 AND attempt = $2`, j.ID, j.Attempts).Scan(&status, &cost, &runtime); err != nil {
		t.Fatal(err)
	}
	if status != UsageSettled || cost != 0.02 || runtime != RuntimeManaged {
		t.Fatalf("row = %s %v %s", status, cost, runtime)
	}
	// The next claim sees the 0.02 cost, not the 0.50 reservation.
	if got := claimOne(t, s, uid); len(got) != 1 {
		t.Fatalf("claim after settle took %d jobs, want 1", len(got))
	}
}

// Three settle outcomes of RecordAgentJobUsage plus the legacy wrapper.
// Mutation: skip the conflict comparison (always UsageUnchanged).
func TestRecordAgentJobUsage_Outcomes(t *testing.T) {
	ctx := context.Background()
	s := withBudget(newTestStoreCrypted(t), 0.5, 1, 15, 20)
	uid := seedManagedAccount(t, s, "outcomes", RuntimeManaged, 1)
	j := claimOne(t, s, uid)[0]
	u := Usage{CostUSD: 0.1, Model: "m", Runner: "claude", InputTokens: 3, OutputTokens: 4}
	if out, err := s.RecordAgentJobUsage(ctx, uid, j.ID, j.Attempts, u); err != nil || out != UsageRecorded {
		t.Fatalf("first: %v %v", out, err)
	}
	if out, err := s.RecordAgentJobUsage(ctx, uid, j.ID, j.Attempts, u); err != nil || out != UsageUnchanged {
		t.Fatalf("repeat: %v %v", out, err)
	}
	for _, d := range []Usage{
		{CostUSD: 0.2, Model: "m", Runner: "claude", InputTokens: 3, OutputTokens: 4},
		{CostUSD: 0.1, Model: "x", Runner: "claude", InputTokens: 3, OutputTokens: 4},
		{CostUSD: 0.1, Model: "m", Runner: "claude", InputTokens: 9, OutputTokens: 4},
	} {
		if _, err := s.RecordAgentJobUsage(ctx, uid, j.ID, j.Attempts, d); !errors.Is(err, ErrUsageConflict) {
			t.Fatalf("different report %+v: %v, want ErrUsageConflict", d, err)
		}
	}
	if _, err := s.RecordAgentJobUsage(ctx, uid, j.ID, j.Attempts+1, u); !errors.Is(err, ErrAgentJobNotFound) {
		t.Fatalf("stale attempt: %v", err)
	}
	if n := usageRows(t, s, `job_id = $1`, j.ID); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
	var runner string
	var in int64
	if err := s.DB.QueryRow(`SELECT runner, input_tokens FROM agent_usage WHERE job_id = $1`, j.ID).Scan(&runner, &in); err != nil || runner != "claude" || in != 3 {
		t.Fatalf("row changed: %s %d %v", runner, in, err)
	}
	// Legacy shape through the wrapper on an own job.
	own := seedManagedAccount(t, s, "legacyown", RuntimeOwn, 1)
	oj, err := s.ClaimAgentJobs(ctx, "w", own, RuntimeOwn, 1)
	if err != nil || len(oj) != 1 {
		t.Fatalf("own claim: %v", err)
	}
	if err := s.RecordAgentJobCost(ctx, own, oj[0].ID, oj[0].Attempts, 0.07); err != nil {
		t.Fatal(err)
	}
}

// T9: an own job settles as runtime own and never counts toward managed caps.
// Mutation: default the inserted runtime to managed.
func TestRecordCost_OwnJobNeverManaged(t *testing.T) {
	ctx := context.Background()
	s := withBudget(newTestStoreCrypted(t), 0.5, 0.5, 15, 0.5)
	own := seedManagedAccount(t, s, "ownacct", RuntimeOwn, 1)
	oj, err := s.ClaimAgentJobs(ctx, "w", own, RuntimeOwn, 1)
	if err != nil || len(oj) != 1 {
		t.Fatalf("own claim: %v", err)
	}
	if _, err := s.RecordAgentJobUsage(ctx, own, oj[0].ID, oj[0].Attempts, Usage{CostUSD: 9, Runner: "claude"}); err != nil {
		t.Fatal(err)
	}
	var rt, status string
	if err := s.DB.QueryRow(`SELECT runtime, status FROM agent_usage WHERE job_id = $1`, oj[0].ID).Scan(&rt, &status); err != nil || rt != RuntimeOwn || status != UsageSettled {
		t.Fatalf("row = %s %s %v", rt, status, err)
	}
	managed := seedManagedAccount(t, s, "mgd", RuntimeManaged, 1)
	if got := claimOne(t, s, managed); len(got) != 1 {
		t.Fatalf("managed claim after a large own spend took %d jobs, want 1", len(got))
	}
}

// T3. Mutation: remove the DELETE in ReleaseUnissuedClaim (the re-claim then
// fails on UNIQUE(job_id, attempt)).
func TestReservation_DeletedOnUnissuedRelease(t *testing.T) {
	ctx := context.Background()
	s := withBudget(newTestStoreCrypted(t), 0.5, 1, 15, 20)
	uid := seedManagedAccount(t, s, "unissued", RuntimeManaged, 1)
	j := claimOne(t, s, uid)[0]
	if err := s.ReleaseUnissuedClaim(ctx, j.ID, j.Attempts, "pool"); err != nil {
		t.Fatal(err)
	}
	if n := usageRows(t, s, `job_id = $1`, j.ID); n != 0 {
		t.Fatalf("rows after release = %d, want 0", n)
	}
	if _, err := s.DB.Exec(`UPDATE agent_jobs SET next_run_at = $1 WHERE id = $2`, time.Now().UTC().Add(-time.Minute), j.ID); err != nil {
		t.Fatal(err)
	}
	again := claimOne(t, s, uid)
	if len(again) != 1 || again[0].Attempts != j.Attempts {
		t.Fatalf("re-claim: %+v", again)
	}
	if n := usageRows(t, s, `job_id = $1 AND status = 'reserved'`, j.ID); n != 1 {
		t.Fatalf("reserved rows = %d, want 1", n)
	}
}

func ageClaim(t *testing.T, s *Store, jobID int64) {
	t.Helper()
	if _, err := s.DB.Exec(`UPDATE agent_jobs SET claimed_at = $1 WHERE id = $2`, time.Now().UTC().Add(-time.Hour), jobID); err != nil {
		t.Fatal(err)
	}
}

func runHeldOnDeadlineCrossing(t *testing.T, mk func(t *testing.T) *Store) {
	ctx := context.Background()
	for _, kind := range []string{"requeued", "dead_lettered", "fenced"} {
		t.Run(kind, func(t *testing.T) {
			s := withBudget(mk(t), 0.5, 1.0, 15, 20)
			uid := seedManagedAccount(t, s, "held-"+kind, RuntimeManaged, 2)
			jobs := claimOne(t, s, uid)
			if len(jobs) != 2 {
				t.Fatalf("claim took %d jobs, want 2", len(jobs))
			}
			j := jobs[0]
			// Both seeded jobs fit under the 1.00 cap, so claimOne took both; only j ages.
			switch kind {
			case "dead_lettered":
				if _, err := s.DB.Exec(`UPDATE agent_jobs SET max_attempts = 1 WHERE id = $1`, j.ID); err != nil {
					t.Fatal(err)
				}
			case "fenced":
				if _, err := s.DB.Exec(`UPDATE agent_profiles SET runtime = 'own' WHERE user_id = $1`, uid); err != nil {
					t.Fatal(err)
				}
			}
			ageClaim(t, s, j.ID)
			if _, _, err := s.RequeueStaleAgentJobs(ctx, time.Minute); err != nil {
				t.Fatal(err)
			}
			var status string
			if err := s.DB.QueryRow(`SELECT status FROM agent_usage WHERE job_id = $1 AND attempt = $2`, j.ID, j.Attempts).Scan(&status); err != nil || status != UsageHeld {
				t.Fatalf("status = %q err %v, want held", status, err)
			}
			usd, rows, err := s.HeldUsage(ctx)
			if err != nil || usd != 0.5 || rows != 1 {
				t.Fatalf("HeldUsage = %v %d %v, want 0.5 1", usd, rows, err)
			}
			if kind == "fenced" {
				return
			}
			if kind == "dead_lettered" {
				// A dead-lettered job cannot be re-claimed; a late report settles it.
				if _, err := s.RecordAgentJobUsage(ctx, uid, j.ID, j.Attempts, Usage{CostUSD: 0.03}); err != nil {
					t.Fatalf("late report: %v", err)
				}
				if usd, rows, _ := s.HeldUsage(ctx); usd != 0 || rows != 0 {
					t.Fatalf("held after settle = %v %d", usd, rows)
				}
				return
			}
			// A late report while attempts still matches settles at the reported cost.
			if _, err := s.RecordAgentJobUsage(ctx, uid, j.ID, j.Attempts, Usage{CostUSD: 0.03}); err != nil {
				t.Fatalf("late report: %v", err)
			}
			var cost float64
			if err := s.DB.QueryRow(`SELECT cost_usd FROM agent_usage WHERE job_id = $1 AND attempt = $2 AND status = 'settled'`, j.ID, j.Attempts).Scan(&cost); err != nil || cost != 0.03 {
				t.Fatalf("settled cost = %v err %v", cost, err)
			}
		})
	}
	t.Run("reclaim_refuses_old_report", func(t *testing.T) {
		s := withBudget(mk(t), 0.5, 2.0, 15, 20)
		uid := seedManagedAccount(t, s, "held-reclaim", RuntimeManaged, 1)
		j := claimOne(t, s, uid)[0]
		ageClaim(t, s, j.ID)
		if _, _, err := s.RequeueStaleAgentJobs(ctx, time.Minute); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.Exec(`UPDATE agent_jobs SET next_run_at = $1 WHERE id = $2`, time.Now().UTC().Add(-time.Minute), j.ID); err != nil {
			t.Fatal(err)
		}
		again := claimOne(t, s, uid)
		if len(again) != 1 || again[0].Attempts != j.Attempts+1 {
			t.Fatalf("re-claim: %+v", again)
		}
		if _, err := s.RecordAgentJobUsage(ctx, uid, j.ID, j.Attempts, Usage{CostUSD: 0.01}); !errors.Is(err, ErrAgentJobNotFound) {
			t.Fatalf("old attempt report: %v, want ErrAgentJobNotFound", err)
		}
		var status string
		if err := s.DB.QueryRow(`SELECT status FROM agent_usage WHERE job_id = $1 AND attempt = $2`, j.ID, j.Attempts).Scan(&status); err != nil || status != UsageHeld {
			t.Fatalf("old row = %q err %v, want held", status, err)
		}
	})
}

// T14. Mutation: set a non-held status (or delete the row) in the sweeper.
func TestReservation_HeldOnDeadlineCrossing(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { runHeldOnDeadlineCrossing(t, newTestStoreCrypted) })
	t.Run("postgres", func(t *testing.T) { runHeldOnDeadlineCrossing(t, newFreshSchemaPostgresStore) })
}

// T4. Mutation: remove the budget_paused_until predicate from the candidate query.
func TestManagedCandidates_ExcludeExhaustedAccount(t *testing.T) {
	ctx := context.Background()
	s := withBudget(newTestStoreCrypted(t), 0.5, 1, 15, 20)
	a := seedManagedAccount(t, s, "cand-a", RuntimeManaged, 1)
	b := seedManagedAccount(t, s, "cand-b", RuntimeManaged, 1)
	setLoginID(t, s, a, 9001)
	setLoginID(t, s, b, 9002)
	if _, err := s.DB.Exec(`UPDATE agent_profiles SET budget_paused_until = $1 WHERE user_id = $2`, time.Now().UTC().Add(time.Hour), a); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListManagedClaimCandidates(ctx, time.Now(), 1, nil, 10)
	if err != nil || len(got) != 1 || got[0].UserID != b {
		t.Fatalf("candidates = %+v err %v, want only %d", got, err, b)
	}
	// Past the pause the account is listed again.
	got, err = s.ListManagedClaimCandidates(ctx, time.Now().Add(2*time.Hour), 1, nil, 10)
	if err != nil || len(got) != 2 {
		t.Fatalf("candidates after the window = %+v err %v", got, err)
	}
}

// T5. Mutation: remove the global guard from the candidate query.
func TestManagedCandidates_ExcludeGlobal(t *testing.T) {
	ctx := context.Background()
	s := withBudget(newTestStoreCrypted(t), 0.5, 5, 15, 1.0)
	a := seedManagedAccount(t, s, "glob-a", RuntimeManaged, 2)
	b := seedManagedAccount(t, s, "glob-b", RuntimeManaged, 1)
	setLoginID(t, s, a, 9101)
	setLoginID(t, s, b, 9102)
	if got := claimOne(t, s, a); len(got) != 2 {
		t.Fatalf("claim: %d", len(got))
	}
	// Global usage 1.00 of 1.00: no room for another 0.50.
	got, err := s.ListManagedClaimCandidates(ctx, budgetNow, 5, nil, 10)
	if err != nil || len(got) != 0 {
		t.Fatalf("candidates = %+v err %v, want none", got, err)
	}
}

// T10. Mutation: drop the "budget_paused_until < $end" guard in pauseForBudget.
func TestBudgetNotification_OncePerWindow(t *testing.T) {
	ctx := context.Background()
	now := budgetNow
	s := newTestStoreCrypted(t).WithManagedBudget(ManagedBudget{
		PerJobUSD: 0.5, AccountDayUSD: 0.5, AccountMonthUSD: 15, GlobalDayUSD: 20,
		Now: func() time.Time { return now },
	})
	reg := metrics.New()
	s.WithMetrics(reg)
	uid := seedManagedAccount(t, s, "notify", RuntimeManaged, 4)

	j := claimOne(t, s, uid)[0]
	if _, err := s.RecordAgentJobUsage(ctx, uid, j.ID, j.Attempts, Usage{CostUSD: 0.5}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if got := claimOne(t, s, uid); len(got) != 0 {
			t.Fatalf("exhausted claim took %d jobs", len(got))
		}
	}
	if n := budgetNotifications(t, s, uid); n != 1 {
		t.Fatalf("notifications = %d, want 1", n)
	}
	wantEnd := time.Date(2030, 6, 16, 0, 0, 0, 0, time.UTC)
	if got := pausedUntil(t, s, uid); !got.Equal(wantEnd) {
		t.Fatalf("paused until %v, want %v", got, wantEnd)
	}
	if v := testutil.ToFloat64(reg.AgentBudgetExhaustedTotal.WithLabelValues("account_day")); v != 2 {
		t.Fatalf("exhausted counter = %v, want 2", v)
	}
	// Next window: one claim works, exhausting it again queues one more.
	now = now.Add(24 * time.Hour)
	j2 := claimOne(t, s, uid)
	if len(j2) != 1 {
		t.Fatalf("claim in the new window took %d jobs", len(j2))
	}
	if _, err := s.RecordAgentJobUsage(ctx, uid, j2[0].ID, j2[0].Attempts, Usage{CostUSD: 0.5}); err != nil {
		t.Fatal(err)
	}
	claimOne(t, s, uid)
	claimOne(t, s, uid)
	if n := budgetNotifications(t, s, uid); n != 2 {
		t.Fatalf("notifications after the window moved = %d, want 2", n)
	}
}

// T10, global half. Mutation: as above.
func TestBudgetNotification_GlobalOncePerAccount(t *testing.T) {
	ctx := context.Background()
	{
		g := withBudget(newTestStoreCrypted(t), 0.5, 5, 15, 0.5)
		a := seedManagedAccount(t, g, "gn-a", RuntimeManaged, 2)
		b := seedManagedAccount(t, g, "gn-b", RuntimeManaged, 1)
		idle := seedManagedAccount(t, g, "gn-idle", RuntimeManaged, 0)
		ja := claimOne(t, g, a)
		if len(ja) != 1 {
			t.Fatalf("claim a: %d", len(ja))
		}
		if _, err := g.RecordAgentJobUsage(ctx, a, ja[0].ID, ja[0].Attempts, Usage{CostUSD: 0.5}); err != nil {
			t.Fatal(err)
		}
		claimOne(t, g, b)
		claimOne(t, g, b)
		claimOne(t, g, a)
		for _, u := range []int64{a, b} {
			if n := budgetNotifications(t, g, u); n != 1 {
				t.Fatalf("user %d notifications = %d, want 1", u, n)
			}
		}
		if n := budgetNotifications(t, g, idle); n != 0 {
			t.Fatalf("idle account notified %d times", n)
		}
	}
}

// T11. Mutation: remove the NOT EXISTS budget predicate from RouteUnclaimedAgentJobs.
func TestRouteUnclaimed_SkipsBudgetPaused(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t).WithEventOutbox(reasonBuilder).WithOperatorRouting(true)
	paused := seedManagedAccount(t, s, "route-paused", RuntimeManaged, 1)
	free := seedManagedAccount(t, s, "route-free", RuntimeManaged, 1)
	if _, err := s.DB.Exec(`UPDATE agent_jobs SET created_at = $1`, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE agent_profiles SET budget_paused_until = $1 WHERE user_id = $2`, time.Now().UTC().Add(time.Hour), paused); err != nil {
		t.Fatal(err)
	}
	if n, err := s.RouteUnclaimedAgentJobs(ctx, time.Minute); err != nil || n != 1 {
		t.Fatalf("route: %d %v, want 1", n, err)
	}
	status := func(uid int64) string {
		var st string
		if err := s.DB.QueryRow(`SELECT status FROM agent_jobs WHERE user_id = $1`, uid).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	if status(paused) != JobPending || status(free) != JobRouted {
		t.Fatalf("paused=%s free=%s", status(paused), status(free))
	}
}

// Override columns change the cap the claim uses.
// Mutation: ignore the managed_budget_usd_day override in reserveBudget.
func TestReserveBudget_AccountOverride(t *testing.T) {
	ctx := context.Background()
	s := withBudget(newTestStoreCrypted(t), 0.5, 0.5, 15, 20)
	uid := seedManagedAccount(t, s, "override", RuntimeManaged, 3)
	day := 1.0
	if err := s.UpdateAgentProfileFields(ctx, uid, AgentProfileUpdate{ManagedBudgetUSDDay: &day}); err != nil {
		t.Fatal(err)
	}
	if got := claimOne(t, s, uid); len(got) != 2 {
		t.Fatalf("claim with a 1.00 override took %d jobs, want 2", len(got))
	}
	p, _ := s.GetAgentProfile(ctx, uid)
	if p.ManagedBudgetUSDDay == nil || *p.ManagedBudgetUSDDay != 1.0 || p.ManagedBudgetUSDMonth != nil {
		t.Fatalf("profile override = %+v", p)
	}
	if err := s.UpdateAgentProfileFields(ctx, uid, AgentProfileUpdate{ClearManagedBudgetUSDDay: true}); err != nil {
		t.Fatal(err)
	}
	if p, _ = s.GetAgentProfile(ctx, uid); p.ManagedBudgetUSDDay != nil {
		t.Fatal("override not cleared")
	}
}

// Own claims and managed claims without a budget never touch the ledger or the lock.
func TestClaim_NoBudgetNoLedger(t *testing.T) {
	s := newTestStoreCrypted(t)
	locked := false
	s.budgetLockHook = func(int64) { locked = true }
	own := seedManagedAccount(t, s, "nb-own", RuntimeOwn, 1)
	mgd := seedManagedAccount(t, s, "nb-mgd", RuntimeManaged, 1)
	if _, err := s.ClaimAgentJobs(context.Background(), "w", own, RuntimeOwn, 1); err != nil {
		t.Fatal(err)
	}
	if got := claimOne(t, s, mgd); len(got) != 1 {
		t.Fatalf("claim: %d", len(got))
	}
	s = withBudget(s, 0.5, 5, 15, 20)
	own2 := seedManagedAccount(t, s, "nb-own2", RuntimeOwn, 1)
	if _, err := s.ClaimAgentJobs(context.Background(), "w", own2, RuntimeOwn, 1); err != nil {
		t.Fatal(err)
	}
	if locked || usageRows(t, s, `1 = 1`) != 0 {
		t.Fatalf("budget code ran for an unbudgeted claim (locked=%v)", locked)
	}
}

// T15 (Postgres). Mutation: decide the pause on durable + in-flight usage.
func TestBudget_InflightReservationsDoNotPause(t *testing.T) {
	ctx := context.Background()
	s := withBudget(newFreshSchemaPostgresStore(t), 0.5, 5, 15, 1.0)
	reg := metrics.New()
	s.WithMetrics(reg)
	a := seedManagedAccount(t, s, "inf-a", RuntimeManaged, 1)
	b := seedManagedAccount(t, s, "inf-b", RuntimeManaged, 1)
	c := seedManagedAccount(t, s, "inf-c", RuntimeManaged, 1)
	ja, jb := claimOne(t, s, a), claimOne(t, s, b)
	if len(ja) != 1 || len(jb) != 1 {
		t.Fatalf("setup claims: %d %d", len(ja), len(jb))
	}
	if got := claimOne(t, s, c); len(got) != 0 {
		t.Fatalf("c claimed %d jobs", len(got))
	}
	if !pausedUntil(t, s, c).IsZero() || budgetNotifications(t, s, c) != 0 {
		t.Fatal("in-flight reservations paused or notified the account")
	}
	if v := testutil.ToFloat64(reg.AgentBudgetExhaustedTotal.WithLabelValues("global_day")); v != 0 {
		t.Fatalf("exhausted = %v, want 0", v)
	}
	if v := testutil.ToFloat64(reg.AgentBudgetDeferredTotal.WithLabelValues("global_day")); v != 1 {
		t.Fatalf("deferred = %v, want 1", v)
	}
	for _, p := range []struct {
		uid int64
		j   AgentJob
	}{{a, ja[0]}, {b, jb[0]}} {
		if _, err := s.RecordAgentJobUsage(ctx, p.uid, p.j.ID, p.j.Attempts, Usage{CostUSD: 0.02}); err != nil {
			t.Fatal(err)
		}
	}
	if got := claimOne(t, s, c); len(got) != 1 {
		t.Fatalf("c after settle claimed %d jobs, want 1", len(got))
	}
}

// T15 on SQLite: the same durable/transient split without concurrency.
func TestBudget_InflightReservationsDoNotPause_SQLite(t *testing.T) {
	s := withBudget(newTestStoreCrypted(t), 0.5, 5, 15, 0.5)
	a := seedManagedAccount(t, s, "isq-a", RuntimeManaged, 1)
	b := seedManagedAccount(t, s, "isq-b", RuntimeManaged, 1)
	if len(claimOne(t, s, a)) != 1 {
		t.Fatal("a did not claim")
	}
	if got := claimOne(t, s, b); len(got) != 0 {
		t.Fatalf("b claimed %d", len(got))
	}
	if !pausedUntil(t, s, b).IsZero() || budgetNotifications(t, s, b) != 0 {
		t.Fatal("transient exhaustion paused or notified")
	}
}

// T16 (Postgres). Mutation: take the account advisory lock and an
// agent_profiles ... FOR UPDATE before the global lock (the first draft's
// order); B then holds its profile row when A's global pause reaches it.
func TestManagedClaim_GlobalPauseNoDeadlock(t *testing.T) {
	ctx := context.Background()
	s := withBudget(newFreshSchemaPostgresStore(t), 0.5, 5, 15, 0.5)
	a := seedManagedAccount(t, s, "dl-a", RuntimeManaged, 2)
	b := seedManagedAccount(t, s, "dl-b", RuntimeManaged, 1)
	// A settles 0.5: the global day is durably exhausted.
	ja := claimOne(t, s, a)
	if len(ja) != 1 {
		t.Fatalf("setup claim: %d", len(ja))
	}
	if _, err := s.RecordAgentJobUsage(ctx, a, ja[0].ID, ja[0].Attempts, Usage{CostUSD: 0.5}); err != nil {
		t.Fatal(err)
	}
	reached := make(chan struct{})
	release := make(chan struct{})
	s.budgetLockHook = func(uid int64) {
		if uid == b {
			close(reached)
			<-release
		}
	}
	bDone := make(chan error, 1)
	go func() {
		_, err := s.ClaimManagedAgentJobs(ctx, "pool-b", b, 1, 1)
		bDone <- err
	}()
	select {
	case <-reached:
	case <-time.After(10 * time.Second):
		t.Fatal("claim B never reached the global lock")
	}
	aDone := make(chan error, 1)
	go func() {
		_, err := s.ClaimManagedAgentJobs(ctx, "pool-a", a, 1, 2)
		aDone <- err
	}()
	select {
	case err := <-aDone:
		if err != nil {
			t.Fatalf("claim A: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("claim A timed out: deadlocked against claim B")
	}
	close(release)
	select {
	case err := <-bDone:
		if err != nil {
			if strings.Contains(err.Error(), "40P01") {
				t.Fatalf("claim B deadlocked: %v", err)
			}
			t.Fatalf("claim B: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("claim B timed out")
	}
	if pausedUntil(t, s, b).IsZero() {
		t.Fatal("B was not paused")
	}
	if n := budgetNotifications(t, s, b); n != 1 {
		t.Fatalf("B notifications = %d, want 1", n)
	}
}

// HeldUsage and the managed account gauge source.
func TestHeldUsage_OnlyManagedHeldCurrentDay(t *testing.T) {
	ctx := context.Background()
	s := withBudget(newTestStoreCrypted(t), 0.5, 5, 15, 20)
	uid := seedManagedAccount(t, s, "gauge", RuntimeManaged, 1)
	if usd, rows, err := s.HeldUsage(ctx); err != nil || usd != 0 || rows != 0 {
		t.Fatalf("empty: %v %d %v", usd, rows, err)
	}
	if n, err := s.CountManagedAccounts(ctx); err != nil || n != 1 {
		t.Fatalf("managed accounts = %d %v", n, err)
	}
	_ = uid
}

// The coalesced claim path reserves too, and stops at the cap.
// Mutation: drop the insertReservation call from claimCoalesced.
func TestManagedClaim_BudgetOnCoalescedPath(t *testing.T) {
	ctx := context.Background()
	f := newTurnFixture(t, &turnCfg)
	withBudget(f.s, 0.5, 0.5, 15, 20)
	setRuntime(t, f.s, f.uid, RuntimeManaged)
	f.ingest(t, 555, 1, 5, 0)
	f.ingest(t, 556, 1, 5, 0)
	f.now = turnBase.Add(time.Minute)
	jobs, err := f.s.ClaimManagedAgentJobs(ctx, "r", f.uid, 5, 5)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("coalesced budgeted claim: %d jobs, err %v; want 1", len(jobs), err)
	}
	if n := usageRows(t, f.s, `job_id = $1 AND status = 'reserved' AND reserved_usd = 0.5`, jobs[0].ID); n != 1 {
		t.Fatalf("reservation rows = %d, want 1", n)
	}
	if more, err := f.s.ClaimManagedAgentJobs(ctx, "r", f.uid, 5, 5); err != nil || len(more) != 0 {
		t.Fatalf("claim over the cap: %d jobs, err %v", len(more), err)
	}
}
