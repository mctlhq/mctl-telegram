package db

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
)

// newFreshSchemaPostgresStore opens TEST_DATABASE_URL in a schema of its own,
// migrated from scratch, so its tables carry no planner statistics. That is
// the state in which Postgres planned the old IN (subquery LIMIT ... SKIP
// LOCKED) claim as a re-run semi join; a database other tests have filled
// may plan it differently and hide the bug.
func newFreshSchemaPostgresStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := Open(ctx, dsn, 2, 1)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	schema := fmt.Sprintf("claim_test_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		_ = admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_ = admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	conn, err := Open(ctx, u.String(), 10, 2)
	if err != nil {
		t.Fatalf("open schema-scoped conn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	c, err := crypto.New(makeKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	return &Store{DB: conn, Crypt: c}
}

// seedManagedAccount creates an account on runtime with n due jobs, each in a
// conversation of its own so the per-conversation serialization in the claim
// never limits how many can be claimed at once. login must be unique per run
// on Postgres, whose database outlives the test.
func seedManagedAccount(t *testing.T, s *Store, login, runtime string, n int) int64 {
	t.Helper()
	ctx := context.Background()
	uid := seedAgentUser(t, s, login)
	setRuntime(t, s, uid, runtime)
	for i := 0; i < n; i++ {
		conv, err := s.EnsureConversation(ctx, uid, int64(7000+i), "peer", "Peer")
		if err != nil {
			t.Fatalf("conversation: %v", err)
		}
		jobID := seedJob(t, s, uid, fmt.Sprintf("evt:v1:%s:%d:1", login, i))
		if _, err := s.DB.ExecContext(ctx, `UPDATE agent_jobs SET conversation_id = $1, next_run_at = $2 WHERE id = $3`,
			conv.ID, time.Now().UTC().Add(-time.Minute), jobID); err != nil {
			t.Fatalf("bind conversation: %v", err)
		}
	}
	return uid
}

func processingCount(t *testing.T, s *Store, uid int64) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM agent_jobs WHERE user_id = $1 AND status = $2`, uid, JobProcessing).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The in-flight cap is enforced by the claim itself, not by the candidate
// list the pool reads first. A second claimer that saw the account below the
// cap (a stale hint) gets nothing once another claim filled it, and the cap
// also bounds limit. Deterministic on SQLite.
// Mutation: drop the reserveInflight call from claimAgentJobs.
func TestClaimManagedAgentJobs_CapIsAuthoritativeOverStaleHint(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedManagedAccount(t, s, "capped", RuntimeManaged, 4)
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET telegram_login_id = 9811 WHERE id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	// Both claimers read the hint while the account is empty.
	cands, err := s.ListManagedClaimCandidates(ctx, time.Now(), 1, nil, 10)
	if err != nil || len(cands) != 1 || cands[0].UserID != uid {
		t.Fatalf("candidates = %+v err %v", cands, err)
	}
	first, err := s.ClaimManagedAgentJobs(ctx, "pool-a", uid, 1, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim: %d jobs, err %v", len(first), err)
	}
	second, err := s.ClaimManagedAgentJobs(ctx, "pool-b", uid, 1, 1)
	if err != nil || len(second) != 0 {
		t.Fatalf("second claim on a stale hint: %d jobs, err %v; want 0", len(second), err)
	}
	// Cap 3 with one in flight leaves room for two, whatever limit asks.
	more, err := s.ClaimManagedAgentJobs(ctx, "pool-a", uid, 10, 3)
	if err != nil || len(more) != 2 {
		t.Fatalf("claim with room for two: %d jobs, err %v", len(more), err)
	}
	if n := processingCount(t, s, uid); n != 3 {
		t.Fatalf("processing = %d, want 3", n)
	}
	if _, err := s.ClaimManagedAgentJobs(ctx, "pool-a", uid, 1, 0); err == nil {
		t.Fatal("a cap below 1 must be refused, not treated as unlimited")
	}
}

// The coalesced claim path enforces the same cap.
// Mutation: drop the reserveInflight call from claimCoalesced.
func TestClaimManagedAgentJobs_CapOnCoalescedPath(t *testing.T) {
	ctx := context.Background()
	f := newTurnFixture(t, &turnCfg)
	setRuntime(t, f.s, f.uid, RuntimeManaged)
	f.ingest(t, 555, 1, 5, 0)
	f.ingest(t, 556, 1, 5, 0)
	f.now = turnBase.Add(time.Minute)
	if jobs, err := f.s.ClaimManagedAgentJobs(ctx, "r", f.uid, 5, 1); err != nil || len(jobs) != 1 {
		t.Fatalf("coalesced capped claim: %d jobs, err %v; want 1", len(jobs), err)
	}
	if jobs, err := f.s.ClaimManagedAgentJobs(ctx, "r", f.uid, 5, 1); err != nil || len(jobs) != 0 {
		t.Fatalf("second coalesced claim at the cap: %d jobs, err %v; want 0", len(jobs), err)
	}
}

// runConcurrentCappedClaims starts n claims of uid at once (cap 1, limit 1)
// and returns how many jobs they claimed in total.
func runConcurrentCappedClaims(t *testing.T, s *Store, uid int64, n int) int {
	t.Helper()
	ctx := context.Background()
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	total := 0
	var firstErr error
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			jobs, err := s.ClaimManagedAgentJobs(ctx, fmt.Sprintf("pool-%d", i), uid, 1, 1)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			total += len(jobs)
		}(i)
	}
	close(start)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("concurrent claim: %v", firstErr)
	}
	return total
}

// Concurrent pool claims of one account never exceed the cap (SQLite).
func TestClaimManagedAgentJobs_ConcurrentClaimsRespectCap(t *testing.T) {
	s := newTestStoreCrypted(t)
	uid := seedManagedAccount(t, s, "racer", RuntimeManaged, 8)
	if got := runConcurrentCappedClaims(t, s, uid, 8); got != 1 {
		t.Fatalf("8 concurrent claims took %d jobs under a cap of 1", got)
	}
	if n := processingCount(t, s, uid); n != 1 {
		t.Fatalf("processing = %d, want 1", n)
	}
}

// Same race on Postgres, where the claims really run in parallel
// transactions: only the per-account advisory lock makes the count and the
// claim atomic. 20 rounds of 8 claimers.
// Mutation: drop the pg_advisory_xact_lock statement in reserveInflight
// (keeping the count) -- READ COMMITTED lets parallel claimers all count 0.
func TestClaimManagedAgentJobs_InflightCap_Postgres(t *testing.T) {
	s := newFreshSchemaPostgresStore(t)
	for round := 0; round < 20; round++ {
		uid := seedManagedAccount(t, s, fmt.Sprintf("pgcap-%d", round), RuntimeManaged, 8)
		if got := runConcurrentCappedClaims(t, s, uid, 8); got != 1 {
			t.Fatalf("round %d: 8 concurrent claims took %d jobs under a cap of 1", round, got)
		}
		if n := processingCount(t, s, uid); n != 1 {
			t.Fatalf("round %d: processing = %d, want 1", round, n)
		}
	}
}

// A claim never takes more than limit jobs, on either runtime, on Postgres
// tables without statistics. Regression test for the IN (subquery LIMIT ...
// SKIP LOCKED) claim, which took all 8 due jobs for limit 1 there.
// Mutation: restore "WHERE status = $4 AND id IN (SELECT j.id ... LIMIT $5
// FOR UPDATE SKIP LOCKED)" in place of the CTE.
func TestClaimAgentJobs_LimitHonoured_Postgres(t *testing.T) {
	ctx := context.Background()
	s := newFreshSchemaPostgresStore(t)
	own := seedManagedAccount(t, s, "limit-own", RuntimeOwn, 8)
	managed := seedManagedAccount(t, s, "limit-managed", RuntimeManaged, 8)
	for _, limit := range []int{1, 3} {
		jobs, err := s.ClaimAgentJobs(ctx, "w", own, RuntimeOwn, limit)
		if err != nil || len(jobs) != limit {
			t.Fatalf("own claim limit %d: %d jobs, err %v", limit, len(jobs), err)
		}
		jobs, err = s.ClaimManagedAgentJobs(ctx, "pool", managed, limit, 100)
		if err != nil || len(jobs) != limit {
			t.Fatalf("managed claim limit %d: %d jobs, err %v", limit, len(jobs), err)
		}
	}
	if n := processingCount(t, s, own); n != 4 {
		t.Fatalf("own processing = %d, want 4", n)
	}
}

// T12 (store half): once the account's runtime moves, an attempt claimed
// under the old runtime cannot close the job, by either completion writer;
// the stale-claim sweep returns it to pending, the old runtime can no longer
// claim it and the new one claims it stamped with the new runtime.
// Mutation: drop completeRuntimeFence from either completion UPDATE.
func TestCompleteAgentJob_RuntimeSwitchFence(t *testing.T) {
	ctx := context.Background()
	for _, withResult := range []bool{false, true} {
		t.Run(fmt.Sprintf("with_result=%v", withResult), func(t *testing.T) {
			s := newTestStoreCrypted(t)
			uid := seedManagedAccount(t, s, "switcher", RuntimeOwn, 1)
			jobs, err := s.ClaimAgentJobs(ctx, "own-worker", uid, RuntimeOwn, 1)
			if err != nil || len(jobs) != 1 || jobs[0].Runtime != RuntimeOwn {
				t.Fatalf("own claim: %+v err %v", jobs, err)
			}
			j := jobs[0]
			if _, err := s.DB.ExecContext(ctx, `UPDATE agent_profiles SET runtime = $1 WHERE user_id = $2`, RuntimeManaged, uid); err != nil {
				t.Fatal(err)
			}
			if withResult {
				err = s.CompleteAgentJobWithResult(ctx, uid, j.ID, j.Attempts, JobFailed, "late", 0, 0)
			} else {
				err = s.CompleteAgentJob(ctx, j.ID, j.Attempts, JobCompleted, "late")
			}
			if !errors.Is(err, ErrAgentJobNotFound) {
				t.Fatalf("completion under the old runtime: %v, want ErrAgentJobNotFound", err)
			}
			if got, _ := s.GetAgentJob(ctx, uid, j.ID); got.Status != JobProcessing {
				t.Fatalf("fenced job status = %s, want processing", got.Status)
			}
			if _, err := s.DB.ExecContext(ctx, `UPDATE agent_jobs SET claimed_at = $1 WHERE id = $2`, time.Now().UTC().Add(-time.Hour), j.ID); err != nil {
				t.Fatal(err)
			}
			if requeued, _, err := s.RequeueStaleAgentJobs(ctx, time.Minute); err != nil || requeued != 1 {
				t.Fatalf("requeue: %d err %v", requeued, err)
			}
			if again, err := s.ClaimAgentJobs(ctx, "own-worker", uid, RuntimeOwn, 1); err != nil || len(again) != 0 {
				t.Fatalf("old runtime reclaimed: %d jobs err %v", len(again), err)
			}
			reclaimed, err := s.ClaimManagedAgentJobs(ctx, "pool", uid, 1, 1)
			if err != nil || len(reclaimed) != 1 || reclaimed[0].Runtime != RuntimeManaged || reclaimed[0].Attempts != j.Attempts+1 {
				t.Fatalf("managed reclaim: %+v err %v", reclaimed, err)
			}
			// The new runtime's attempt completes normally.
			if err := s.CompleteAgentJob(ctx, reclaimed[0].ID, reclaimed[0].Attempts, JobIgnored, ""); err != nil {
				t.Fatalf("complete under the current runtime: %v", err)
			}
		})
	}
}

// A job claimed before agent_jobs.runtime existed (NULL) is not fenced, and
// an own account's own job completes as before.
func TestCompleteAgentJob_RuntimeFenceLeavesLegacyAndOwnAlone(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedManagedAccount(t, s, "legacy", RuntimeOwn, 2)
	jobs, err := s.ClaimAgentJobs(ctx, "w", uid, RuntimeOwn, 2)
	if err != nil || len(jobs) != 2 {
		t.Fatalf("claim: %d err %v", len(jobs), err)
	}
	if err := s.CompleteAgentJob(ctx, jobs[0].ID, jobs[0].Attempts, JobIgnored, ""); err != nil {
		t.Fatalf("own job on own account: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE agent_jobs SET runtime = NULL WHERE id = $1`, jobs[1].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE agent_profiles SET runtime = $1 WHERE user_id = $2`, RuntimeManaged, uid); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteAgentJob(ctx, jobs[1].ID, jobs[1].Attempts, JobIgnored, ""); err != nil {
		t.Fatalf("legacy NULL-runtime job: %v", err)
	}
}

// T17 (store half): a release whose CAS no longer matches writes nothing,
// including when the job has already left processing.
// Mutation: drop "status = $6" from the ReleaseUnissuedClaim UPDATE.
func TestReleaseUnissuedClaim_StatusChangedWritesNothing(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedManagedAccount(t, s, "released", RuntimeManaged, 1)
	jobs, err := s.ClaimManagedAgentJobs(ctx, "pool", uid, 1, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: %v", err)
	}
	j := jobs[0]
	if err := s.CompleteAgentJob(ctx, j.ID, j.Attempts, JobIgnored, "done"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseUnissuedClaim(ctx, j.ID, j.Attempts, "pool"); !errors.Is(err, ErrAgentJobNotFound) {
		t.Fatalf("release of a finished job: %v, want ErrAgentJobNotFound", err)
	}
	got, err := s.GetAgentJob(ctx, uid, j.ID)
	if err != nil || got.Status != JobIgnored || got.Attempts != j.Attempts || got.LastError != "done" {
		t.Fatalf("finished job changed by a refused release: %+v err %v", got, err)
	}
	var rows int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM agent_job_attempts WHERE job_id = $1`, j.ID).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("attempt rows = %d err %v; the closed attempt must stay", rows, err)
	}
}

// T17 (coalesced half): releasing an unissued coalesced claim keeps the turn
// membership, so the reclaim carries the same SourceEventIDs, with attempts
// one above the pre-claim value, max_attempts untouched and the same turn id.
// Mutations: replace ReleaseUnissuedClaim with RetryAgentJob (attempt count);
// clear turn_id in the release.
func TestReleaseUnissuedClaim_CoalescedKeepsTurn(t *testing.T) {
	ctx := context.Background()
	f := newTurnFixture(t, &turnCfg)
	setRuntime(t, f.s, f.uid, RuntimeManaged)
	var ids []string
	for i := int64(0); i < 3; i++ {
		ids = append(ids, f.ingest(t, 555, 20+i, 5, time.Duration(i)*time.Second))
	}
	f.now = turnBase.Add(time.Minute)
	first, err := f.s.ClaimManagedAgentJobs(ctx, "pool", f.uid, 1, 1)
	if err != nil || len(first) != 1 || strings.Join(first[0].SourceEventIDs, ",") != strings.Join(ids, ",") {
		t.Fatalf("first claim: %+v err %v", first, err)
	}
	var maxBefore int
	if err := f.s.DB.QueryRow(`SELECT max_attempts FROM agent_jobs WHERE id = $1`, first[0].ID).Scan(&maxBefore); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxBefore+2; i++ {
		jobs, err := f.s.ClaimManagedAgentJobs(ctx, "pool", f.uid, 1, 1)
		if i == 0 {
			jobs, err = first, nil
		}
		if err != nil || len(jobs) != 1 {
			t.Fatalf("round %d claim: %d err %v", i, len(jobs), err)
		}
		if err := f.s.ReleaseUnissuedClaim(ctx, jobs[0].ID, jobs[0].Attempts, "pool"); err != nil {
			t.Fatalf("round %d release: %v", i, err)
		}
		if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET next_run_at = $1 WHERE id = $2`, turnBase, jobs[0].ID); err != nil {
			t.Fatal(err)
		}
	}
	// A message arriving after the release must not join the frozen turn: it
	// waits for a turn of its own. Re-forming the turn on reclaim would pull
	// it in.
	late := f.ingest(t, 555, 99, 5, 3*time.Second) // inside the turn window
	f.now = turnBase.Add(2 * time.Minute)
	again, err := f.s.ClaimManagedAgentJobs(ctx, "pool", f.uid, 1, 1)
	if err != nil || len(again) != 1 {
		t.Fatalf("reclaim: %d err %v", len(again), err)
	}
	if st, _ := f.status(t, late); st != JobPending {
		t.Fatalf("late message status = %s, want pending (not part of the released turn)", st)
	}
	if again[0].ID != first[0].ID || again[0].Attempts != 1 || again[0].MaxAttempts != maxBefore ||
		again[0].TurnID == "" || again[0].TurnID != first[0].TurnID ||
		strings.Join(again[0].SourceEventIDs, ",") != strings.Join(ids, ",") || again[0].Status != JobProcessing {
		t.Fatalf("reclaim after %d releases: %+v; want same head, attempt 1, max %d, sources %v", maxBefore+2, again[0], maxBefore, ids)
	}
}

// Flag-off surfacing: managed accounts with pending jobs are counted, own
// accounts and managed accounts without pending work are not.
func TestCountManagedAccountsWithPendingJobs(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	seedManagedAccount(t, s, "m1", RuntimeManaged, 2)
	seedManagedAccount(t, s, "m2", RuntimeManaged, 1)
	seedManagedAccount(t, s, "o1", RuntimeOwn, 3)
	idle := seedManagedAccount(t, s, "m3", RuntimeManaged, 1)
	if _, err := s.DB.ExecContext(ctx, `UPDATE agent_jobs SET status = $1 WHERE user_id = $2`, JobCompleted, idle); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CountManagedAccountsWithPendingJobs(ctx); err != nil || n != 2 {
		t.Fatalf("count = %d err %v; want 2", n, err)
	}
}

// A runtime-fenced job on its last attempt is requeued for the new runtime
// with one more attempt, not dead-lettered; a stale job that was not fenced
// still dead-letters on its last attempt.
// Mutation: drop the fenced-requeue transition from RequeueStaleAgentJobs.
func TestRequeueStale_RuntimeFencedLastAttemptIsReclaimed(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	fenced := seedManagedAccount(t, s, "fenced", RuntimeOwn, 1)
	plain := seedManagedAccount(t, s, "plain", RuntimeOwn, 1)
	var jobs []AgentJob
	for _, uid := range []int64{fenced, plain} {
		if _, err := s.DB.ExecContext(ctx, `UPDATE agent_jobs SET max_attempts = 1 WHERE user_id = $1`, uid); err != nil {
			t.Fatal(err)
		}
		got, err := s.ClaimAgentJobs(ctx, "own-worker", uid, RuntimeOwn, 1)
		if err != nil || len(got) != 1 || got[0].Attempts != 1 {
			t.Fatalf("claim: %+v err %v", got, err)
		}
		jobs = append(jobs, got[0])
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE agent_profiles SET runtime = $1 WHERE user_id = $2`, RuntimeManaged, fenced); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE agent_jobs SET claimed_at = $1`, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	requeued, dead, err := s.RequeueStaleAgentJobs(ctx, time.Minute)
	if err != nil || requeued != 1 || dead != 1 {
		t.Fatalf("sweep: requeued=%d dead=%d err %v; want 1 and 1", requeued, dead, err)
	}
	f, _ := s.GetAgentJob(ctx, fenced, jobs[0].ID)
	if f.Status != JobPending || f.Attempts != 1 || f.MaxAttempts != 2 {
		t.Fatalf("fenced job %+v; want pending, attempts 1, max 2", f)
	}
	if p, _ := s.GetAgentJob(ctx, plain, jobs[1].ID); p.Status != JobDeadLetter {
		t.Fatalf("unfenced last-attempt job status %s, want dead_letter", p.Status)
	}
	var open int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM agent_job_attempts WHERE job_id = $1 AND finished_at IS NULL`, f.ID).Scan(&open); err != nil || open != 0 {
		t.Fatalf("fenced job open attempt rows = %d err %v", open, err)
	}
	re, err := s.ClaimManagedAgentJobs(ctx, "pool", fenced, 1, 1)
	if err != nil || len(re) != 1 || re[0].Attempts != 2 || re[0].Runtime != RuntimeManaged {
		t.Fatalf("new runtime reclaim: %+v err %v; want attempt 2 as managed", re, err)
	}
}

// Candidates mirror the claim's per-conversation rule: an account whose only
// due job waits behind a processing job of the same conversation is not a
// candidate (it would only take a window slot).
// Mutation: drop the NOT EXISTS predicate.
func TestListManagedClaimCandidates_HeadOfLineAndPaging(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	blocked, a, b := seedPagingAccounts(t, s, "hol")
	var conv int64
	if err := s.DB.QueryRow(`SELECT conversation_id FROM agent_jobs WHERE user_id = $1`, blocked).Scan(&conv); err != nil {
		t.Fatal(err)
	}
	busy := seedJob(t, s, blocked, "evt:v1:hol-blocked:busy:1")
	if _, err := s.DB.ExecContext(ctx, `UPDATE agent_jobs SET conversation_id = $1, status = $2 WHERE id = $3`, conv, JobProcessing, busy); err != nil {
		t.Fatal(err)
	}
	all, err := s.ListManagedClaimCandidates(ctx, time.Now(), 5, nil, 10)
	if err != nil || len(all) != 2 || all[0].UserID != a || all[1].UserID != b {
		t.Fatalf("candidates = %+v err %v; want a, b (blocked excluded)", all, err)
	}
	assertKeysetPaging(t, s, []int64{a, b})
}

// seedPagingAccounts creates three managed accounts with one due job each,
// due in creation order, and returns their user ids.
func seedPagingAccounts(t *testing.T, s *Store, prefix string) (int64, int64, int64) {
	t.Helper()
	ctx := context.Background()
	var uids []int64
	for i, name := range []string{"blocked", "a", "b"} {
		uid := seedManagedAccount(t, s, prefix+"-"+name, RuntimeManaged, 1)
		if _, err := s.DB.ExecContext(ctx, `UPDATE users SET telegram_login_id = $1 WHERE id = $2`, 9850+int64(i)+int64(len(prefix))*10, uid); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.ExecContext(ctx, `UPDATE agent_jobs SET next_run_at = $1 WHERE user_id = $2`,
			time.Now().UTC().Add(-time.Hour).Add(time.Duration(i)*time.Second), uid); err != nil {
			t.Fatal(err)
		}
		uids = append(uids, uid)
	}
	return uids[0], uids[1], uids[2]
}

// assertKeysetPaging walks the candidate order one account per page and
// checks it visits want in order, then stops. A served account dropping out
// between pages must not make the walk skip the next one, which an offset
// would. Mutation: ignore the cursor (every page restarts at the front).
func assertKeysetPaging(t *testing.T, s *Store, want []int64) {
	t.Helper()
	ctx := context.Background()
	var after *ManagedClaimCursor
	var got []int64
	for i := 0; i < len(want)+2; i++ {
		page, err := s.ListManagedClaimCandidates(ctx, time.Now(), 5, after, 1)
		if err != nil {
			t.Fatalf("page %d: %v", i, err)
		}
		if len(page) == 0 {
			break
		}
		got = append(got, page[0].UserID)
		after = &page[0].Cursor
		if i == 0 {
			// The first account is served: its only job leaves pending.
			if _, err := s.DB.ExecContext(ctx, `UPDATE agent_jobs SET status = $1 WHERE user_id = $2`, JobCompleted, page[0].UserID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("keyset walk visited %v, want %v", got, want)
	}
}

// The cursor holds the aggregate as the driver returned it; prove the walk on
// Postgres too, where that is a timestamptz rather than SQLite's text.
func TestListManagedClaimCandidates_KeysetPaging_Postgres(t *testing.T) {
	s := newFreshSchemaPostgresStore(t)
	_, a, b := seedPagingAccounts(t, s, "pg")
	// No head-of-line block here: all three are candidates.
	all, err := s.ListManagedClaimCandidates(context.Background(), time.Now(), 5, nil, 10)
	if err != nil || len(all) != 3 {
		t.Fatalf("candidates = %+v err %v", all, err)
	}
	assertKeysetPaging(t, s, []int64{all[0].UserID, a, b})
}
