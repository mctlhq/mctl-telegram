package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// The PA run-loop store (issue #1313 slice d1) on both dialects. The
// SQLite and Postgres entry points run the same body; Postgres keeps state
// between runs, so the body clears its own principals first and measures
// the shared global-day window instead of assuming it is empty.

const (
	paAlice int64 = 555
	paBob   int64 = 556
)

func TestPAJobs_SQLite(t *testing.T) {
	runPAJobsSuite(t, newTestStore(t))
}

func TestPAJobsPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	runPAJobsSuite(t, s)
	t.Run("concurrent claims share one global window", func(t *testing.T) { paConcurrentGlobal(t, s) })
	t.Run("concurrent claimers count one failure once", func(t *testing.T) { paConcurrentFailure(t, s) })
}

// paConcurrentFailure: claimers that fail on the same job at the same
// instant record one failure, not one each.
func paConcurrentFailure(t *testing.T, s *Store) {
	f := newPAFixture(t, s)
	f.enqueue(paAlice, "c1")
	gate := func(context.Context, *sql.Tx, jobs.Job, time.Time) error { return errors.New("alice's row") }
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = s.ClaimPAJob(context.Background(), jobs.ClaimRequest{
				Now: f.now, Lease: time.Minute, Budget: f.b, Gate: gate, Build: paBuild(),
			})
		}()
	}
	wg.Wait()
	var n int
	if err := s.DB.QueryRow(`SELECT claim_failures FROM pa_jobs WHERE principal = $1`, paAlice).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("claim_failures = %d after one failure instant, want 1", n)
	}
}

func paReset(t *testing.T, s *Store) {
	t.Helper()
	for _, q := range []string{
		`DELETE FROM pa_jobs WHERE principal IN ($1, $2)`,
		`DELETE FROM pa_usage WHERE principal IN ($1, $2)`,
		`DELETE FROM pa_rate WHERE principal IN ($1, $2)`,
	} {
		if _, err := s.DB.Exec(q, paAlice, paBob); err != nil {
			t.Fatal(err)
		}
	}
}

func okGate(context.Context, *sql.Tx, jobs.Job, time.Time) error { return nil }

func paBuild(tools ...string) jobs.Build {
	return func(_ context.Context, _ *sql.Tx, j jobs.Job, res int64) ([]byte, string, []string, error) {
		b := []byte(fmt.Sprintf(`{"job":%d,"attempt":%d,"res":%d}`, j.ID, j.Attempts, res))
		sum := sha256.Sum256(b)
		return b, hex.EncodeToString(sum[:]), tools, nil
	}
}

// globalDayNow is the global-day spend (both ledgers, durable + in
// flight) at now, as the claim sees it.
func globalDayNow(t *testing.T, s *Store, now time.Time) float64 {
	t.Helper()
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	d, i, err := usageSums(context.Background(), tx, day, 0)
	if err != nil {
		t.Fatal(err)
	}
	return d + i
}

type paFixture struct {
	t   *testing.T
	s   *Store
	now time.Time
	b   jobs.Budget
}

func (f *paFixture) enqueue(p int64, conv string) jobs.EnqueueOutcome {
	f.t.Helper()
	tx, err := f.s.DB.Begin()
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	out, err := f.s.EnqueuePAJob(context.Background(), tx, jobs.EnqueueRequest{
		Principal: p, ConversationID: conv, UpdateID: 1, ConsentVersion: "pa-data-flow/v1", Now: f.now,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *paFixture) claim(tools ...string) jobs.ClaimResult {
	f.t.Helper()
	res, err := f.s.ClaimPAJob(context.Background(), jobs.ClaimRequest{
		Now: f.now, Lease: 5 * time.Minute, Budget: f.b, Gate: okGate, Build: paBuild(tools...),
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

func ref(j jobs.Job) jobs.Ref {
	return jobs.Ref{Principal: j.Principal, JobID: j.ID, Attempt: j.Attempts, Digest: j.ContextDigest}
}

func (f *paFixture) finish(j jobs.Job, cost float64) {
	f.t.Helper()
	if _, err := f.s.FinishPAJob(context.Background(), ref(j), jobs.FinishRequest{Now: f.now, CostUSD: cost, MinTurnUSD: f.b.MinTurnUSD, Gate: okGate}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *paFixture) turn(j jobs.Job) {
	f.t.Helper()
	if _, err := f.s.AdmitPATurn(context.Background(), ref(j), jobs.TurnRequest{
		Now: f.now, ContextTokens: 1, MaxContextTokens: 100, MaxTurns: 9, Gate: okGate,
	}); err != nil {
		f.t.Fatal(err)
	}
}

func firstPAJob(t *testing.T, s *Store, principal int64) int64 {
	t.Helper()
	var id int64
	if err := s.DB.QueryRow(`SELECT MIN(id) FROM pa_jobs WHERE principal = $1`, principal).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *paFixture) status(id int64) (string, string) {
	f.t.Helper()
	var js, us string
	if err := f.s.DB.QueryRow(`SELECT status FROM pa_jobs WHERE id = $1`, id).Scan(&js); err != nil {
		f.t.Fatal(err)
	}
	err := f.s.DB.QueryRow(`SELECT status FROM pa_usage WHERE job_id = $1 ORDER BY attempt DESC LIMIT 1`, id).Scan(&us)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		f.t.Fatal(err)
	}
	return js, us
}

func newPAFixture(t *testing.T, s *Store) *paFixture {
	paReset(t, s)
	now := time.Now().UTC()
	// Far from midnight, so the day window cannot roll over mid-test.
	if now.Hour() == 23 && now.Minute() > 50 {
		now = now.Add(-time.Hour)
	}
	return &paFixture{t: t, s: s, now: now, b: jobs.Budget{
		PerJobUSD: 0.25, PrincipalDayUSD: 2, PrincipalMonthUSD: 20, GlobalDayUSD: 1e6, MinTurnUSD: 0.005,
	}}
}

func runPAJobsSuite(t *testing.T, s *Store) {
	t.Run("one queued and one running job per principal", func(t *testing.T) {
		f := newPAFixture(t, s)
		if f.enqueue(paAlice, "c1") != jobs.Enqueued || f.enqueue(paAlice, "c1") != jobs.Coalesced {
			t.Fatal("second message of the same conversation must coalesce")
		}
		r := f.claim()
		if r.Outcome != jobs.ClaimClaimed || r.Job.Principal != paAlice || r.Job.Attempts != 1 {
			t.Fatalf("claim = %+v", r)
		}
		if f.enqueue(paAlice, "c1") != jobs.Enqueued {
			t.Fatal("a message during a run must queue the next run")
		}
		if got := f.claim(); got.Outcome != jobs.ClaimNone {
			t.Fatalf("a second running job for Alice: %+v", got)
		}
	})

	t.Run("claim reserves, finish settles the reported cost", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		r := f.claim()
		if js, us := f.status(r.Job.ID); js != "claimed" || us != "reserved" {
			t.Fatalf("after claim: job %s usage %s", js, us)
		}
		f.finish(r.Job, 0.07)
		rows, err := s.PAUsageFor(context.Background(), paAlice)
		if err != nil || len(rows) != 1 || rows[0].Status != "settled" || math.Abs(rows[0].Cost.Float64-0.07) > 1e-9 {
			t.Fatalf("usage = %+v err=%v", rows, err)
		}
		// Unreported cost settles at the full reservation.
		f.enqueue(paAlice, "c1")
		r = f.claim()
		f.finish(r.Job, -1)
		rows, _ = s.PAUsageFor(context.Background(), paAlice)
		if math.Abs(rows[1].Cost.Float64-0.25) > 1e-9 {
			t.Fatalf("unreported cost settled at %v, want the reservation", rows[1].Cost)
		}
	})

	// S1-R3 (store part): an exhausted budget holds the job, says so once,
	// takes no reservation, and the job runs once the window resets.
	t.Run("S1-R3 principal day budget holds once", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.b.PrincipalDayUSD = 0.5
		for range 2 {
			f.enqueue(paAlice, "c1")
			f.finish(f.claim().Job, -1)
		}
		f.enqueue(paAlice, "c1")
		r := f.claim()
		if r.Outcome != jobs.ClaimHeld || !r.Notify || r.Scope != jobs.ScopePrincipalDay {
			t.Fatalf("claim over budget = %+v", r)
		}
		if js, us := f.status(r.Job.ID); js != "held" || us != "" {
			t.Fatalf("held job: job %s usage %q (a held job takes no reservation)", js, us)
		}
		if again := f.claim(); again.Outcome != jobs.ClaimNone || again.Notify {
			t.Fatalf("held job claimed again or notified twice: %+v", again)
		}
		// Due again while the budget is still spent (the hold time has
		// passed, the spend has not aged out): held again, not told again.
		if _, err := s.DB.Exec(`UPDATE pa_jobs SET held_until_ms = $1 WHERE id = $2`, f.now.Add(-time.Second).UnixMilli(), r.Job.ID); err != nil {
			t.Fatal(err)
		}
		if again := f.claim(); again.Outcome != jobs.ClaimHeld || again.Notify {
			t.Fatalf("re-held job = %+v, want held without a second notice", again)
		}
		f.now = r.Job.HeldUntil.Add(time.Second)
		if next := f.claim(); next.Outcome != jobs.ClaimClaimed || next.Job.ID != r.Job.ID {
			t.Fatalf("after the window reset: %+v", next)
		}
	})

	// The global day is one window for the managed runtime and the PA:
	// PA spend shows in usageSums (which the managed claim reads), and a
	// PA claim is held by spend it did not make itself.
	t.Run("global day window is shared with the managed ledger", func(t *testing.T) {
		f := newPAFixture(t, s)
		before := globalDayNow(t, s, f.now)
		f.enqueue(paAlice, "c1")
		r := f.claim()
		if got := globalDayNow(t, s, f.now) - before; math.Abs(got-0.25) > 1e-6 {
			t.Fatalf("a PA reservation moved the global day by %v, want 0.25", got)
		}
		f.finish(r.Job, -1)
		f.b.GlobalDayUSD = globalDayNow(t, s, f.now) + 0.1
		f.enqueue(paBob, "c2")
		if h := f.claim(); h.Outcome != jobs.ClaimHeld || h.Scope != jobs.ScopeGlobalDay || h.Job.Principal != paBob {
			t.Fatalf("Bob over the global cap = %+v", h)
		}
	})

	t.Run("in-flight reservations defer, they do not hold", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		f.claim()
		f.b.GlobalDayUSD = globalDayNow(t, s, f.now) + 0.1 // 0.35 with Alice's 0.25 in flight
		f.enqueue(paBob, "c2")
		if r := f.claim(); r.Outcome != jobs.ClaimDeferred || r.Notify {
			t.Fatalf("Bob behind an in-flight reservation = %+v", r)
		}
	})

	// S1-X2 (budget part): Alice's spend never holds Bob.
	t.Run("S1-X2 one principal's budget does not touch another's", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.b.PrincipalDayUSD = 0.25
		f.enqueue(paAlice, "c1")
		f.finish(f.claim().Job, -1)
		f.enqueue(paAlice, "c1")
		if r := f.claim(); r.Outcome != jobs.ClaimHeld {
			t.Fatalf("Alice = %+v", r)
		}
		f.enqueue(paBob, "c2")
		r := f.claim()
		if r.Outcome != jobs.ClaimClaimed || r.Job.Principal != paBob {
			t.Fatalf("Bob held by Alice's spend: %+v", r)
		}
		rows, _ := s.PAUsageFor(context.Background(), paBob)
		if len(rows) != 1 || rows[0].Principal != paBob {
			t.Fatalf("Bob's ledger = %+v", rows)
		}
	})

	// S1-R2 and S1-I1 (store part).
	t.Run("S1-R2 tool-call cap and S1-I1 tool set", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		j := f.claim("tg/get_messages").Job
		call := func(tool string) error {
			_, err := s.AdmitPAToolCall(context.Background(), ref(j), jobs.ToolCallRequest{
				Now: f.now, Tool: tool, MaxToolCalls: 8, Gate: okGate,
			})
			return err
		}
		if err := call("alice/alice_control_room"); !errors.Is(err, jobs.ErrToolNotInSet) {
			t.Fatalf("tool outside the set: %v", err)
		}
		for i := range 8 {
			if err := call("tg/get_messages"); err != nil {
				t.Fatalf("call %d: %v", i+1, err)
			}
		}
		if err := call("tg/get_messages"); !errors.Is(err, jobs.ErrToolCap) {
			t.Fatalf("ninth call: %v", err)
		}
		var n int
		_ = s.DB.QueryRow(`SELECT tool_calls FROM pa_jobs WHERE id = $1`, j.ID).Scan(&n)
		if n != 8 {
			t.Fatalf("tool_calls = %d, want 8 (refused calls are not counted)", n)
		}
	})

	t.Run("turn cap and context cap", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		j := f.claim().Job
		turn := func(tokens int) error {
			_, err := s.AdmitPATurn(context.Background(), ref(j), jobs.TurnRequest{
				Now: f.now, ContextTokens: tokens, MaxContextTokens: 100, MaxTurns: 2, Gate: okGate,
			})
			return err
		}
		if err := turn(101); !errors.Is(err, jobs.ErrContextTooLarge) {
			t.Fatalf("context over the cap: %v", err)
		}
		if turn(100) != nil || turn(1) != nil {
			t.Fatal("turns within the cap refused")
		}
		if err := turn(1); !errors.Is(err, jobs.ErrToolCap) {
			t.Fatalf("third turn: %v", err)
		}
	})

	t.Run("a token for another attempt or digest is stale", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		j := f.claim().Job
		for _, bad := range []jobs.Ref{
			{Principal: paAlice, JobID: j.ID, Attempt: j.Attempts + 1, Digest: j.ContextDigest},
			{Principal: paAlice, JobID: j.ID, Attempt: j.Attempts, Digest: "00"},
		} {
			if _, err := s.RunningPAJob(context.Background(), bad, f.now, okGate); !errors.Is(err, jobs.ErrStale) {
				t.Fatalf("%+v: %v", bad, err)
			}
		}
		// Bob naming Alice's job: the lookup is under the principal.
		if _, err := s.RunningPAJob(context.Background(), jobs.Ref{Principal: paBob, JobID: j.ID, Attempt: 1, Digest: j.ContextDigest}, f.now, okGate); !errors.Is(err, jobs.ErrNotFound) {
			t.Fatalf("Bob reading Alice's job: %v", err)
		}
	})

	t.Run("an expired lease holds the reservation", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		j := f.claim().Job
		later := f.now.Add(6 * time.Minute)
		if _, err := s.RunningPAJob(context.Background(), ref(j), later, okGate); !errors.Is(err, jobs.ErrStale) {
			t.Fatalf("after the lease: %v", err)
		}
		notices, err := s.ExpirePAJobs(context.Background(), later)
		if err != nil {
			t.Fatal(err)
		}
		if len(notices) != 1 || notices[0].Principal != paAlice || notices[0].Kind != jobs.NoticeRunFailed {
			t.Fatalf("notices = %+v, want one run-failed notice for Alice", notices)
		}
		if again, _ := s.ExpirePAJobs(context.Background(), later); len(again) != 0 {
			t.Fatalf("a second expiry pass owes %+v", again)
		}
		if js, us := f.status(j.ID); js != "expired" || us != "held" {
			t.Fatalf("expired: job %s usage %s", js, us)
		}
	})

	t.Run("gate: gone cancels, a read error changes nothing", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		j := f.claim().Job
		broken := errors.New("consent read failed")
		_, err := s.AdmitPATurn(context.Background(), ref(j), jobs.TurnRequest{
			Now: f.now, MaxContextTokens: 10, MaxTurns: 9,
			Gate: func(context.Context, *sql.Tx, jobs.Job, time.Time) error { return broken },
		})
		if !errors.Is(err, broken) {
			t.Fatalf("read error: %v", err)
		}
		if js, us := f.status(j.ID); js != "claimed" || us != "reserved" {
			t.Fatalf("after a read error: job %s usage %s, want unchanged", js, us)
		}
		_, err = s.AdmitPATurn(context.Background(), ref(j), jobs.TurnRequest{
			Now: f.now, MaxContextTokens: 10, MaxTurns: 9,
			Gate: func(context.Context, *sql.Tx, jobs.Job, time.Time) error { return jobs.ErrGone },
		})
		if !errors.Is(err, jobs.ErrGone) {
			t.Fatalf("gone: %v", err)
		}
		if js, us := f.status(j.ID); js != "cancelled" || us != "held" {
			t.Fatalf("after gone: job %s usage %s", js, us)
		}
	})

	t.Run("claim gate gone cancels without a reservation", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		res, err := s.ClaimPAJob(context.Background(), jobs.ClaimRequest{
			Now: f.now, Lease: time.Minute, Budget: f.b, Build: paBuild(),
			Gate: func(context.Context, *sql.Tx, jobs.Job, time.Time) error { return jobs.ErrGone },
		})
		if err != nil || res.Outcome != jobs.ClaimCancelled {
			t.Fatalf("res=%+v err=%v", res, err)
		}
		if js, us := f.status(res.Job.ID); js != "cancelled" || us != "" {
			t.Fatalf("job %s usage %q", js, us)
		}
	})

	t.Run("forget cancels queued and running jobs", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		j := f.claim().Job
		f.enqueue(paAlice, "c1")
		tx, _ := s.DB.Begin()
		if err := s.ForgetPAConversations(context.Background(), tx, paAlice); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if js, us := f.status(j.ID); js != "cancelled" || us != "held" {
			t.Fatalf("running job after /forget: %s %s", js, us)
		}
		var live int
		_ = s.DB.QueryRow(`SELECT COUNT(*) FROM pa_jobs WHERE principal = $1 AND status IN ('pending','held','claimed')`, paAlice).Scan(&live)
		if live != 0 {
			t.Fatalf("%d live jobs after /forget", live)
		}
	})

	t.Run("/new cancels queued and running jobs at once", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		j := f.claim().Job
		f.enqueue(paAlice, "c1")
		tx, _ := s.DB.Begin()
		if err := s.ClosePAConversations(context.Background(), tx, paAlice, f.now); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if js, us := f.status(j.ID); js != "cancelled" || us != "held" {
			t.Fatalf("running job after /new: %s %s", js, us)
		}
		var live int
		_ = s.DB.QueryRow(`SELECT COUNT(*) FROM pa_jobs WHERE principal = $1 AND status IN ('pending','held','claimed')`, paAlice).Scan(&live)
		if live != 0 {
			t.Fatalf("%d live jobs after /new", live)
		}
	})

	t.Run("release backs off or cancels", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		j := f.claim().Job
		// A store fault on the fragment load: nothing counted, due again
		// after the first backoff step, so the job does not stay at the
		// head of the queue while its fault recurs.
		n, err := s.ReleasePAClaim(context.Background(), ref(j), jobs.ReleaseRetry, f.now)
		if err != nil || n != nil {
			t.Fatalf("retry: notice %+v err %v", n, err)
		}
		var failures int
		var retryAt int64
		_ = s.DB.QueryRow(`SELECT claim_failures, retry_at_ms FROM pa_jobs WHERE id = $1`, j.ID).Scan(&failures, &retryAt)
		if failures != 0 || retryAt != f.now.Add(jobs.ClaimBackoff(1)).UnixMilli() {
			t.Fatalf("a retry counted %d failures, retry at %d", failures, retryAt)
		}
		if again := f.claim(); again.Outcome != jobs.ClaimNone {
			t.Fatalf("a retried job claimed before its retry time: %+v", again)
		}
		f.now = f.now.Add(jobs.ClaimBackoff(1))
		j = f.claim().Job
		if j.ID == 0 {
			t.Fatal("a retried job was not due after the first backoff step")
		}
		n, err = s.ReleasePAClaim(context.Background(), ref(j), jobs.ReleaseBackoff, f.now)
		if err != nil || n != nil {
			t.Fatalf("requeue: notice %+v err %v", n, err)
		}
		if js, us := f.status(j.ID); js != "pending" || us != "" {
			t.Fatalf("requeued: %s %q", js, us)
		}
		// Backed off: not due at once, so it cannot stay the oldest due job.
		if r := f.claim(); r.Outcome != jobs.ClaimNone {
			t.Fatalf("requeued job claimed during its backoff: %+v", r)
		}
		f.now = f.now.Add(jobs.ClaimBackoff(1) + time.Second)
		j = f.claim().Job
		n, err = s.ReleasePAClaim(context.Background(), ref(j), jobs.ReleaseCancel, f.now)
		if err != nil || n == nil || n.Kind != jobs.NoticeRunFailed || n.Principal != paAlice {
			t.Fatalf("release for good: notice %+v err %v", n, err)
		}
		if js, _ := f.status(j.ID); js != "cancelled" {
			t.Fatalf("released for good: %s", js)
		}
	})

	// F1: one principal's unreadable state must not block the queue.
	t.Run("a failing job is backed off and the next principal claims", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1") // oldest
		f.now = f.now.Add(time.Millisecond)
		f.enqueue(paBob, "c2")
		broken := errors.New("alice's consent row does not read")
		gate := func(_ context.Context, _ *sql.Tx, j jobs.Job, _ time.Time) error {
			if j.Principal == paAlice {
				return broken
			}
			return nil
		}
		claim := func() jobs.ClaimResult {
			r, err := s.ClaimPAJob(context.Background(), jobs.ClaimRequest{
				Now: f.now, Lease: time.Hour, Budget: f.b, Gate: gate, Build: paBuild(),
			})
			if err != nil {
				t.Fatalf("claim: %v", err)
			}
			return r
		}
		r := claim()
		if r.Outcome != jobs.ClaimClaimed || r.Job.Principal != paBob {
			t.Fatalf("claim behind Alice's broken job = %+v", r)
		}
		var aliceID int64
		_ = s.DB.QueryRow(`SELECT id FROM pa_jobs WHERE principal = $1`, paAlice).Scan(&aliceID)
		if js, us := f.status(aliceID); js != "pending" || us != "" {
			t.Fatalf("Alice: %s %q", js, us)
		}
		// Each failure backs off further; the fifth cancels with a notice.
		for i := 2; i <= jobs.MaxClaimFailures; i++ {
			f.now = f.now.Add(jobs.ClaimBackoff(i-1) + time.Second)
			r = claim()
			if i < jobs.MaxClaimFailures {
				if len(r.Notices) != 0 {
					t.Fatalf("failure %d: notices %+v", i, r.Notices)
				}
				continue
			}
			if len(r.Notices) != 1 || r.Notices[0].Principal != paAlice || r.Notices[0].Kind != jobs.NoticeRunFailed {
				t.Fatalf("failure %d: notices %+v, want Alice told", i, r.Notices)
			}
		}
		if js, _ := f.status(aliceID); js != "cancelled" {
			t.Fatalf("Alice after %d failures: %s", jobs.MaxClaimFailures, js)
		}
	})

	t.Run("a backoff never shortens a budget hold", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		until := f.now.Add(48 * time.Hour)
		if _, err := s.DB.Exec(`UPDATE pa_jobs SET status = 'held', held_until_ms = $1 WHERE principal = $2`, until.UnixMilli(), paAlice); err != nil {
			t.Fatal(err)
		}
		// Picked early (no open conversation row), then the gate fails.
		_, err := s.ClaimPAJob(context.Background(), jobs.ClaimRequest{
			Now: f.now, Lease: time.Minute, Budget: f.b, Build: paBuild(),
			Gate: func(context.Context, *sql.Tx, jobs.Job, time.Time) error { return errors.New("unreadable") },
		})
		if err != nil {
			t.Fatal(err)
		}
		var held, retry int64
		_ = s.DB.QueryRow(`SELECT held_until_ms, retry_at_ms FROM pa_jobs WHERE principal = $1`, paAlice).Scan(&held, &retry)
		if held != until.UnixMilli() || retry <= f.now.UnixMilli() {
			t.Fatalf("held until %v retry %v, want the hold kept and a backoff set", time.UnixMilli(held).UTC(), retry)
		}
		// The backoff applies to the gone-conversation pick too: polls
		// during it do not count more failures.
		for range 3 {
			_, _ = s.ClaimPAJob(context.Background(), jobs.ClaimRequest{
				Now: f.now, Lease: time.Minute, Budget: f.b, Build: paBuild(),
				Gate: func(context.Context, *sql.Tx, jobs.Job, time.Time) error { return errors.New("unreadable") },
			})
		}
		var n int
		_ = s.DB.QueryRow(`SELECT claim_failures FROM pa_jobs WHERE principal = $1`, paAlice).Scan(&n)
		if n != 1 {
			t.Fatalf("claim_failures = %d after polls inside the backoff, want 1", n)
		}
	})

	// A store fault (nothing observed about the job) changes no state and
	// counts nothing, however long it lasts; only a row fault does.
	t.Run("store faults never count against a job", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		fault := fmt.Errorf("%w: %w: consent: driver: bad connection", jobs.ErrUnreadable, jobs.ErrStoreFault)
		for _, step := range []struct {
			name  string
			gate  jobs.Gate
			build jobs.Build
		}{
			{"gate", func(context.Context, *sql.Tx, jobs.Job, time.Time) error { return fault }, paBuild()},
			{"build", okGate, func(context.Context, *sql.Tx, jobs.Job, int64) ([]byte, string, []string, error) {
				return nil, "", nil, fault
			}},
		} {
			for range 10 {
				f.now = f.now.Add(10 * time.Minute)
				r, err := s.ClaimPAJob(context.Background(), jobs.ClaimRequest{
					Now: f.now, Lease: time.Minute, Budget: f.b, Gate: step.gate, Build: step.build,
				})
				if !errors.Is(err, jobs.ErrStoreFault) || len(r.Notices) != 0 {
					t.Fatalf("%s: claim = %+v err %v, want the store fault and no notice", step.name, r, err)
				}
			}
			var n int
			var retry int64
			var st string
			_ = s.DB.QueryRow(`SELECT status, claim_failures, retry_at_ms FROM pa_jobs WHERE principal = $1`, paAlice).Scan(&st, &n, &retry)
			if st != "pending" || n != 0 || retry != 0 {
				t.Fatalf("%s: after 10 faulted polls: %s failures %d retry %d", step.name, st, n, retry)
			}
			if rows, _ := s.PAUsageFor(context.Background(), paAlice); len(rows) != 0 {
				t.Fatalf("%s: a faulted claim left usage %+v", step.name, rows)
			}
		}
	})

	t.Run("a transient build error is backed off, not cancelled", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		flaky := func(context.Context, *sql.Tx, jobs.Job, int64) ([]byte, string, []string, error) {
			return nil, "", nil, errors.New("resolver timed out")
		}
		r, err := s.ClaimPAJob(context.Background(), jobs.ClaimRequest{
			Now: f.now, Lease: time.Minute, Budget: f.b, Gate: okGate, Build: flaky,
		})
		if err != nil || r.Outcome != jobs.ClaimNone || len(r.Notices) != 0 {
			t.Fatalf("claim = %+v err %v", r, err)
		}
		var st string
		var n int
		_ = s.DB.QueryRow(`SELECT status, claim_failures FROM pa_jobs WHERE principal = $1`, paAlice).Scan(&st, &n)
		if st != "pending" || n != 1 {
			t.Fatalf("after a transient build error: %s failures %d", st, n)
		}
		f.now = f.now.Add(jobs.ClaimBackoff(1) + time.Second)
		if c := f.claim(); c.Outcome != jobs.ClaimClaimed {
			t.Fatalf("retry after the backoff = %+v", c)
		}
	})

	t.Run("an unbuildable job is cancelled at once and the next is claimed", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		f.now = f.now.Add(time.Millisecond)
		f.enqueue(paBob, "c2")
		build := func(ctx context.Context, tx *sql.Tx, j jobs.Job, res int64) ([]byte, string, []string, error) {
			if j.Principal == paAlice {
				return nil, "", nil, fmt.Errorf("%w: write tool offered", jobs.ErrInvalid)
			}
			return paBuild()(ctx, tx, j, res)
		}
		r, err := s.ClaimPAJob(context.Background(), jobs.ClaimRequest{
			Now: f.now, Lease: time.Minute, Budget: f.b, Gate: okGate, Build: build,
		})
		if err != nil || r.Outcome != jobs.ClaimClaimed || r.Job.Principal != paBob {
			t.Fatalf("claim = %+v err %v", r, err)
		}
		if len(r.Notices) != 1 || r.Notices[0].Principal != paAlice {
			t.Fatalf("notices = %+v", r.Notices)
		}
		rows, _ := s.PAUsageFor(context.Background(), paAlice)
		if len(rows) != 0 {
			t.Fatalf("Alice's refused build left usage %+v", rows)
		}
	})

	t.Run("expired leases end before the claim picks", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		old := f.claim().Job
		f.enqueue(paAlice, "c1")
		f.now = f.now.Add(6 * time.Minute)
		r := f.claim()
		if r.Outcome != jobs.ClaimClaimed || r.Job.ID == old.ID {
			t.Fatalf("Alice's next job behind an expired lease = %+v", r)
		}
		if len(r.Notices) != 1 || r.Notices[0].JobID != old.ID {
			t.Fatalf("notices = %+v, want the expired job's", r.Notices)
		}
	})

	t.Run("principal month cap holds until the month ends", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.b.PrincipalDayUSD, f.b.PrincipalMonthUSD = 0.5, 0.5
		for range 2 {
			f.enqueue(paAlice, "c1")
			f.finish(f.claim().Job, -1)
		}
		f.enqueue(paAlice, "c1")
		r := f.claim()
		end := time.Date(f.now.Year(), f.now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
		if r.Outcome != jobs.ClaimHeld || r.Scope != jobs.ScopePrincipalMonth || !r.Job.HeldUntil.Equal(end) {
			t.Fatalf("month cap = %+v, want held until %v", r, end)
		}
	})

	t.Run("a tool call needs a live reservation", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		j := f.claim("tg/get_messages").Job
		if _, err := s.DB.Exec(`UPDATE pa_usage SET status = 'held' WHERE job_id = $1`, j.ID); err != nil {
			t.Fatal(err)
		}
		_, err := s.AdmitPAToolCall(context.Background(), ref(j), jobs.ToolCallRequest{
			Now: f.now, Tool: "tg/get_messages", MaxToolCalls: 8, Gate: okGate,
		})
		if !errors.Is(err, jobs.ErrBudget) {
			t.Fatalf("tool call without a live reservation: %v", err)
		}
	})

	// Owner decisions 2026-11-19 (2, 3): a run settles
	// max(turns x floor, min(reported, 4 x reservation, $1)); the raw
	// report is kept as reported_cost_usd.
	t.Run("settlement is bounded by 4x the reservation and floored per turn", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			perJob   float64
			reported float64
			turns    int
			want     float64
		}{
			{"below the reservation", 0.25, 0.07, 1, 0.07},
			{"between the reservation and 4x", 0.25, 0.6, 1, 0.6},
			{"exactly 4x", 0.25, 1.0, 1, 1.0},
			{"above 4x", 0.25, 1e9, 1, 1.0},
			{"above 4x of a small reservation", 0.1, 0.5, 1, 0.4},
			{"no absolute ceiling below 4x", 0.3, 1.1, 1, 1.1},
			{"no absolute ceiling at 4x", 0.5, 3, 1, 2.0},
			{"zero with three turns charges the floor", 0.25, 0, 3, 0.015},
			{"zero with no turn admitted charges one turn", 0.25, 0, 0, 0.005},
			{"a report above the floor is not raised", 0.25, 0.02, 3, 0.02},
			{"unreported settles at the reservation", 0.25, -1, 3, 0.25},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newPAFixture(t, s)
				f.b.PerJobUSD = tc.perJob
				f.enqueue(paAlice, "c1")
				j := f.claim().Job
				for range tc.turns {
					f.turn(j)
				}
				before := globalDayNow(t, s, f.now)
				f.finish(j, tc.reported)
				var cost float64
				var reported sql.NullFloat64
				if err := s.DB.QueryRow(`SELECT cost_usd, reported_cost_usd FROM pa_usage WHERE job_id = $1`, j.ID).Scan(&cost, &reported); err != nil {
					t.Fatal(err)
				}
				if math.Abs(cost-tc.want) > 1e-9 {
					t.Fatalf("settled %v, want %v", cost, tc.want)
				}
				if tc.reported >= 0 && (!reported.Valid || reported.Float64 != tc.reported) {
					t.Fatalf("reported_cost_usd = %+v, want the raw %v", reported, tc.reported)
				}
				if tc.reported < 0 && reported.Valid {
					t.Fatalf("an unreported cost stored as %v", reported.Float64)
				}
				// The global day shared with the managed runtime moves by
				// the settlement, not the reservation.
				if got := globalDayNow(t, s, f.now) - before; math.Abs(got-(tc.want-tc.perJob)) > 1e-6 {
					t.Fatalf("global day moved by %v at settlement, want %v", got, tc.want-tc.perJob)
				}
			})
		}
	})

	// Owner decision 2026-11-19 (3): runs that report $0 still spend the
	// floor, so they reach the principal's day cap and are held.
	t.Run("repeated zero-cost runs reach the day cap", func(t *testing.T) {
		f := newPAFixture(t, s)
		for i := range 200 {
			f.enqueue(paAlice, "c1")
			r := f.claim()
			if r.Outcome == jobs.ClaimHeld {
				if r.Scope != jobs.ScopePrincipalDay {
					t.Fatalf("held on %s, want the principal day", r.Scope)
				}
				// 3 turns x 0.005: held once less than one reservation is left.
				if want := int(math.Ceil((f.b.PrincipalDayUSD - f.b.PerJobUSD) / 0.015)); i != want {
					t.Fatalf("held after %d zero-cost runs, want %d", i, want)
				}
				return
			}
			if r.Outcome != jobs.ClaimClaimed {
				t.Fatalf("run %d: %+v", i, r)
			}
			for range 3 {
				f.turn(r.Job)
			}
			f.finish(r.Job, 0)
		}
		t.Fatal("200 zero-cost runs never reached the day cap")
	})

	// The floor counts the turns the server saw: /turn admissions, and at
	// least one per admitted tool call plus the answer. A worker that
	// skips /turn cannot deflate it.
	// Mutation: settle with j.Turns alone.
	t.Run("floor counts tool calls when /turn is skipped", func(t *testing.T) {
		for _, tc := range []struct {
			name         string
			turns, calls int
			want         float64
		}{
			{"eight calls, no turn", 0, 8, 9 * 0.005},
			{"more turns than calls", 6, 2, 6 * 0.005},
			{"fewer turns than calls", 2, 5, 6 * 0.005},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newPAFixture(t, s)
				f.enqueue(paAlice, "c1")
				j := f.claim("tg/get_messages").Job
				for range tc.turns {
					f.turn(j)
				}
				for range tc.calls {
					if _, err := s.AdmitPAToolCall(context.Background(), ref(j), jobs.ToolCallRequest{
						Now: f.now, Tool: "tg/get_messages", MaxToolCalls: 8, Gate: okGate,
					}); err != nil {
						t.Fatal(err)
					}
				}
				f.finish(j, 0)
				var cost float64
				if err := s.DB.QueryRow(`SELECT cost_usd FROM pa_usage WHERE job_id = $1`, j.ID).Scan(&cost); err != nil {
					t.Fatal(err)
				}
				if math.Abs(cost-tc.want) > 1e-9 {
					t.Fatalf("settled %v, want %v", cost, tc.want)
				}
			})
		}
	})

	// Past the cutoff the claim takes nothing, but a lease that lapsed is
	// still expired and its principal still told.
	// Mutation: return no notices from the cutoff branch.
	t.Run("cutoff keeps lease expiry notices", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		j := f.claim().Job
		f.now = j.LeaseUntil.Add(time.Second)
		f.b.ClaimNotAfter = f.now.Add(-time.Minute)
		r := f.claim()
		if r.Outcome != jobs.ClaimNone || len(r.Notices) != 1 || r.Notices[0].JobID != j.ID || r.Notices[0].Principal != paAlice {
			t.Fatalf("claim past the cutoff with a lapsed lease = %+v, want ClaimNone and the expiry notice", r)
		}
		if js, _ := f.status(j.ID); js != "expired" {
			t.Fatalf("lapsed job is %s past the cutoff, want expired", js)
		}
	})

	t.Run("finish refuses a missing turn floor", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		j := f.claim().Job
		_, err := s.FinishPAJob(context.Background(), ref(j), jobs.FinishRequest{Now: f.now, CostUSD: 0, Gate: okGate})
		if !errors.Is(err, jobs.ErrInvalid) {
			t.Fatalf("finish without a floor: %v", err)
		}
		if js, us := f.status(j.ID); js != "claimed" || us != "reserved" {
			t.Fatalf("a refused finish changed the job: %s %s", js, us)
		}
	})

	// Owner decision 2026-11-19 (1): MANAGED_CLAIM_NOT_AFTER ends PA claims
	// as it ends managed ones: nothing is picked, reserved, held or backed
	// off at or after the instant.
	t.Run("claims end at ClaimNotAfter", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			offset time.Duration
			want   jobs.ClaimOutcome
		}{
			{"before", time.Second, jobs.ClaimClaimed},
			{"at", 0, jobs.ClaimNone},
			{"after", -time.Second, jobs.ClaimNone},
		} {
			t.Run(tc.name, func(t *testing.T) {
				f := newPAFixture(t, s)
				f.b.ClaimNotAfter = f.now.Add(tc.offset)
				f.enqueue(paAlice, "c1")
				r := f.claim()
				if r.Outcome != tc.want {
					t.Fatalf("claim = %+v, want %v", r, tc.want)
				}
				var reserved, failures, retry int
				_ = s.DB.QueryRow(`SELECT COUNT(*) FROM pa_usage WHERE principal = $1`, paAlice).Scan(&reserved)
				_ = s.DB.QueryRow(`SELECT COALESCE(SUM(claim_failures), 0), COALESCE(SUM(retry_at_ms), 0) FROM pa_jobs WHERE principal = $1`, paAlice).Scan(&failures, &retry)
				if tc.want == jobs.ClaimNone {
					if reserved != 0 || failures != 0 || retry != 0 {
						t.Fatalf("past the cutoff: %d reservations, %d failures, retry %d", reserved, failures, retry)
					}
					if js, _ := f.status(firstPAJob(t, s, paAlice)); js != "pending" {
						t.Fatalf("past the cutoff the job is %s, want pending", js)
					}
				}
			})
		}
	})

	t.Run("rate window", func(t *testing.T) {
		f := newPAFixture(t, s)
		admit := func(now time.Time) jobs.RateDecision {
			tx, _ := s.DB.Begin()
			defer func() { _ = tx.Rollback() }()
			d, err := s.AdmitPAMessage(context.Background(), tx, paAlice, now, 3, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			return d
		}
		for i := range 3 {
			if d := admit(f.now); !d.Allowed || d.First != (i == 0) {
				t.Fatalf("message %d = %+v, want allowed, first only for the first", i+1, d)
			}
		}
		if d := admit(f.now); d.Allowed || !d.Notify {
			t.Fatalf("fourth = %+v, want refused with a notice", d)
		}
		if d := admit(f.now); d.Allowed || d.Notify {
			t.Fatalf("fifth = %+v, want refused silently", d)
		}
		if d := admit(f.now.Add(time.Hour)); !d.Allowed || !d.First {
			t.Fatalf("new window = %+v, want allowed and first", d)
		}
	})

	t.Run("update failures are counted and acknowledged", func(t *testing.T) {
		id := time.Now().UnixNano()
		for want := 1; want <= 3; want++ {
			n, err := s.RecordPAUpdateFailure(context.Background(), id)
			if err != nil || n != want {
				t.Fatalf("n=%d err=%v, want %d", n, err, want)
			}
		}
		if err := s.AckFailedPAUpdate(context.Background(), id, "handler_error"); err != nil {
			t.Fatal(err)
		}
		ran, err := s.AcceptPAUpdate(context.Background(), id, func(context.Context, *sql.Tx) error { return nil })
		if err != nil || ran {
			t.Fatalf("an acknowledged update ran again: ran=%v err=%v", ran, err)
		}
		if reason, err := s.PAUpdateHandlerError(context.Background(), id); err != nil || reason != "handler_error" {
			t.Fatalf("reason=%q err=%v", reason, err)
		}
	})
}

// paConcurrentGlobal: two claims racing for the last room in the global
// window; the managed budget lock lets exactly one reserve.
func paConcurrentGlobal(t *testing.T, s *Store) {
	f := newPAFixture(t, s)
	f.enqueue(paAlice, "c1")
	f.enqueue(paBob, "c2")
	f.b.GlobalDayUSD = globalDayNow(t, s, f.now) + 0.3
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		got []jobs.ClaimOutcome
	)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := s.ClaimPAJob(context.Background(), jobs.ClaimRequest{
				Now: f.now, Lease: time.Minute, Budget: f.b, Gate: okGate, Build: paBuild(),
			})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			got = append(got, r.Outcome)
			mu.Unlock()
		}()
	}
	wg.Wait()
	claimed := 0
	for _, o := range got {
		if o == jobs.ClaimClaimed {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("outcomes %v: %d claims reserved in a window with room for one", got, claimed)
	}
}

// TestPAJobs_LedgerReadErrorFailsClosed: an unreadable ledger, managed or
// PA, is not zero spend. The claim errors, the job stays pending, nothing is
// reserved. SQLite only: it breaks the schema.
func TestPAJobs_LedgerReadErrorFailsClosed(t *testing.T) {
	for _, table := range []string{"agent_usage", "pa_usage"} {
		t.Run(table, func(t *testing.T) {
			s := newTestStore(t)
			f := newPAFixture(t, s)
			f.enqueue(paAlice, "c1")
			if _, err := s.DB.Exec(`ALTER TABLE ` + table + ` RENAME TO gone_` + table); err != nil {
				t.Fatal(err)
			}
			res, err := s.ClaimPAJob(context.Background(), jobs.ClaimRequest{
				Now: f.now, Lease: time.Minute, Budget: f.b, Gate: okGate, Build: paBuild(),
			})
			if err == nil {
				t.Fatalf("claim over an unreadable %s: %+v", table, res)
			}
			if table == "agent_usage" && !errors.Is(err, jobs.ErrUnreadable) {
				t.Fatalf("budget read error not marked unreadable: %v", err)
			}
			var st string
			_ = s.DB.QueryRow(`SELECT status FROM pa_jobs WHERE principal = $1`, paAlice).Scan(&st)
			if st != "pending" {
				t.Fatalf("job %s, want pending", st)
			}
			// The managed claim path reads the same global sum: it fails too.
			tx, _ := s.DB.Begin()
			defer func() { _ = tx.Rollback() }()
			if _, _, err := usageSums(context.Background(), tx, f.now.Add(-time.Hour), 0); err == nil {
				t.Fatal("global window read an unreadable ledger as zero")
			}
		})
	}
}

// TestPAJobs_ManagedCandidatesSeePASpend: the managed runtime's candidate
// filter reads pa_usage in the shared global day, so PA spend stops a
// managed claim it leaves no room for.
func TestPAJobs_ManagedCandidatesSeePASpend(t *testing.T) {
	ctx := context.Background()
	s := withBudget(newTestStoreCrypted(t), 0.5, 5, 15, 1.0)
	uid := seedManagedAccount(t, s, "pa-glob", RuntimeManaged, 1)
	if _, err := s.DB.ExecContext(ctx, `UPDATE users SET telegram_login_id = 9811 WHERE id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ListManagedClaimCandidates(ctx, budgetNow, 5, nil, 10); err != nil || len(got) != 1 {
		t.Fatalf("before PA spend: %+v err %v", got, err)
	}
	f := &paFixture{t: t, s: s, now: budgetNow, b: jobs.Budget{PerJobUSD: 0.6, PrincipalDayUSD: 2, PrincipalMonthUSD: 20, GlobalDayUSD: 1.0, MinTurnUSD: 0.005}}
	paReset(t, s)
	f.enqueue(paAlice, "c1")
	if r := f.claim(); r.Outcome != jobs.ClaimClaimed {
		t.Fatalf("PA claim = %+v", r)
	}
	if got, err := s.ListManagedClaimCandidates(ctx, budgetNow, 5, nil, 10); err != nil || len(got) != 0 {
		t.Fatalf("after 0.6 of PA spend in a 1.0 window: %+v err %v, want none", got, err)
	}
	if got := claimOne(t, s, uid); len(got) != 0 {
		t.Fatalf("managed claim took %d jobs past the shared window", len(got))
	}
}

// TestPAJobsPostgresSharesManagedBudgetLock: a PA claim waits for the
// managed budget lock, so spend committed under it (by a managed claim) is
// seen before the PA claim reserves.
func TestPAJobsPostgresSharesManagedBudgetLock(t *testing.T) {
	ctx := context.Background()
	s := newFreshSchemaPostgresStore(t)
	f := newPAFixture(t, s)
	f.b.GlobalDayUSD = globalDayNow(t, s, f.now) + 0.3 // room for one 0.25 job
	f.enqueue(paAlice, "c1")

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, managedBudgetLockKey); err != nil {
		t.Fatal(err)
	}
	done := make(chan jobs.ClaimResult, 1)
	errc := make(chan error, 1)
	go func() {
		r, err := s.ClaimPAJob(ctx, jobs.ClaimRequest{Now: f.now, Lease: time.Minute, Budget: f.b, Gate: okGate, Build: paBuild()})
		if err != nil {
			errc <- err
			return
		}
		done <- r
	}()
	select {
	case r := <-done:
		t.Fatalf("PA claim did not wait for the managed budget lock: %+v", r)
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(500 * time.Millisecond):
	}
	// Spend committed under the lock, as a managed claim would.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO pa_usage(job_id, attempt, principal, reserved_usd, cost_usd, status, created_at_ms, updated_at_ms)
		 VALUES(-1, 1, $1, 0.25, 0.25, 'settled', $2, $2)`, paBob, f.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.Outcome != jobs.ClaimHeld || r.Scope != jobs.ScopeGlobalDay {
			t.Fatalf("PA claim after the locked spend = %+v, want held on the global day", r)
		}
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(10 * time.Second):
		t.Fatal("PA claim never finished")
	}
}

// TestPAJobsPostgresFinishTakesManagedBudgetLock: a settlement may exceed
// its reservation (up to 4x), so it is written under the #1092 lock that
// every managed and PA claim decides the shared global day under.
// Mutation: FinishPAJob through beginRunning (no budget lock).
func TestPAJobsPostgresFinishTakesManagedBudgetLock(t *testing.T) {
	ctx := context.Background()
	s := newFreshSchemaPostgresStore(t)
	f := newPAFixture(t, s)
	f.enqueue(paAlice, "c1")
	j := f.claim().Job

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, managedBudgetLockKey); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := s.FinishPAJob(ctx, ref(j), jobs.FinishRequest{Now: f.now, CostUSD: 1, MinTurnUSD: f.b.MinTurnUSD, Gate: okGate})
		errc <- err
	}()
	select {
	case err := <-errc:
		t.Fatalf("finish did not wait for the managed budget lock: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("finish never completed")
	}
	if js, _ := f.status(j.ID); js != "done" {
		t.Fatalf("job %s after the finish", js)
	}
}

// TestPAJobs_FinishLocksBudgetBeforePrincipal: on every dialect the finish
// takes the managed budget lock, and before the principal lock, the order
// a claim takes them in (the other order could deadlock against a claim).
// The principal lock stamps locked_at_ms with the wall clock, so a budget
// lock taken first, and followed by a pause, is strictly earlier.
// Mutations: no budget lock in FinishPAJob; the budget lock after the job
// is loaded.
func TestPAJobs_FinishLocksBudgetBeforePrincipal(t *testing.T) {
	s := newTestStore(t)
	f := newPAFixture(t, s)
	f.enqueue(paAlice, "c1")
	j := f.claim().Job
	var budgetMS int64
	s.budgetLockHook = func(int64) {
		budgetMS = time.Now().UnixMilli()
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := s.FinishPAJob(context.Background(), ref(j), jobs.FinishRequest{Now: f.now, CostUSD: 0.1, MinTurnUSD: f.b.MinTurnUSD, Gate: okGate}); err != nil {
		t.Fatal(err)
	}
	var lockedMS int64
	if err := s.DB.QueryRow(`SELECT locked_at_ms FROM pa_principal_locks WHERE principal = $1`, paAlice).Scan(&lockedMS); err != nil {
		t.Fatal(err)
	}
	if budgetMS == 0 || lockedMS <= budgetMS {
		t.Fatalf("budget lock at %d, principal lock at %d: want the budget lock taken, and first", budgetMS, lockedMS)
	}
}

// TestPAJobs_BackoffWriteErrorFails: a backoff that cannot be written is
// an error (503), never a quiet ClaimNone and never a claim of the next
// job while the failed one stays due.
func TestPAJobs_BackoffWriteErrorFails(t *testing.T) {
	s := newTestStore(t)
	f := newPAFixture(t, s)
	f.enqueue(paAlice, "c1")
	f.now = f.now.Add(time.Millisecond)
	f.enqueue(paBob, "c2")
	if _, err := s.DB.Exec(`CREATE TRIGGER pa_no_backoff BEFORE UPDATE OF claim_failures ON pa_jobs
		BEGIN SELECT RAISE(ABORT, 'backoff write refused'); END`); err != nil {
		t.Fatal(err)
	}
	gate := func(_ context.Context, _ *sql.Tx, j jobs.Job, _ time.Time) error {
		if j.Principal == paAlice {
			return errors.New("alice's row")
		}
		return nil
	}
	r, err := s.ClaimPAJob(context.Background(), jobs.ClaimRequest{
		Now: f.now, Lease: time.Minute, Budget: f.b, Gate: gate, Build: paBuild(),
	})
	if err == nil || r.Outcome == jobs.ClaimClaimed {
		t.Fatalf("claim with a failed backoff write = %+v err %v", r, err)
	}
}

// TestPAConvo_StoreFaultVsRowFault: a failed read is a store fault; a row
// that was read and does not scan is the row's fault.
func TestPAConvo_StoreFaultVsRowFault(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.DB.Exec(`INSERT INTO pa_consents(principal, version, text_sha256, state, updated_at_ms)
		VALUES($1, 'v', 'h', 'accepted', 'not a number')`, paAlice); err != nil {
		t.Fatal(err)
	}
	read := func() error {
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		_, err = s.GetPAConsent(ctx, tx, paAlice)
		return err
	}
	if err := read(); !errors.Is(err, convo.ErrUnreadable) || errors.Is(err, convo.ErrStoreFault) {
		t.Fatalf("a row that does not scan: %v, want a row fault", err)
	}
	if _, err := s.DB.Exec(`ALTER TABLE pa_consents RENAME TO pa_consents_gone`); err != nil {
		t.Fatal(err)
	}
	if err := read(); !errors.Is(err, convo.ErrStoreFault) {
		t.Fatalf("a failed consent query: %v, want a store fault", err)
	}
	_ = s.DB.Close()
	if _, err := s.LoadPAFragments(ctx, paAlice, "c1", time.Now()); !errors.Is(err, convo.ErrStoreFault) {
		t.Fatalf("a load that cannot begin: %v, want a store fault", err)
	}
}

// paJobState is (claim_failures, retry_at_ms, status) of a job.
func paJobState(t *testing.T, s *Store, id int64) (int, int64, string) {
	t.Helper()
	var failures int
	var retry int64
	var status string
	if err := s.DB.QueryRow(`SELECT claim_failures, retry_at_ms, status FROM pa_jobs WHERE id = $1`, id).Scan(&failures, &retry, &status); err != nil {
		t.Fatal(err)
	}
	return failures, retry, status
}

// TestPAJobs_StoreFaultOfOneJobDoesNotHoldTheQueue: a store fault met
// while claiming Alice's job records nothing against it and the claim moves
// on to Bob; a fault met on every job is a store-wide fault and an error
// (503), never a quiet ClaimNone, again with nothing recorded.
// Mutations: return a post-pick store fault without the job (loop stops);
// return ClaimNone at the end of the loop although a fault was met.
func TestPAJobs_StoreFaultOfOneJobDoesNotHoldTheQueue(t *testing.T) {
	ctx := context.Background()
	faultFor := func(who ...int64) jobs.Gate {
		return func(_ context.Context, _ *sql.Tx, j jobs.Job, _ time.Time) error {
			if slices.Contains(who, j.Principal) {
				return fmt.Errorf("%w: %w: consent: timeout", jobs.ErrUnreadable, jobs.ErrStoreFault)
			}
			return nil
		}
	}
	claim := func(f *paFixture, gate jobs.Gate) (jobs.ClaimResult, error) {
		return f.s.ClaimPAJob(ctx, jobs.ClaimRequest{Now: f.now, Lease: time.Minute, Budget: f.b, Gate: gate, Build: paBuild()})
	}
	t.Run("one job", func(t *testing.T) {
		f := newPAFixture(t, newTestStore(t))
		f.enqueue(paAlice, "c1")
		f.now = f.now.Add(time.Millisecond)
		f.enqueue(paBob, "c2")
		alice := firstPAJob(t, f.s, paAlice)
		r, err := claim(f, faultFor(paAlice))
		if err != nil || r.Outcome != jobs.ClaimClaimed || r.Job.Principal != paBob {
			t.Fatalf("claim behind Alice's fault = %+v, %v; want Bob claimed", r, err)
		}
		// Only Alice is due now: her fault is the answer, not ClaimNone.
		if _, err := claim(f, faultFor(paAlice)); !errors.Is(err, jobs.ErrStoreFault) {
			t.Fatalf("claim with only Alice's fault left: %v, want a store fault", err)
		}
		if n, retry, st := paJobState(t, f.s, alice); n != 0 || retry != 0 || st != "pending" {
			t.Fatalf("Alice after store faults: %d failures, retry %d, %s; want untouched", n, retry, st)
		}
	})
	t.Run("store-wide", func(t *testing.T) {
		f := newPAFixture(t, newTestStore(t))
		f.enqueue(paAlice, "c1")
		f.enqueue(paBob, "c2")
		_, err := claim(f, faultFor(paAlice, paBob))
		if !errors.Is(err, jobs.ErrStoreFault) {
			t.Fatalf("a fault on every job: %v, want a store fault", err)
		}
		for _, p := range []int64{paAlice, paBob} {
			if n, retry, st := paJobState(t, f.s, firstPAJob(t, f.s, p)); n != 0 || retry != 0 || st != "pending" {
				t.Fatalf("principal %d after a store-wide fault: %d failures, retry %d, %s", p, n, retry, st)
			}
		}
		var usage int
		_ = f.s.DB.QueryRow(`SELECT COUNT(*) FROM pa_usage`).Scan(&usage)
		if usage != 0 {
			t.Fatalf("%d reservations after a store-wide fault", usage)
		}
	})
}

// TestPAJobs_StoreFaultOnEveryTry: more due jobs than maxClaimTries, each
// meeting a store fault. The loop runs out of tries, not out of jobs, and
// still answers with the fault, never ClaimNone, with nothing recorded.
// Mutation: drop the fault return after the loop.
func TestPAJobs_StoreFaultOnEveryTry(t *testing.T) {
	f := newPAFixture(t, newTestStore(t))
	for i := range maxClaimTries + 2 {
		f.enqueue(int64(9100+i), fmt.Sprintf("c%d", i))
	}
	gate := func(context.Context, *sql.Tx, jobs.Job, time.Time) error {
		return fmt.Errorf("%w: %w: consent: timeout", jobs.ErrUnreadable, jobs.ErrStoreFault)
	}
	r, err := f.s.ClaimPAJob(context.Background(), jobs.ClaimRequest{Now: f.now, Lease: time.Minute, Budget: f.b, Gate: gate, Build: paBuild()})
	if !errors.Is(err, jobs.ErrStoreFault) {
		t.Fatalf("every try faulted: %+v, %v; want a store fault", r, err)
	}
	var touched int
	_ = f.s.DB.QueryRow(`SELECT COUNT(*) FROM pa_jobs WHERE claim_failures <> 0 OR retry_at_ms <> 0 OR status <> 'pending'`).Scan(&touched)
	if touched != 0 {
		t.Fatalf("%d jobs changed by store faults", touched)
	}
}

// TestPAJobs_ReReadTellsStoreFaultFromRowFault (C14): the job re-read
// under the principal lock classifies a row that does not scan as this
// job's failure (counted, the queue moves on) and a failed query as a store
// fault (nothing counted, an error).
// Mutation: invert or drop the isRowFault branch in claimOnce.
func TestPAJobs_ReReadTellsStoreFaultFromRowFault(t *testing.T) {
	t.Run("row fault", func(t *testing.T) {
		f := newPAFixture(t, newTestStore(t))
		f.enqueue(paAlice, "c1")
		f.now = f.now.Add(time.Millisecond)
		f.enqueue(paBob, "c2")
		alice := firstPAJob(t, f.s, paAlice)
		// SQLite keeps the text; only the full re-read scans turns.
		if _, err := f.s.DB.Exec(`UPDATE pa_jobs SET turns = 'x' WHERE id = $1`, alice); err != nil {
			t.Fatal(err)
		}
		if r := f.claim(); r.Outcome != jobs.ClaimClaimed || r.Job.Principal != paBob {
			t.Fatalf("claim behind Alice's broken row = %+v, want Bob", r)
		}
		if n, retry, _ := paJobState(t, f.s, alice); n != 1 || retry == 0 {
			t.Fatalf("Alice's broken row: %d failures, retry %d; want it counted and backed off", n, retry)
		}
	})
	t.Run("store fault", func(t *testing.T) {
		f := newPAFixture(t, newTestStore(t))
		f.enqueue(paAlice, "c1")
		alice := firstPAJob(t, f.s, paAlice)
		// The pick does not read tool_set; the re-read does, and fails as
		// a query, not as a scan.
		if _, err := f.s.DB.Exec(`ALTER TABLE pa_jobs RENAME COLUMN tool_set TO tool_set_gone`); err != nil {
			t.Fatal(err)
		}
		_, err := f.s.ClaimPAJob(context.Background(), jobs.ClaimRequest{Now: f.now, Lease: time.Minute, Budget: f.b, Gate: okGate, Build: paBuild()})
		if !errors.Is(err, jobs.ErrStoreFault) {
			t.Fatalf("a failed re-read: %v, want a store fault", err)
		}
		if n, retry, st := paJobState(t, f.s, alice); n != 0 || retry != 0 || st != "pending" {
			t.Fatalf("Alice after a failed re-read: %d failures, retry %d, %s; want untouched", n, retry, st)
		}
	})
}

// TestPAConversationOpen_StoreFault (C15): a conversation check that cannot
// read is a store fault, which a claim does not count, never ErrGone (that
// would cancel the job) and never a bare unreadable (that would back it
// off).
// Mutation: jobsUnreadable for jobsStoreFault in PAConversationOpen.
func TestPAConversationOpen_StoreFault(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.DB.Exec(`ALTER TABLE pa_conversations RENAME TO pa_conversations_gone`); err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	err = s.PAConversationOpen(ctx, tx, paAlice, "c1", time.Now())
	if !errors.Is(err, jobs.ErrStoreFault) || errors.Is(err, jobs.ErrGone) {
		t.Fatalf("a failed conversation read: %v, want a store fault", err)
	}
}

// TestLoadPAFragments_ScanErrorIsRowFault (C19): a fragment row that does
// not scan is that conversation's broken state (the run is cancelled), not
// a store fault (which would retry it forever).
// Mutation: storeFault for rowRead at the fragment scan.
func TestLoadPAFragments_ScanErrorIsRowFault(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now()
	if _, err := s.DB.Exec(`INSERT INTO pa_conversations(id, principal, created_at_ms, expires_at_ms) VALUES('c1', $1, $2, $3)`,
		paAlice, now.UnixMilli(), now.Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO pa_fragments(conversation_id, seq, principal, kind, sealed, created_at_ms)
		VALUES('c1', 1, $1, 'user', x'00', 'not a number')`, paAlice); err != nil {
		t.Fatal(err)
	}
	_, err := s.LoadPAFragments(ctx, paAlice, "c1", now)
	if !errors.Is(err, convo.ErrUnreadable) || errors.Is(err, convo.ErrStoreFault) {
		t.Fatalf("a fragment row that does not scan: %v, want a row fault", err)
	}
}
