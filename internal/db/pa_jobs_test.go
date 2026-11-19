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
	"sync"
	"testing"
	"time"

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
	if _, err := f.s.FinishPAJob(context.Background(), ref(j), jobs.FinishRequest{Now: f.now, CostUSD: cost, Gate: okGate}); err != nil {
		f.t.Fatal(err)
	}
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
		PerJobUSD: 0.25, PrincipalDayUSD: 2, PrincipalMonthUSD: 20, GlobalDayUSD: 1e6,
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
		n, err := s.ReleasePAClaim(context.Background(), ref(j), true, f.now)
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
		n, err = s.ReleasePAClaim(context.Background(), ref(j), false, f.now)
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
		var held int64
		_ = s.DB.QueryRow(`SELECT held_until_ms FROM pa_jobs WHERE principal = $1`, paAlice).Scan(&held)
		if held != until.UnixMilli() {
			t.Fatalf("held until %v, want the hold's %v kept", time.UnixMilli(held).UTC(), until)
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

	t.Run("a reported cost settles at most the reservation", func(t *testing.T) {
		f := newPAFixture(t, s)
		f.enqueue(paAlice, "c1")
		j := f.claim().Job
		f.finish(j, 1e9)
		var cost, reported float64
		if err := s.DB.QueryRow(`SELECT cost_usd, reported_cost_usd FROM pa_usage WHERE job_id = $1`, j.ID).Scan(&cost, &reported); err != nil {
			t.Fatal(err)
		}
		if cost != 0.25 || reported != 1e9 {
			t.Fatalf("cost %v reported %v, want 0.25 and the report kept", cost, reported)
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
			if d := admit(f.now); !d.Allowed {
				t.Fatalf("message %d refused", i+1)
			}
		}
		if d := admit(f.now); d.Allowed || !d.Notify {
			t.Fatalf("fourth = %+v, want refused with a notice", d)
		}
		if d := admit(f.now); d.Allowed || d.Notify {
			t.Fatalf("fifth = %+v, want refused silently", d)
		}
		if d := admit(f.now.Add(time.Hour)); !d.Allowed {
			t.Fatal("new window refused")
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
	f := &paFixture{t: t, s: s, now: budgetNow, b: jobs.Budget{PerJobUSD: 0.6, PrincipalDayUSD: 2, PrincipalMonthUSD: 20, GlobalDayUSD: 1.0}}
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
