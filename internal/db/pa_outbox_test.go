package db

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// The PA outbox store (issue #1313 slice d2) on both dialects.

const paCarol int64 = 557

func TestPAOutbox_SQLite(t *testing.T) {
	runPAOutboxSuite(t, newTestStore(t))
}

func TestPAOutboxPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	runPAOutboxSuite(t, s)
	t.Run("concurrent claims take a row once", func(t *testing.T) { paOutboxConcurrentClaim(t, s) })
}

func paOutboxReset(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.DB.Exec(`DELETE FROM pa_outbox WHERE principal IN ($1, $2, $3)`, paAlice, paBob, paCarol); err != nil {
		t.Fatal(err)
	}
}

// outboxEnqueue writes items in one transaction, committed or not.
func outboxEnqueue(t *testing.T, s *Store, now time.Time, commit bool, items ...jobs.OutboxItem) {
	t.Helper()
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, it := range items {
		if err := s.EnqueuePAOutbox(context.Background(), tx, it, now); err != nil {
			t.Fatal(err)
		}
	}
	if commit {
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
}

func outboxClaim(t *testing.T, s *Store, now time.Time, principal int64) jobs.OutboxClaimResult {
	t.Helper()
	res, err := s.ClaimPAOutbox(context.Background(), jobs.OutboxClaimRequest{
		Now: now, Lease: jobs.OutboxLease, Principal: principal, Limit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func outboxRows(t *testing.T, s *Store, principal int64) []jobs.OutboxItem {
	t.Helper()
	rows, err := s.PAOutboxRows(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func notice(p, job int64, k jobs.OutboxKind) jobs.OutboxItem {
	return jobs.OutboxItem{Principal: p, JobID: job, Kind: k}
}

// paJobID is a job id no other suite uses on a shared Postgres.
func paJobID(t *testing.T, n int64) int64 {
	t.Helper()
	return time.Now().UnixNano()/1000 + n
}

func runPAOutboxSuite(t *testing.T, s *Store) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("enqueue is once per job and kind, and only with its transaction", func(t *testing.T) {
		paOutboxReset(t, s)
		j := paJobID(t, 1)
		outboxEnqueue(t, s, now, false, notice(paAlice, j, jobs.OutboxRunFailed))
		if n := len(outboxRows(t, s, paAlice)); n != 0 {
			t.Fatalf("%d rows survived a rolled-back transaction", n)
		}
		outboxEnqueue(t, s, now, true, notice(paAlice, j, jobs.OutboxRunFailed), notice(paAlice, j, jobs.OutboxRunFailed))
		outboxEnqueue(t, s, now, true, notice(paAlice, j, jobs.OutboxRunFailed))
		rows := outboxRows(t, s, paAlice)
		if len(rows) != 1 || rows[0].Status != jobs.OutboxPending || rows[0].Attempts != 0 {
			t.Fatalf("rows = %+v, want one pending row", rows)
		}
	})

	t.Run("invalid items are refused", func(t *testing.T) {
		tx, err := s.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		for _, it := range []jobs.OutboxItem{
			{Principal: paAlice, JobID: 1, Kind: "other"},
			{Principal: 0, JobID: 1, Kind: jobs.OutboxRunFailed},
			{Principal: paAlice, JobID: 1, Kind: jobs.OutboxReply},
			{Principal: paAlice, JobID: 1, Kind: jobs.OutboxReply, ConversationID: "c", FragmentSeq: 0},
			{Principal: paAlice, JobID: 1, Kind: jobs.OutboxReply, FragmentSeq: 3},
			{Principal: paAlice, JobID: 1, Kind: jobs.OutboxRunFailed, ConversationID: "c", FragmentSeq: 1},
		} {
			if err := s.EnqueuePAOutbox(ctx, tx, it, now); !errors.Is(err, jobs.ErrInvalid) {
				t.Fatalf("%+v: err = %v, want ErrInvalid", it, err)
			}
		}
	})

	t.Run("claim, send-once and retry", func(t *testing.T) {
		paOutboxReset(t, s)
		j := paJobID(t, 2)
		outboxEnqueue(t, s, now, true, notice(paAlice, j, jobs.OutboxBudgetHold))
		res := outboxClaim(t, s, now, paAlice)
		if len(res.Items) != 1 || res.Items[0].Status != jobs.OutboxSending || res.Items[0].Attempts != 1 {
			t.Fatalf("claim = %+v", res)
		}
		it := res.Items[0]
		if again := outboxClaim(t, s, now, paAlice); len(again.Items) != 0 {
			t.Fatalf("a sending row was claimed twice: %+v", again)
		}
		// A failed send: due again later, not now.
		if err := s.CompletePAOutbox(ctx, it, jobs.OutboxCompletion{Now: now, Status: jobs.OutboxPending, RetryAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if again := outboxClaim(t, s, now, paAlice); len(again.Items) != 0 {
			t.Fatal("a retry was due before its time")
		}
		res = outboxClaim(t, s, now.Add(time.Minute), paAlice)
		if len(res.Items) != 1 || res.Items[0].Attempts != 2 {
			t.Fatalf("retry claim = %+v", res)
		}
		// A completion for the earlier attempt is stale.
		if err := s.CompletePAOutbox(ctx, it, jobs.OutboxCompletion{Now: now, Status: jobs.OutboxSent}); !errors.Is(err, jobs.ErrOutboxStale) {
			t.Fatalf("stale completion: %v", err)
		}
		if err := s.CompletePAOutbox(ctx, res.Items[0], jobs.OutboxCompletion{Now: now, Status: jobs.OutboxSent}); err != nil {
			t.Fatal(err)
		}
		if again := outboxClaim(t, s, now.Add(time.Hour), paAlice); len(again.Items) != 0 {
			t.Fatal("a sent row was claimed again")
		}
	})

	t.Run("a row that outlives its lease is unknown and never sent again", func(t *testing.T) {
		paOutboxReset(t, s)
		outboxEnqueue(t, s, now, true, notice(paAlice, paJobID(t, 3), jobs.OutboxRunFailed))
		it := outboxClaim(t, s, now, paAlice).Items[0]
		res := outboxClaim(t, s, now.Add(jobs.OutboxLease), paAlice)
		if res.Unknown != 1 || len(res.Items) != 0 {
			t.Fatalf("after the lease: %+v, want one unknown and nothing claimed", res)
		}
		if rows := outboxRows(t, s, paAlice); rows[0].Status != jobs.OutboxUnknown {
			t.Fatalf("status %s", rows[0].Status)
		}
		if err := s.CompletePAOutbox(ctx, it, jobs.OutboxCompletion{Now: now, Status: jobs.OutboxSent}); !errors.Is(err, jobs.ErrOutboxStale) {
			t.Fatalf("late completion: %v", err)
		}
		if again := outboxClaim(t, s, now.Add(time.Hour), paAlice); len(again.Items) != 0 || again.Unknown != 0 {
			t.Fatalf("an unknown row came back: %+v", again)
		}
	})

	t.Run("one row per principal at a time, in order", func(t *testing.T) {
		paOutboxReset(t, s)
		j := paJobID(t, 4)
		outboxEnqueue(t, s, now, true,
			notice(paAlice, j, jobs.OutboxBudgetHold), notice(paAlice, j, jobs.OutboxRequestDropped),
			notice(paBob, j+1, jobs.OutboxRunFailed))
		res := outboxClaim(t, s, now, 0)
		var mine []jobs.OutboxItem
		for _, it := range res.Items {
			if it.Principal == paAlice || it.Principal == paBob {
				mine = append(mine, it)
			}
		}
		if len(mine) != 2 || mine[0].Kind != jobs.OutboxBudgetHold || mine[1].Principal != paBob {
			t.Fatalf("claimed %+v, want Alice's first row and Bob's row", mine)
		}
		// Alice's first row failed and waits: her second waits behind it.
		if err := s.CompletePAOutbox(ctx, mine[0], jobs.OutboxCompletion{Now: now, Status: jobs.OutboxPending, RetryAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		if again := outboxClaim(t, s, now, paAlice); len(again.Items) != 0 {
			t.Fatalf("a later row overtook a failed one: %+v", again)
		}
		first := outboxClaim(t, s, now.Add(time.Minute), paAlice)
		if len(first.Items) != 1 || first.Items[0].Kind != jobs.OutboxBudgetHold {
			t.Fatalf("retry = %+v", first)
		}
		if err := s.CompletePAOutbox(ctx, first.Items[0], jobs.OutboxCompletion{Now: now, Status: jobs.OutboxFailed}); err != nil {
			t.Fatal(err)
		}
		next := outboxClaim(t, s, now.Add(time.Minute), paAlice)
		if len(next.Items) != 1 || next.Items[0].Kind != jobs.OutboxRequestDropped {
			t.Fatalf("after a failed row the next goes: %+v", next)
		}
	})

	t.Run("completion is validated", func(t *testing.T) {
		it := jobs.OutboxItem{ID: 1, Attempts: 1}
		for _, c := range []jobs.OutboxCompletion{
			{Now: now, Status: jobs.OutboxSending},
			{Now: now, Status: "other"},
			{Now: now, Status: jobs.OutboxPending},
			{Status: jobs.OutboxSent},
		} {
			if err := s.CompletePAOutbox(ctx, it, c); !errors.Is(err, jobs.ErrInvalid) {
				t.Fatalf("%+v: %v", c, err)
			}
		}
	})

	t.Run("the sweep keeps undelivered rows", func(t *testing.T) {
		paOutboxReset(t, s)
		j := paJobID(t, 5)
		old := now.Add(-72 * time.Hour)
		outboxEnqueue(t, s, old, true, notice(paCarol, j, jobs.OutboxRunFailed), notice(paCarol, j, jobs.OutboxBudgetHold),
			notice(paBob, j+1, jobs.OutboxRunFailed))
		// Bob's row is mid-send: claimed, never completed.
		if n := len(outboxClaim(t, s, old, paBob).Items); n != 1 {
			t.Fatalf("claimed %d of Bob's rows", n)
		}
		it := outboxClaim(t, s, old, paCarol).Items[0]
		if err := s.CompletePAOutbox(ctx, it, jobs.OutboxCompletion{Now: old, Status: jobs.OutboxSent}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SweepPAState(ctx, now, now.Add(-48*time.Hour)); err != nil {
			t.Fatal(err)
		}
		rows := outboxRows(t, s, paCarol)
		if len(rows) != 1 || rows[0].Status != jobs.OutboxPending {
			t.Fatalf("after the sweep: %+v, want only the pending row", rows)
		}
		if rows := outboxRows(t, s, paBob); len(rows) != 1 || rows[0].Status != jobs.OutboxSending {
			t.Fatalf("after the sweep: Bob %+v, want the sending row kept", rows)
		}
	})

	t.Run("delivered parts are recorded while sending, and only grow", func(t *testing.T) {
		paOutboxReset(t, s)
		outboxEnqueue(t, s, now, true, notice(paAlice, paJobID(t, 7), jobs.OutboxBudgetHold))
		it := outboxClaim(t, s, now, paAlice).Items[0]
		if err := s.RecordPAOutboxParts(ctx, it, 2, now); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordPAOutboxParts(ctx, it, 1, now); !errors.Is(err, jobs.ErrOutboxStale) {
			t.Fatalf("shrinking the count: %v, want ErrOutboxStale", err)
		}
		if err := s.RecordPAOutboxParts(ctx, it, 0, now); !errors.Is(err, jobs.ErrInvalid) {
			t.Fatalf("zero parts: %v, want ErrInvalid", err)
		}
		other := it
		other.Attempts++
		if err := s.RecordPAOutboxParts(ctx, other, 3, now); !errors.Is(err, jobs.ErrOutboxStale) {
			t.Fatalf("another attempt: %v, want ErrOutboxStale", err)
		}
		if err := s.CompletePAOutbox(ctx, it, jobs.OutboxCompletion{Now: now, Status: jobs.OutboxPending, RetryAt: now}); err != nil {
			t.Fatal(err)
		}
		again := outboxClaim(t, s, now, paAlice).Items
		if len(again) != 1 || again[0].SentParts != 2 || again[0].Attempts != 2 {
			t.Fatalf("retry claim = %+v, want 2 parts kept on attempt 2", again)
		}
		if err := s.RecordPAOutboxParts(ctx, it, 3, now); !errors.Is(err, jobs.ErrOutboxStale) {
			t.Fatalf("the old attempt after a new claim: %v, want ErrOutboxStale", err)
		}
	})

	t.Run("an unknown outcome is final", func(t *testing.T) {
		paOutboxReset(t, s)
		outboxEnqueue(t, s, now, true, notice(paAlice, paJobID(t, 8), jobs.OutboxBudgetHold))
		it := outboxClaim(t, s, now, paAlice).Items[0]
		if err := s.CompletePAOutbox(ctx, it, jobs.OutboxCompletion{Now: now, Status: jobs.OutboxUnknown}); err != nil {
			t.Fatal(err)
		}
		if again := outboxClaim(t, s, now.Add(24*time.Hour), paAlice); len(again.Items) != 0 {
			t.Fatalf("an unknown row was claimed again: %+v", again)
		}
	})

	t.Run("forget deletes pending notices only", func(t *testing.T) {
		paOutboxReset(t, s)
		j := paJobID(t, 9)
		outboxEnqueue(t, s, now, true, notice(paAlice, j, jobs.OutboxRunFailed), notice(paAlice, j, jobs.OutboxBudgetHold),
			jobs.OutboxItem{Principal: paAlice, JobID: j, Kind: jobs.OutboxReply, ConversationID: "c-forget", FragmentSeq: 2},
			notice(paBob, j+1, jobs.OutboxRunFailed))
		// Alice's oldest row is mid-send.
		sending := outboxClaim(t, s, now, paAlice).Items[0]
		tx, err := s.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ForgetPAConversations(ctx, tx, paAlice); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		rows := outboxRows(t, s, paAlice)
		if len(rows) != 2 || rows[0].ID != sending.ID || rows[1].Kind != jobs.OutboxReply {
			t.Fatalf("after forget: %+v, want the sending row and the pending reply", rows)
		}
		if n := len(outboxRows(t, s, paBob)); n != 1 {
			t.Fatalf("Bob has %d rows after Alice's forget", n)
		}
	})

	t.Run("every notice is written with its state change", func(t *testing.T) { paNoticesInOutbox(t, s) })
}

// paNoticesInOutbox: each store path that owes a principal a message writes
// it to the outbox in its own transaction.
func paNoticesInOutbox(t *testing.T, s *Store) {
	ctx := context.Background()
	kinds := func(p int64) []jobs.OutboxKind {
		var out []jobs.OutboxKind
		for _, r := range outboxRows(t, s, p) {
			out = append(out, r.Kind)
		}
		return out
	}
	t.Run("expired lease", func(t *testing.T) {
		f := newPAFixture(t, s)
		paOutboxReset(t, s)
		f.enqueue(paAlice, "c1")
		r := f.claim()
		f.now = f.now.Add(10 * time.Minute)
		if _, err := s.ExpirePAJobs(ctx, f.now); err != nil {
			t.Fatal(err)
		}
		if k := kinds(paAlice); len(k) != 1 || k[0] != jobs.OutboxRunFailed || outboxRows(t, s, paAlice)[0].JobID != r.Job.ID {
			t.Fatalf("outbox = %v", k)
		}
	})
	t.Run("budget hold, once", func(t *testing.T) {
		f := newPAFixture(t, s)
		paOutboxReset(t, s)
		f.b.PrincipalDayUSD, f.b.PerJobUSD = 0.25, 0.25
		f.enqueue(paAlice, "c1")
		f.finish(f.claim().Job, 0.25)
		f.enqueue(paAlice, "c1")
		if r := f.claim(); r.Outcome != jobs.ClaimHeld || !r.Notify {
			t.Fatalf("claim = %+v", r)
		}
		f.claim()
		if k := kinds(paAlice); len(k) != 1 || k[0] != jobs.OutboxBudgetHold {
			t.Fatalf("outbox = %v", k)
		}
	})
	t.Run("released with a notice", func(t *testing.T) {
		f := newPAFixture(t, s)
		paOutboxReset(t, s)
		f.enqueue(paAlice, "c1")
		r := f.claim()
		if _, err := s.ReleasePAClaim(ctx, ref(r.Job), jobs.ReleaseCancel, f.now); err != nil {
			t.Fatal(err)
		}
		if k := kinds(paAlice); len(k) != 1 || k[0] != jobs.OutboxRunFailed {
			t.Fatalf("outbox = %v", k)
		}
	})
	t.Run("released for a retry owes nothing", func(t *testing.T) {
		f := newPAFixture(t, s)
		paOutboxReset(t, s)
		f.enqueue(paAlice, "c1")
		r := f.claim()
		if _, err := s.ReleasePAClaim(ctx, ref(r.Job), jobs.ReleaseRetry, f.now); err != nil {
			t.Fatal(err)
		}
		if k := kinds(paAlice); len(k) != 0 {
			t.Fatalf("outbox = %v", k)
		}
	})
	t.Run("deterministic claim failure", func(t *testing.T) {
		f := newPAFixture(t, s)
		paOutboxReset(t, s)
		f.enqueue(paAlice, "c1")
		bad := func(context.Context, *sql.Tx, jobs.Job, int64) ([]byte, string, []string, error) {
			return nil, "", nil, jobs.ErrInvalid
		}
		if _, err := s.ClaimPAJob(ctx, jobs.ClaimRequest{Now: f.now, Lease: time.Minute, Budget: f.b, Gate: okGate, Build: bad}); err != nil {
			t.Fatal(err)
		}
		if k := kinds(paAlice); len(k) != 1 || k[0] != jobs.OutboxRunFailed {
			t.Fatalf("outbox = %v", k)
		}
	})
	gone := func(context.Context, *sql.Tx, jobs.Job, time.Time) error { return jobs.ErrConversationGone }
	t.Run("dropped at claim", func(t *testing.T) {
		f := newPAFixture(t, s)
		paOutboxReset(t, s)
		f.enqueue(paAlice, "c1")
		if _, err := s.ClaimPAJob(ctx, jobs.ClaimRequest{Now: f.now, Lease: time.Minute, Budget: f.b, Gate: gone, Build: paBuild()}); err != nil {
			t.Fatal(err)
		}
		if k := kinds(paAlice); len(k) != 1 || k[0] != jobs.OutboxRequestDropped {
			t.Fatalf("outbox = %v", k)
		}
	})
	t.Run("dropped mid-run", func(t *testing.T) {
		f := newPAFixture(t, s)
		paOutboxReset(t, s)
		f.enqueue(paAlice, "c1")
		r := f.claim()
		_, err := s.AdmitPATurn(ctx, ref(r.Job), jobs.TurnRequest{Now: f.now, ContextTokens: 1, MaxContextTokens: 10, MaxTurns: 9, Gate: gone})
		if !errors.Is(err, jobs.ErrConversationGone) {
			t.Fatal(err)
		}
		if k := kinds(paAlice); len(k) != 1 || k[0] != jobs.OutboxRequestDropped {
			t.Fatalf("outbox = %v", k)
		}
	})
	t.Run("withdrawn consent owes nothing", func(t *testing.T) {
		f := newPAFixture(t, s)
		paOutboxReset(t, s)
		f.enqueue(paAlice, "c1")
		withdrawn := func(context.Context, *sql.Tx, jobs.Job, time.Time) error { return jobs.ErrGone }
		if _, err := s.ClaimPAJob(ctx, jobs.ClaimRequest{Now: f.now, Lease: time.Minute, Budget: f.b, Gate: withdrawn, Build: paBuild()}); err != nil {
			t.Fatal(err)
		}
		if k := kinds(paAlice); len(k) != 0 {
			t.Fatalf("outbox = %v", k)
		}
	})
}

// paOutboxConcurrentClaim: deliverers racing for one row claim it once.
// paOutboxConcurrentClaim forces the race the conditional claim guards
// against: a second deliverer claims the row after the first one read it
// as due and before the first one claims it. Only one of them may get it.
func paOutboxConcurrentClaim(t *testing.T, s *Store) {
	paOutboxReset(t, s)
	now := time.Now().UTC()
	outboxEnqueue(t, s, now, true, notice(paCarol, paJobID(t, 6), jobs.OutboxRunFailed))
	req := jobs.OutboxClaimRequest{Now: now, Lease: jobs.OutboxLease, Principal: paCarol, Limit: 10}
	var inner jobs.OutboxClaimResult
	var innerErr error
	ran := false
	s.paOutboxAfterSelect = func() {
		if ran {
			return
		}
		ran = true
		inner, innerErr = s.ClaimPAOutbox(context.Background(), req)
	}
	t.Cleanup(func() { s.paOutboxAfterSelect = nil })
	outer, err := s.ClaimPAOutbox(context.Background(), req)
	if err != nil || innerErr != nil {
		t.Fatalf("claims failed: outer %v, inner %v", err, innerErr)
	}
	if !ran {
		t.Fatal("the interleave did not happen")
	}
	if len(inner.Items) != 1 || len(outer.Items) != 0 {
		t.Fatalf("inner claimed %d, outer %d: want the row claimed once, by the inner claim", len(inner.Items), len(outer.Items))
	}
	if rows := outboxRows(t, s, paCarol); len(rows) != 1 || rows[0].Attempts != 1 {
		t.Fatalf("rows = %+v, want one claim recorded", rows)
	}
}
