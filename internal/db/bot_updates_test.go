package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
)

// chat returns a valid chat id.
func chat(id int64) sql.NullInt64 { return sql.NullInt64{Int64: id, Valid: true} }

// TestBotUpdates_AcceptanceIsIdempotent is the guarantee the whole receiver
// rests on: the second acceptance of an update_id reports false, so the caller
// knows not to dispatch it. Both dialects, because ON CONFLICT DO NOTHING and
// RowsAffected are exactly the kind of thing that differs between them.
func TestBotUpdates_AcceptanceIsIdempotent(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		assertAcceptanceIdempotent(t, newTestStore(t))
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		s := newPostgresTestStore(t, dsn)
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM bot_updates`) })
		assertAcceptanceIdempotent(t, s)
	})
}

func assertAcceptanceIdempotent(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()

	first, err := s.AcceptUpdate(ctx, 1, KindMessage, chat(42))
	if err != nil {
		t.Fatalf("first accept: %v", err)
	}
	if !first {
		t.Fatal("first acceptance reported false; the update would never be dispatched")
	}

	second, err := s.AcceptUpdate(ctx, 1, KindMessage, chat(42))
	if err != nil {
		t.Fatalf("second accept: %v", err)
	}
	if second {
		t.Error("second acceptance reported true; a redelivery would be dispatched twice")
	}

	var n int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM bot_updates WHERE update_id = $1`, 1).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}
}

// TestBotUpdates_AcceptanceNeverOverwritesAnExistingRow: a redelivery must not
// resurrect work. If the second accept were an upsert it would clear
// processed_at and the update would be dispatched all over again.
func TestBotUpdates_AcceptanceNeverOverwritesAnExistingRow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.AcceptUpdate(ctx, 5, KindMessage, chat(42)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := s.DispatchOnce(ctx, 5, func(context.Context, *sql.Tx) (string, error) {
		return OutcomeHandled, nil
	}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	// The redelivery.
	accepted, err := s.AcceptUpdate(ctx, 5, KindMessage, chat(42))
	if err != nil {
		t.Fatalf("re-accept: %v", err)
	}
	if accepted {
		t.Error("redelivery was accepted again")
	}

	pending, err := s.ListPendingUpdates(ctx, 0, 10)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("pending = %+v after a redelivery of a processed update; the row was reset", pending)
	}
}

// TestBotUpdates_NextOffsetTracksDurableStateOnly is the acknowledgement rule.
func TestBotUpdates_NextOffsetTracksDurableStateOnly(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	got, err := s.NextOffset(ctx)
	if err != nil {
		t.Fatalf("empty offset: %v", err)
	}
	if got != 0 {
		t.Errorf("offset on an empty table = %d, want 0", got)
	}

	for _, id := range []int64{10, 11, 9} {
		if _, err := s.AcceptUpdate(ctx, id, KindMessage, chat(42)); err != nil {
			t.Fatalf("accept %d: %v", id, err)
		}
	}
	got, err = s.NextOffset(ctx)
	if err != nil {
		t.Fatalf("offset: %v", err)
	}
	if got != 12 {
		t.Errorf("offset = %d, want 12 (max update_id + 1) even though 9 arrived last", got)
	}
}

// TestBotUpdates_DispatchOnceIsAtomicWithTheHandler is the crash-seam proof: a
// handler error must roll back the claim AND anything the handler wrote, so the
// update is retried rather than half-applied.
func TestBotUpdates_DispatchOnceIsAtomicWithTheHandler(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.AcceptUpdate(ctx, 20, KindMessage, chat(42)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	boom := errors.New("handler exploded")
	err := s.DispatchOnce(ctx, 20, func(ctx context.Context, tx *sql.Tx) (string, error) {
		// A write the handler makes through the supplied tx.
		if _, werr := tx.ExecContext(ctx,
			`UPDATE bot_updates SET outcome = 'written-by-handler' WHERE update_id = $1`, 20); werr != nil {
			return "", werr
		}
		return "", boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("DispatchOnce error = %v, want the handler's error", err)
	}

	var (
		outcome   string
		processed sql.NullTime
		claimed   sql.NullTime
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT outcome, processed_at, claimed_at FROM bot_updates WHERE update_id = $1`, 20,
	).Scan(&outcome, &processed, &claimed); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if outcome == "written-by-handler" {
		t.Error("the handler's write survived its own failure; the transaction did not roll back")
	}
	if processed.Valid {
		t.Error("update marked processed despite the handler failing")
	}
	if claimed.Valid {
		t.Error("claim survived the rollback; the update looks in-flight forever")
	}

	// Still retriable.
	pending, err := s.ListPendingUpdates(ctx, 0, 10)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	if len(pending) != 1 || pending[0].UpdateID != 20 {
		t.Fatalf("pending = %+v, want update 20 awaiting retry", pending)
	}
}

// TestBotUpdates_DispatchOnceRefusesASecondClaim: whichever caller gets there
// first wins, and the loser is told rather than running the handler again.
func TestBotUpdates_DispatchOnceRefusesASecondClaim(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.AcceptUpdate(ctx, 30, KindCallbackQuery, chat(42)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	var calls int
	run := func() error {
		return s.DispatchOnce(ctx, 30, func(context.Context, *sql.Tx) (string, error) {
			calls++
			return OutcomeHandled, nil
		})
	}
	if err := run(); err != nil {
		t.Fatalf("first dispatch: %v", err)
	}
	err := run()
	if !errors.Is(err, ErrUpdateNotClaimable) {
		t.Fatalf("second dispatch error = %v, want ErrUpdateNotClaimable", err)
	}
	if calls != 1 {
		t.Errorf("handler ran %d times, want 1", calls)
	}
}

// TestBotUpdates_ListPendingIsOldestFirst: recovery must replay in arrival
// order, or a later update could be handled before an earlier one.
func TestBotUpdates_ListPendingIsOldestFirst(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	for _, id := range []int64{3, 1, 2} {
		if _, err := s.AcceptUpdate(ctx, id, KindMessage, chat(42)); err != nil {
			t.Fatalf("accept %d: %v", id, err)
		}
	}
	pending, err := s.ListPendingUpdates(ctx, 0, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var got []int64
	for _, p := range pending {
		got = append(got, p.UpdateID)
	}
	if fmt.Sprint(got) != fmt.Sprint([]int64{1, 2, 3}) {
		t.Errorf("order = %v, want [1 2 3]", got)
	}
}

// TestBotUpdates_MarkUpdateFailedIsTerminalAndDoesNotResurrect: a permanently
// broken update must stop blocking the sweep, and marking an already-processed
// one must not overwrite its real outcome.
func TestBotUpdates_MarkUpdateFailedIsTerminalAndDoesNotResurrect(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if _, err := s.AcceptUpdate(ctx, 40, KindMessage, chat(42)); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := s.MarkUpdateFailed(ctx, 40); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	pending, err := s.ListPendingUpdates(ctx, 0, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pending) != 0 {
		t.Errorf("pending = %+v, want empty after a terminal failure", pending)
	}

	// A successfully handled update keeps its outcome.
	if _, err := s.AcceptUpdate(ctx, 41, KindMessage, chat(42)); err != nil {
		t.Fatalf("accept 41: %v", err)
	}
	if err := s.DispatchOnce(ctx, 41, func(context.Context, *sql.Tx) (string, error) {
		return OutcomeUnknownChat, nil
	}); err != nil {
		t.Fatalf("dispatch 41: %v", err)
	}
	if err := s.MarkUpdateFailed(ctx, 41); err != nil {
		t.Fatalf("mark 41: %v", err)
	}
	var outcome string
	if err := s.DB.QueryRowContext(ctx, `SELECT outcome FROM bot_updates WHERE update_id = $1`, 41).Scan(&outcome); err != nil {
		t.Fatalf("read 41: %v", err)
	}
	if outcome != OutcomeUnknownChat {
		t.Errorf("outcome = %q, want %q -- a processed row must not be rewritten", outcome, OutcomeUnknownChat)
	}
}
