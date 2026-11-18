package db

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"
)

// TestPAUpdates_Dedup is the storage half of S1-B2: a second delivery of the
// same update_id does not run fn again, and a failed fn leaves the update
// retryable. Both dialects, because ON CONFLICT and RowsAffected differ.
func TestPAUpdates_Dedup(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		assertPAUpdateDedup(t, newTestStore(t))
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		s := newPostgresTestStore(t, dsn)
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_updates`) })
		assertPAUpdateDedup(t, s)
	})
}

func assertPAUpdateDedup(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	runs := 0
	fn := func(context.Context, *sql.Tx) error { runs++; return nil }

	ok, err := s.AcceptPAUpdate(ctx, 501, fn)
	if err != nil || !ok || runs != 1 {
		t.Fatalf("first delivery: ok=%v err=%v runs=%d, want true nil 1", ok, err, runs)
	}
	ok, err = s.AcceptPAUpdate(ctx, 501, fn)
	if err != nil || ok || runs != 1 {
		t.Fatalf("duplicate delivery: ok=%v err=%v runs=%d, want false nil 1", ok, err, runs)
	}

	// A failing fn rolls the row back: the retry is processed, not dropped.
	boom := errors.New("enqueue failed")
	ok, err = s.AcceptPAUpdate(ctx, 502, func(context.Context, *sql.Tx) error { return boom })
	if !errors.Is(err, boom) || ok {
		t.Fatalf("failing fn: ok=%v err=%v, want false and the fn error", ok, err)
	}
	ok, err = s.AcceptPAUpdate(ctx, 502, fn)
	if err != nil || !ok || runs != 2 {
		t.Fatalf("retry after failure: ok=%v err=%v runs=%d, want true nil 2", ok, err, runs)
	}
}
