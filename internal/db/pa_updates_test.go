package db

import (
	"context"
	"database/sql"
	"errors"
	"math/rand/v2"
	"os"
	"sync"
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
		if _, err := s.DB.Exec(`DELETE FROM pa_updates WHERE update_id IN (501, 502)`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_updates WHERE update_id IN (501, 502)`) })
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

// TestPAUpdates_ConcurrentDuplicates: N concurrent deliveries of one
// update_id run fn at most once. On Postgres every call succeeds and exactly
// one runs. SQLite may answer a contended writer with SQLITE_BUSY, which the
// webhook turns into a 503 and a Telegram retry; it must never be a second
// run. So that "every call was BUSY" cannot pass vacuously, each failed call
// is then retried sequentially, the way Telegram would: after the retries
// exactly one run must exist, and one more delivery must be a duplicate.
func TestPAUpdates_ConcurrentDuplicates(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		s := newTestStore(t)
		const id = 601
		runs, errs := concurrentPAAccepts(t, s, id, 16)
		if runs > 1 {
			t.Fatalf("runs = %d, want at most 1", runs)
		}
		if runs == 0 && errs == 0 {
			t.Fatal("no run and no error: the update was swallowed")
		}
		for range errs {
			ok, err := s.AcceptPAUpdate(context.Background(), id, func(context.Context, *sql.Tx) error { return nil })
			if err != nil {
				t.Fatalf("sequential retry: %v", err)
			}
			if ok {
				runs++
			}
		}
		if runs != 1 {
			t.Fatalf("runs after retrying the failed deliveries = %d, want exactly 1", runs)
		}
		assertPADuplicate(t, s, id)
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		s := newPostgresTestStore(t, dsn)
		// A random id, and a delete first: a row left by an earlier run
		// against the same database cannot turn this into a false failure.
		id := 1_000_000 + rand.Int64N(1_000_000_000)
		if _, err := s.DB.Exec(`DELETE FROM pa_updates WHERE update_id = $1`, id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_updates WHERE update_id = $1`, id) })
		runs, errs := concurrentPAAccepts(t, s, id, 16)
		if runs != 1 || errs != 0 {
			t.Fatalf("runs=%d errors=%d, want exactly 1 run and no errors", runs, errs)
		}
		assertPADuplicate(t, s, id)
	})
}

// assertPADuplicate delivers id once more, sequentially: it must be a
// duplicate, and fn must not run.
func assertPADuplicate(t *testing.T, s *Store, id int64) {
	t.Helper()
	ran := false
	ok, err := s.AcceptPAUpdate(context.Background(), id, func(context.Context, *sql.Tx) error { ran = true; return nil })
	if err != nil || ok || ran {
		t.Fatalf("delivery after the run: ok=%v err=%v ran=%v, want a duplicate", ok, err, ran)
	}
}

func concurrentPAAccepts(t *testing.T, s *Store, updateID int64, n int) (runs, errs int) {
	t.Helper()
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		start = make(chan struct{})
	)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ran := false
			ok, err := s.AcceptPAUpdate(context.Background(), updateID, func(context.Context, *sql.Tx) error {
				ran = true
				return nil
			})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs++
				return
			}
			if ok != ran {
				t.Errorf("accepted=%v but fn ran=%v", ok, ran)
			}
			if ok {
				runs++
			}
		}()
	}
	close(start)
	wg.Wait()
	return runs, errs
}
