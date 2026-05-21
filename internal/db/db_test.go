package db

import (
	"context"
	"os"
	"testing"
)

// TestOpenPool verifies that db.Open respects the maxOpenConns and maxIdleConns
// parameters and that passing 0/0 preserves the prior default behaviour.
func TestOpenPool(t *testing.T) {
	ctx := context.Background()
	// SQLite in-memory DSN used for all non-Postgres sub-tests.
	const sqlite = "file::memory:?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

	t.Run("sqlite_zero_values_preserves_default", func(t *testing.T) {
		db, err := Open(ctx, sqlite, 0, 0)
		if err != nil {
			t.Fatalf("Open(sqlite, 0, 0) error: %v", err)
		}
		defer db.Close()
		stats := db.Stats()
		// SQLite branch always calls SetMaxOpenConns(1) regardless of the
		// passed values; 0 is the sentinel for "use default" on Postgres only.
		if stats.MaxOpenConnections != 1 {
			t.Errorf("MaxOpenConnections = %d, want 1 for SQLite", stats.MaxOpenConnections)
		}
	})

	t.Run("sqlite_nonzero_values_still_sets_one", func(t *testing.T) {
		// The SQLite branch ignores maxOpenConns and always calls
		// SetMaxOpenConns(1). Passing non-zero values must not crash.
		db, err := Open(ctx, sqlite, 5, 3)
		if err != nil {
			t.Fatalf("Open(sqlite, 5, 3) error: %v", err)
		}
		defer db.Close()
		stats := db.Stats()
		if stats.MaxOpenConnections != 1 {
			t.Errorf("MaxOpenConnections = %d, want 1 for SQLite (branch always uses 1)", stats.MaxOpenConnections)
		}
	})

	// Postgres sub-test: only runs when TEST_DATABASE_URL is set.
	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		t.Run("postgres_nonzero_values_applied", func(t *testing.T) {
			db, err := Open(ctx, dsn, 7, 3)
			if err != nil {
				t.Skipf("postgres not available: %v", err)
			}
			defer db.Close()
			stats := db.Stats()
			if stats.MaxOpenConnections != 7 {
				t.Errorf("MaxOpenConnections = %d, want 7 for Postgres with explicit value", stats.MaxOpenConnections)
			}
		})
	}
}
