package db

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestGrantClientTierIfUnset_SetsClientWhenUnset(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const tgID int64 = 880540001
	if _, err := st.EnsureUserByTelegramID(ctx, tgID, "fresh", "Fresh"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	granted, err := st.GrantClientTierIfUnset(ctx, tgID)
	if err != nil {
		t.Fatalf("GrantClientTierIfUnset: %v", err)
	}
	if !granted {
		t.Fatal("expected granted=true for an unset row")
	}
	tier, err := st.GetAccessTier(ctx, tgID)
	if err != nil {
		t.Fatalf("GetAccessTier: %v", err)
	}
	if tier != TierClient {
		t.Fatalf("tier = %q, want %q", tier, TierClient)
	}
}

func TestGrantClientTierIfUnset_DoesNotOverwriteNone(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const tgID int64 = 880540002
	if _, err := st.EnsureUserByTelegramID(ctx, tgID, "banned", "Banned"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := st.SetAccessTier(ctx, tgID, TierNone); err != nil {
		t.Fatalf("seed none: %v", err)
	}
	granted, err := st.GrantClientTierIfUnset(ctx, tgID)
	if err != nil {
		t.Fatalf("GrantClientTierIfUnset: %v", err)
	}
	if granted {
		t.Fatal("expected granted=false when access_tier is already none")
	}
	tier, err := st.GetAccessTier(ctx, tgID)
	if err != nil {
		t.Fatalf("GetAccessTier: %v", err)
	}
	if tier != TierNone {
		t.Fatalf("tier = %q, want %q", tier, TierNone)
	}
}

func TestGrantClientTierIfUnset_DoesNotOverwriteClient(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const tgID int64 = 880540003
	if _, err := st.EnsureUserByTelegramID(ctx, tgID, "client", "Client"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := st.SetAccessTier(ctx, tgID, TierClient); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	granted, err := st.GrantClientTierIfUnset(ctx, tgID)
	if err != nil {
		t.Fatalf("GrantClientTierIfUnset: %v", err)
	}
	if granted {
		t.Fatal("expected granted=false when access_tier is already client")
	}
}

func TestGrantClientTierIfUnset_EmptyStringIsUnset(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const tgID int64 = 880540004
	if _, err := st.EnsureUserByTelegramID(ctx, tgID, "empty", "Empty"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := st.DB.ExecContext(ctx,
		`UPDATE users SET access_tier = '' WHERE telegram_login_id = $1`, tgID,
	); err != nil {
		t.Fatalf("seed empty: %v", err)
	}
	granted, err := st.GrantClientTierIfUnset(ctx, tgID)
	if err != nil {
		t.Fatalf("GrantClientTierIfUnset: %v", err)
	}
	if !granted {
		t.Fatal("expected granted=true for an empty-string tier")
	}
}

func TestGrantClientTierIfUnset_MissingUserErrors(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	granted, err := st.GrantClientTierIfUnset(ctx, 880540099)
	if err == nil {
		t.Fatal("expected error for a missing users row")
	}
	if granted {
		t.Fatal("expected granted=false when the users row is missing")
	}
}

// TestGrantClientTierIfUnset_ConcurrentNoneIsNotOverwritten hammers the CAS
// against a row that already holds none. Every grant must be a no-op.
func TestGrantClientTierIfUnset_ConcurrentNoneIsNotOverwritten(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	const tgID int64 = 880540005
	if _, err := st.EnsureUserByTelegramID(ctx, tgID, "banned", "Banned"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := st.SetAccessTier(ctx, tgID, TierNone); err != nil {
		t.Fatalf("seed none: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			granted, err := st.GrantClientTierIfUnset(ctx, tgID)
			if err != nil {
				errCh <- err
				return
			}
			if granted {
				errCh <- errors.New("GrantClientTierIfUnset overwrote a pre-set none")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent grant: %v", err)
	}
	tier, err := st.GetAccessTier(ctx, tgID)
	if err != nil {
		t.Fatalf("GetAccessTier: %v", err)
	}
	if tier != TierNone {
		t.Fatalf("tier after concurrent grants = %q, want %q", tier, TierNone)
	}
}

// TestGrantClientTierIfUnset_HeldNoneIsNotOverwritten opens a second
// connection, holds an uncommitted none, then lets GrantClientTierIfUnset
// run. After the ban commits the CAS must leave none in place. The old
// unconditional SetAccessTier(client) would win the write lock and restore
// client. Shared SQL for SQLite and Postgres — no dialect split.
func TestGrantClientTierIfUnset_HeldNoneIsNotOverwritten(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "tier.db") + "?_pragma=busy_timeout(5000)"
	runGrantClientTierIfUnsetHeldNone(t, ctx, dsn, 880540006)
}

func TestGrantClientTierIfUnset_PostgresHeldNoneIsNotOverwritten(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	runGrantClientTierIfUnsetHeldNone(t, ctx, dsn, 880540007)
}

func TestGrantClientTierIfUnset_PostgresSetsClientWhenUnset(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := Open(ctx, dsn, 0, 0)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st := &Store{DB: conn}
	const tgID int64 = 880540008
	t.Cleanup(func() {
		_, _ = conn.ExecContext(ctx, `DELETE FROM users WHERE telegram_login_id = $1`, tgID)
	})
	if _, err := st.EnsureUserByTelegramID(ctx, tgID, "pgfresh", "PG Fresh"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`UPDATE users SET access_tier = NULL WHERE telegram_login_id = $1`, tgID,
	); err != nil {
		t.Fatalf("reset unset: %v", err)
	}
	granted, err := st.GrantClientTierIfUnset(ctx, tgID)
	if err != nil {
		t.Fatalf("GrantClientTierIfUnset: %v", err)
	}
	if !granted {
		t.Fatal("expected granted=true for an unset postgres row")
	}
	if err := st.SetAccessTier(ctx, tgID, TierNone); err != nil {
		t.Fatalf("seed none: %v", err)
	}
	granted, err = st.GrantClientTierIfUnset(ctx, tgID)
	if err != nil {
		t.Fatalf("GrantClientTierIfUnset after none: %v", err)
	}
	if granted {
		t.Fatal("postgres grant overwrote none")
	}
	tier, err := st.GetAccessTier(ctx, tgID)
	if err != nil {
		t.Fatalf("GetAccessTier: %v", err)
	}
	if tier != TierNone {
		t.Fatalf("postgres tier = %q, want %q", tier, TierNone)
	}
}

func runGrantClientTierIfUnsetHeldNone(t *testing.T, ctx context.Context, dsn string, tgID int64) {
	t.Helper()
	conn, err := Open(ctx, dsn, 0, 0)
	if err != nil {
		t.Skipf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	st := &Store{DB: conn}
	if _, err := st.EnsureUserByTelegramID(ctx, tgID, "held", "Held"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`UPDATE users SET access_tier = NULL WHERE telegram_login_id = $1`, tgID,
	); err != nil {
		t.Fatalf("reset unset: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(ctx, `DELETE FROM users WHERE telegram_login_id = $1`, tgID)
	})

	held, err := Open(ctx, dsn, 0, 0)
	if err != nil {
		t.Fatalf("open second conn: %v", err)
	}
	t.Cleanup(func() { _ = held.Close() })
	tx, err := held.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET access_tier = $1 WHERE telegram_login_id = $2`,
		TierNone, tgID,
	); err != nil {
		_ = tx.Rollback()
		t.Fatalf("hold none: %v", err)
	}

	type result struct {
		granted bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		granted, err := st.GrantClientTierIfUnset(ctx, tgID)
		done <- result{granted, err}
	}()

	time.Sleep(100 * time.Millisecond)
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit none: %v", err)
	}
	var got result
	select {
	case got = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("GrantClientTierIfUnset blocked past busy_timeout")
	}
	if got.err != nil {
		t.Fatalf("GrantClientTierIfUnset: %v", got.err)
	}
	if got.granted {
		t.Fatal("grant reported success after a concurrent none committed")
	}
	tier, err := st.GetAccessTier(ctx, tgID)
	if err != nil {
		t.Fatalf("GetAccessTier: %v", err)
	}
	if tier != TierNone {
		t.Fatalf("tier after held-none race = %q, want %q", tier, TierNone)
	}
}
