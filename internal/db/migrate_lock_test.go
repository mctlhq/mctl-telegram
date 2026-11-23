package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"
)

// freshPostgresSchemaDSN creates an empty schema in TEST_DATABASE_URL and
// returns a DSN scoped to it; the schema is dropped when the test ends.
func freshPostgresSchemaDSN(t *testing.T) string {
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
	schema := fmt.Sprintf("migrate_lock_%d", time.Now().UnixNano())
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
	return u.String()
}

// openPostgresPool opens a pool whose sessions carry application_name app,
// so the test can tell its own sessions' locks from those of other test
// packages migrating the same database at the same time.
func openPostgresPool(t *testing.T, dsn, app string) *sql.DB {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("application_name", app)
	u.RawQuery = q.Encode()
	conn, err := Open(context.Background(), u.String(), 5, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// holdMigrateLock takes migrateLockKey on a connection of its own, as
// another replica's Migrate would, and returns the function that releases
// it.
func holdMigrateLock(t *testing.T, pool *sql.DB) func() {
	t.Helper()
	ctx := context.Background()
	conn, err := pool.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrateLockKey); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			var ok bool
			if err := conn.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, migrateLockKey).Scan(&ok); err != nil || !ok {
				t.Errorf("release holder lock: ok=%v err=%v", ok, err)
			}
			_ = conn.Close()
		})
	}
	t.Cleanup(release)
	return release
}

// migrateLockHeldBy reports whether a session of application app holds
// migrateLockKey. The lock is per database, and other test packages migrate
// the same database concurrently, so "nobody holds it" is not something a
// test may assert; "none of this pool's sessions holds it" is. Ending a
// session is asynchronous on the server, so it waits up to 5s for the lock
// to go before answering true.
func migrateLockHeldBy(t *testing.T, observer *sql.DB, app string) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int
		if err := observer.QueryRowContext(context.Background(),
			`SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
			  WHERE a.application_name = $1 AND l.locktype = 'advisory' AND l.granted
			    AND ((l.classid::bigint << 32) | l.objid::bigint) = $2`, app, migrateLockKey).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			return false
		}
		if time.Now().After(deadline) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func testAppName(t *testing.T, role string) string {
	return fmt.Sprintf("migrate_lock_%s_%d", role, time.Now().UnixNano())
}

// tableExists reads the catalog; a failed read fails the test rather than
// reading as "absent".
func tableExists(t *testing.T, pool *sql.DB, name string) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRowContext(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

// TestMigrateLockPostgres_ConcurrentFreshMigrate: two replicas migrating a
// fresh database at the same time both succeed, and the lock is released
// afterwards.
func TestMigrateLockPostgres_ConcurrentFreshMigrate(t *testing.T) {
	dsn := freshPostgresSchemaDSN(t)
	appA, appB := testAppName(t, "a"), testAppName(t, "b")
	a, b := openPostgresPool(t, dsn, appA), openPostgresPool(t, dsn, appB)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	errs := make(chan error, 2)
	var start sync.WaitGroup
	start.Add(1)
	for _, pool := range []*sql.DB{a, b} {
		go func() {
			start.Wait()
			errs <- Migrate(ctx, pool)
		}()
	}
	start.Done()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent Migrate: %v", err)
		}
	}
	if !tableExists(t, a, "pa_outbox") {
		t.Fatal("pa_outbox missing after Migrate")
	}
	if migrateLockHeldBy(t, a, appA) || migrateLockHeldBy(t, a, appB) {
		t.Fatal("migration lock still held by a pool after both Migrate calls returned")
	}
}

// TestMigrateLockPostgres_WaitsForHolder: while another session holds the
// migration lock, Migrate creates nothing; it runs once the lock is
// released.
func TestMigrateLockPostgres_WaitsForHolder(t *testing.T) {
	dsn := freshPostgresSchemaDSN(t)
	app := testAppName(t, "migrate")
	holder, pool := openPostgresPool(t, dsn, testAppName(t, "holder")), openPostgresPool(t, dsn, app)
	release := holdMigrateLock(t, holder)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Migrate(ctx, pool) }()
	select {
	case err := <-done:
		t.Fatalf("Migrate returned (err=%v) while another session held the migration lock", err)
	case <-time.After(750 * time.Millisecond):
	}
	if tableExists(t, holder, "pa_outbox") {
		t.Fatal("Migrate created tables while another session held the migration lock")
	}
	release()
	if err := <-done; err != nil {
		t.Fatalf("Migrate after the lock was released: %v", err)
	}
	if !tableExists(t, holder, "pa_outbox") {
		t.Fatal("pa_outbox missing after Migrate")
	}
	if migrateLockHeldBy(t, holder, app) {
		t.Fatal("migration lock still held by the pool after Migrate returned")
	}
}

// TestMigrateLockPostgres_ContextEndsWhileWaiting: a Migrate whose context
// ends while it waits for the lock returns that error, migrated nothing,
// and no session of its pool holds the lock once the holder let go (so a
// grant that raced the cancellation did not survive on an idle pooled
// connection).
//
// It does not prove that withMigrateLock discards the connection on that
// path: pgx closes a connection whose query was cancelled by its context
// anyway, so the test passes with or without the discard. The discard is
// there for a driver or a failure that leaves the connection open.
func TestMigrateLockPostgres_ContextEndsWhileWaiting(t *testing.T) {
	dsn := freshPostgresSchemaDSN(t)
	app := testAppName(t, "migrate")
	holder, pool := openPostgresPool(t, dsn, testAppName(t, "holder")), openPostgresPool(t, dsn, app)
	release := holdMigrateLock(t, holder)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	err := Migrate(ctx, pool)
	if err == nil {
		t.Fatal("Migrate succeeded while another session held the migration lock")
	}
	if !errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
		t.Fatalf("Migrate failed before its context ended: %v", err)
	}
	if tableExists(t, holder, "pa_outbox") {
		t.Fatal("Migrate created tables without the migration lock")
	}
	release()
	if migrateLockHeldBy(t, holder, app) {
		t.Fatal("a cancelled Migrate left the migration lock held on a pooled connection")
	}
}
