package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// migrateDB is what a migration step runs on: the pool (*sql.DB) on SQLite,
// the one connection that holds the migration lock (*sql.Conn) on Postgres.
type migrateDB interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

var (
	_ migrateDB = (*sql.DB)(nil)
	_ migrateDB = (*sql.Conn)(nil)
)

// migrateLockKey is the Postgres session-level advisory lock Migrate holds
// while it runs (pg_advisory_lock). It is fixed, so every build of this
// server takes the same lock: the bytes spell "mctltg" followed by 0x0001.
// Advisory locks are per database, so it also serialises Migrate across
// schemas of one database (the test suites), which only makes them wait.
// Nothing else in this server takes an advisory lock with this key.
//
// Without it two replicas starting together raced each other's
// CREATE ... IF NOT EXISTS: the existence check and the catalog insert are
// not atomic, so the loser failed on a duplicate key in pg_type or
// pg_class and crash-looped until the winner had finished.
const migrateLockKey int64 = 0x6d63746c74670001

// migrateUnlockTimeout bounds the unlock, which runs on a context detached
// from the caller's so that a cancelled Migrate still releases the lock.
const migrateUnlockTimeout = 10 * time.Second

// withMigrateLock runs fn on one connection of pool while that connection
// holds migrateLockKey, and releases the lock afterwards. Every step of fn
// runs on the same connection, so the lock covers all of them and the
// migration never needs a second pool connection while it holds one.
//
// A failed lock or unlock is an error. When either fails, or the lock's
// state on the connection is not known, the connection is closed rather
// than returned to the pool: ending the session releases a session-level
// advisory lock, so a lock can never stay held by an idle pool connection.
func withMigrateLock(ctx context.Context, pool *sql.DB, fn func(migrateDB) error) (err error) {
	conn, err := pool.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrate: lock: connection: %w", err)
	}
	discard := false
	defer func() {
		if discard {
			// driver.ErrBadConn makes database/sql close the connection
			// instead of putting it back in the pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		if cerr := conn.Close(); cerr != nil && !discard && err == nil {
			err = fmt.Errorf("migrate: lock: release connection: %w", cerr)
		}
	}()

	var got bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, migrateLockKey).Scan(&got); err != nil {
		discard = true
		return fmt.Errorf("migrate: lock: %w", err)
	}
	if !got {
		slog.Info("migrate: another instance holds the migration lock; waiting", "lock_key", migrateLockKey)
		// A context that ends while waiting cancels the query; whether the
		// lock was granted just before is then unknown, so the connection
		// is discarded.
		if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrateLockKey); err != nil {
			discard = true
			return fmt.Errorf("migrate: lock: %w", err)
		}
	}

	ferr := fn(conn)

	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrateUnlockTimeout)
	defer cancel()
	var released bool
	uerr := conn.QueryRowContext(uctx, `SELECT pg_advisory_unlock($1)`, migrateLockKey).Scan(&released)
	switch {
	case uerr != nil:
		discard = true
		uerr = fmt.Errorf("migrate: unlock: %w", uerr)
	case !released:
		// The session did not hold the lock it took: something released it
		// behind our back, so it did not cover every step.
		discard = true
		uerr = errors.New("migrate: unlock: the migration lock was not held")
	}
	return errors.Join(ferr, uerr)
}
