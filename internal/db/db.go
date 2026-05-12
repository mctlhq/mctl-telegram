package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// driverFor inspects the DSN scheme and returns the database/sql driver name
// plus a flag for "is Postgres" so Migrate() can pick the right dialect.
func driverFor(dsn string) (driver string, isPg bool) {
	switch {
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return "pgx", true
	default:
		return "sqlite", false
	}
}

// Open opens a database connection. SQLite (modernc, pure Go) for `file:...`
// DSNs and any unrecognized prefix; pgx/stdlib for `postgres://`.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	driver, isPg := driverFor(dsn)
	dbConn, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", driver, err)
	}
	if err := dbConn.PingContext(ctx); err != nil {
		_ = dbConn.Close()
		return nil, fmt.Errorf("ping %s: %w", driver, err)
	}
	if isPg {
		dbConn.SetMaxOpenConns(10)
		dbConn.SetMaxIdleConns(2)
	} else {
		dbConn.SetMaxOpenConns(1)
	}
	return dbConn, nil
}

// Migrate applies the schema for whichever dialect Open chose. Idempotent.
func Migrate(ctx context.Context, dbConn *sql.DB) error {
	// We re-probe by issuing one driver-specific NOOP. SQLite parses `SELECT 1`
	// fine on both; we detect Postgres by `current_database()` which only
	// exists there. Cleaner than threading the driver name through callers.
	var pg bool
	if err := dbConn.QueryRowContext(ctx, "SELECT 1 FROM pg_catalog.pg_database WHERE datname = current_database()").Scan(new(int)); err == nil {
		pg = true
	}
	var stmts []string
	if pg {
		stmts = pgSchema()
	} else {
		stmts = sqliteSchema()
	}
	for _, s := range stmts {
		if _, err := dbConn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate: %w\nstmt: %s", err, s)
		}
	}
	return nil
}

func sqliteSchema() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			github_login TEXT UNIQUE NOT NULL,
			email TEXT,
			provider TEXT NOT NULL DEFAULT 'local-dev',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS telegram_accounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			telegram_user_id INTEGER,
			display_name TEXT,
			username TEXT,
			session_encrypted BLOB NOT NULL,
			send_enabled INTEGER NOT NULL DEFAULT 0,
			connected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			revoked_at DATETIME
		)`,
		`CREATE INDEX IF NOT EXISTS idx_telegram_accounts_user_active ON telegram_accounts(user_id) WHERE revoked_at IS NULL`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER REFERENCES users(id),
			tool_name TEXT NOT NULL,
			peer_redacted TEXT,
			status TEXT NOT NULL,
			error TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}
}

func pgSchema() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS users (
			id BIGSERIAL PRIMARY KEY,
			github_login TEXT UNIQUE NOT NULL,
			email TEXT,
			provider TEXT NOT NULL DEFAULT 'mctl-api',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS telegram_accounts (
			id BIGSERIAL PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			telegram_user_id BIGINT,
			display_name TEXT,
			username TEXT,
			session_encrypted BYTEA NOT NULL,
			send_enabled BOOLEAN NOT NULL DEFAULT FALSE,
			connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			revoked_at TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS idx_telegram_accounts_user_active ON telegram_accounts(user_id) WHERE revoked_at IS NULL`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id BIGSERIAL PRIMARY KEY,
			user_id BIGINT REFERENCES users(id),
			tool_name TEXT NOT NULL,
			peer_redacted TEXT,
			status TEXT NOT NULL,
			error TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	}
}
