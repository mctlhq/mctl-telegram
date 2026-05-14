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
	// Idempotent ALTER passes for columns added after the initial schema.
	// Each is wrapped in dialect-specific existence checks because CREATE
	// TABLE IF NOT EXISTS does not update existing tables, and we cannot
	// modify the original CREATE TABLE without breaking deployments that
	// already have rows.
	if err := addColumnIfMissing(ctx, dbConn, pg, "telegram_accounts", "last_used_at",
		"TIMESTAMPTZ", "DATETIME"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, dbConn, pg, "telegram_accounts", "expires_at",
		"TIMESTAMPTZ", "DATETIME"); err != nil {
		return err
	}
	// Hash-chain columns on audit_logs (M3.1). Tamper-evident: each new
	// row stores SHA-256(prev_hash || canonical(row)); VerifyAuditChain
	// recomputes the chain and reports the first mismatch.
	if err := addColumnIfMissing(ctx, dbConn, pg, "audit_logs", "prev_hash",
		"BYTEA", "BLOB"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, dbConn, pg, "audit_logs", "entry_hash",
		"BYTEA", "BLOB"); err != nil {
		return err
	}
	// Backfill: rows that pre-date the columns get last_used_at = connected_at
	// and expires_at = connected_at + 90 days. We do this on every Migrate run
	// rather than as a one-shot script because the platform's gitops loop is
	// re-run on every deploy and we want this to converge regardless.
	backfill := []string{
		`UPDATE telegram_accounts
		 SET last_used_at = connected_at
		 WHERE last_used_at IS NULL`,
	}
	if pg {
		backfill = append(backfill,
			`UPDATE telegram_accounts
			 SET expires_at = connected_at + INTERVAL '90 days'
			 WHERE expires_at IS NULL`,
		)
	} else {
		// SQLite has no INTERVAL syntax; use the datetime() function.
		backfill = append(backfill,
			`UPDATE telegram_accounts
			 SET expires_at = datetime(connected_at, '+90 days')
			 WHERE expires_at IS NULL`,
		)
	}
	for _, s := range backfill {
		if _, err := dbConn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("backfill: %w\nstmt: %s", err, s)
		}
	}
	return nil
}

// addColumnIfMissing runs an ALTER TABLE ... ADD COLUMN that is a no-op when
// the column is already present. Postgres has `ADD COLUMN IF NOT EXISTS`
// natively; SQLite needs us to inspect pragma_table_info first and skip the
// ALTER when the column is there. Used by Migrate() to fold post-launch
// schema additions into a single idempotent pass.
func addColumnIfMissing(ctx context.Context, dbConn *sql.DB, pg bool, table, column, pgType, sqliteType string) error {
	if pg {
		stmt := fmt.Sprintf(
			`ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s`,
			table, column, pgType,
		)
		if _, err := dbConn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("add column %s.%s: %w", table, column, err)
		}
		return nil
	}
	// SQLite path: check column existence via pragma_table_info.
	var count int
	if err := dbConn.QueryRowContext(ctx,
		`SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`,
		table, column,
	).Scan(&count); err != nil {
		return fmt.Errorf("pragma table_info(%s): %w", table, err)
	}
	if count > 0 {
		return nil
	}
	stmt := fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, sqliteType)
	if _, err := dbConn.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
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
			revoked_at DATETIME,
			last_used_at DATETIME,
			expires_at DATETIME
		)`,
		`CREATE INDEX IF NOT EXISTS idx_telegram_accounts_user_active ON telegram_accounts(user_id) WHERE revoked_at IS NULL`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER REFERENCES users(id),
			tool_name TEXT NOT NULL,
			peer_redacted TEXT,
			status TEXT NOT NULL,
			error TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			prev_hash BLOB,
			entry_hash BLOB
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
			revoked_at TIMESTAMPTZ,
			last_used_at TIMESTAMPTZ,
			expires_at TIMESTAMPTZ
		)`,
		`CREATE INDEX IF NOT EXISTS idx_telegram_accounts_user_active ON telegram_accounts(user_id) WHERE revoked_at IS NULL`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id BIGSERIAL PRIMARY KEY,
			user_id BIGINT REFERENCES users(id),
			tool_name TEXT NOT NULL,
			peer_redacted TEXT,
			status TEXT NOT NULL,
			error TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			prev_hash BYTEA,
			entry_hash BYTEA
		)`,
	}
}
