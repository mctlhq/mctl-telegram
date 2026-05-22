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
// maxOpenConns and maxIdleConns are Postgres-only tuning knobs; pass 0 to
// keep the prior defaults (10 open, 2 idle). SQLite always uses 1 open conn.
func Open(ctx context.Context, dsn string, maxOpenConns, maxIdleConns int) (*sql.DB, error) {
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
		open := 10
		if maxOpenConns > 0 {
			open = maxOpenConns
		}
		idle := 2
		if maxIdleConns > 0 {
			idle = maxIdleConns
		}
		dbConn.SetMaxOpenConns(open)
		dbConn.SetMaxIdleConns(idle)
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
	// Local Bridge scaffolding (M4). `mode` distinguishes the legacy
	// server-side MTProto path (hosted) from the upcoming Local Bridge
	// path where MTProto runs on the user's machine and tg.mctl.ai is a
	// relay only; `bridge_token_hash` is the SHA-256 of the most-recent
	// short-lived JWT a daemon has used to register, used to drop stale
	// connections when a new token rotates in. Defaults to 'hosted' so
	// existing rows keep their behaviour.
	if err := addColumnIfMissing(ctx, dbConn, pg, "telegram_accounts", "mode",
		"TEXT NOT NULL DEFAULT 'hosted'", "TEXT NOT NULL DEFAULT 'hosted'"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, dbConn, pg, "telegram_accounts", "bridge_token_hash",
		"BYTEA", "BLOB"); err != nil {
		return err
	}
	// call_path column on audit_logs (M4). Distinguishes relay-forwarded
	// calls ('local') from server-side hosted calls (''). No DEFAULT: the
	// column is left NULL for rows that pre-date M4 so they stay
	// distinguishable from M4+ rows (which always write a non-NULL value).
	// A non-NULL default ('hosted') would retroactively change the canonical
	// hash input of every pre-M4 row and make VerifyAuditChain report the
	// whole chain as tampered — see hashAuditEntry's NULL handling.
	if err := addColumnIfMissing(ctx, dbConn, pg, "audit_logs", "call_path",
		"TEXT", "TEXT"); err != nil {
		return err
	}
	// Telegram-native identity columns (users): replaces github_login as the
	// primary key. github_login becomes nullable so widget-issued user rows
	// (which never have a GitHub login) can coexist with legacy ones during
	// the rollout.
	if err := addColumnIfMissing(ctx, dbConn, pg, "users", "telegram_login_id",
		"BIGINT", "INTEGER"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, dbConn, pg, "users", "telegram_username",
		"TEXT", "TEXT"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, dbConn, pg, "users", "telegram_display_name",
		"TEXT", "TEXT"); err != nil {
		return err
	}
	// access_tier: DB-backed client allowlist. NULL/'none' = unprivileged,
	// 'client' = telegram:* scopes for the user's own account. Admins stay on
	// the TG_LOGIN_ADMINS env allowlist; this column only governs the client
	// tier so it can be managed at runtime via the admin MCP tools.
	if err := addColumnIfMissing(ctx, dbConn, pg, "users", "access_tier",
		"TEXT", "TEXT"); err != nil {
		return err
	}
	// Unique index on telegram_login_id (partial — NULLs ignored) so multiple
	// pre-migration rows without telegram_login_id remain valid.
	idxStmts := []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_telegram_login_id ON users(telegram_login_id) WHERE telegram_login_id IS NOT NULL`,
	}
	for _, s := range idxStmts {
		if _, err := dbConn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("create index: %w\nstmt: %s", err, s)
		}
	}
	// Drop the NOT NULL constraint on users.github_login if present. SQLite
	// cannot alter constraints in-place; in production we run on Postgres
	// (where ALTER COLUMN DROP NOT NULL works) and the SQLite branch keeps
	// the legacy schema for local-dev — that's fine because local-dev never
	// inserts NULL into the column (OperatorLogin is always set).
	if pg {
		if _, err := dbConn.ExecContext(ctx,
			`ALTER TABLE users ALTER COLUMN github_login DROP NOT NULL`,
		); err != nil {
			return fmt.Errorf("drop not null on users.github_login: %w", err)
		}
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
			expires_at DATETIME,
			mode TEXT NOT NULL DEFAULT 'hosted',
			bridge_token_hash BLOB
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
		// OAuth refresh tokens (M5). The opaque token string is never stored —
		// only token_hash (SHA-256). family_id ties a token to its rotation
		// lineage so a replayed (already-rotated) token can revoke the family.
		`CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			family_id TEXT NOT NULL,
			token_hash BLOB NOT NULL,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			client_id TEXT NOT NULL,
			telegram_id INTEGER NOT NULL,
			telegram_username TEXT,
			scope TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_hash ON oauth_refresh_tokens(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_family ON oauth_refresh_tokens(family_id)`,
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
			expires_at TIMESTAMPTZ,
			mode TEXT NOT NULL DEFAULT 'hosted',
			bridge_token_hash BYTEA
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
		// OAuth refresh tokens (M5). The opaque token string is never stored —
		// only token_hash (SHA-256). family_id ties a token to its rotation
		// lineage so a replayed (already-rotated) token can revoke the family.
		`CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
			id BIGSERIAL PRIMARY KEY,
			family_id TEXT NOT NULL,
			token_hash BYTEA NOT NULL,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			client_id TEXT NOT NULL,
			telegram_id BIGINT NOT NULL,
			telegram_username TEXT,
			scope TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ NOT NULL,
			revoked_at TIMESTAMPTZ
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_hash ON oauth_refresh_tokens(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_family ON oauth_refresh_tokens(family_id)`,
		// OAuth transient state tables (issue-66). Only created on Postgres; SQLite
		// deployments keep in-memory maps (single-writer contention makes DB-backed
		// OAuth worse there). Tables are idempotent (IF NOT EXISTS) and contain
		// only transient state (TTL <= 10 min for pending/codes; registration TTL
		// default 24h for clients) — safe to drop without user-visible data loss.
		`CREATE TABLE IF NOT EXISTS oauth_pending_auth (
			state              TEXT PRIMARY KEY,
			client_id          TEXT NOT NULL,
			redirect_uri       TEXT NOT NULL,
			client_state       TEXT NOT NULL DEFAULT '',
			code_challenge     TEXT NOT NULL,
			challenge_method   TEXT NOT NULL DEFAULT 'S256',
			scope              TEXT NOT NULL DEFAULT '',
			nonce              TEXT NOT NULL,
			tg_code_verifier   TEXT NOT NULL,
			created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS oauth_auth_codes (
			code                TEXT PRIMARY KEY,
			client_id           TEXT NOT NULL,
			redirect_uri        TEXT NOT NULL,
			code_challenge      TEXT NOT NULL,
			challenge_method    TEXT NOT NULL DEFAULT 'S256',
			telegram_id         BIGINT NOT NULL,
			telegram_username   TEXT NOT NULL DEFAULT '',
			scope               TEXT NOT NULL DEFAULT '',
			created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS oauth_client_registrations (
			client_id      TEXT PRIMARY KEY,
			client_name    TEXT NOT NULL DEFAULT '',
			redirect_uris  TEXT NOT NULL,
			created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		// Indexes on created_at for the three OAuth transient tables — used by
		// sweep (range DELETE WHERE created_at < cutoff) and eviction (ORDER BY
		// created_at ASC LIMIT 1). Without these, both operations do full scans.
		`CREATE INDEX IF NOT EXISTS idx_oauth_pending_auth_created_at ON oauth_pending_auth(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_created_at ON oauth_auth_codes(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_client_regs_created_at ON oauth_client_registrations(created_at)`,
	}
}
