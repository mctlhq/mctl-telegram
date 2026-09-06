package db

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
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
// Open makes exactly one connect-and-ping attempt and returns immediately on
// failure; see OpenWithRetry for the bounded-retry variant used by the
// server's startup path.
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
// Migrate brings the schema up to date. ttlExemptTelegramIDs, when given,
// are excluded from the expires_at backfill below: those identities are meant
// to carry NULL (no absolute expiry), and re-arming them here — even for the
// few lines until ReconcileTTLExemptions clears it again — is visible to every
// other replica sharing this database. For an identity already past the
// original 90-day mark the backfilled deadline is in the past the instant it
// is written, so a concurrent sweeper tick or an inline CheckSessionValid on
// another replica could revoke the row for good, reproducing #409 on a routine
// rolling restart. Excluding them here means the intermediate state never
// exists.
//
// Passing no ids re-arms every NULL row, which is exactly how an identity
// dropped from the exemption list gets its TTL back.
func Migrate(ctx context.Context, dbConn *sql.DB, ttlExemptTelegramIDs ...int64) error {
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
	// server-side MTProto path (hosted) from the Local Bridge path where
	// MTProto runs on the user's machine and tg.mctl.ai is a relay only.
	// Defaults to 'hosted' so existing rows keep their behaviour.
	//
	// A sibling `bridge_token_hash` column was declared alongside it and is
	// dropped below; see dropLegacyColumns.
	if err := addColumnIfMissing(ctx, dbConn, pg, "telegram_accounts", "mode",
		"TEXT NOT NULL DEFAULT 'hosted'", "TEXT NOT NULL DEFAULT 'hosted'"); err != nil {
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
	if err := addColumnIfMissing(ctx, dbConn, pg, "oauth_refresh_tokens", "client_name",
		"TEXT NOT NULL DEFAULT ''", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// Rotation-replay grace window (fixes invalid_grant on legitimate refresh
	// races): parent_token_hash lets a replayed predecessor be verified
	// against its live successor with one indexed lookup, mirroring mctl-api.
	// revoked_reason distinguishes a row superseded by normal rotation
	// ('rotated') from one killed by reuse detection or an operator action
	// ('reuse_detected' / 'explicit_revoke') — RevokedAt alone can't tell
	// these apart, and only 'rotated' rows within the grace window are
	// eligible for replay recovery.
	if err := addColumnIfMissing(ctx, dbConn, pg, "oauth_refresh_tokens", "parent_token_hash",
		"BYTEA", "BLOB"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, dbConn, pg, "oauth_refresh_tokens", "revoked_reason",
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
	// Drop the NOT NULL constraint on telegram_accounts.session_encrypted:
	// local-only accounts (provisioned via ProvisionLocalAccount, never
	// completing a hosted login) have no server-side session to store. Same
	// idempotent, additive pattern as the github_login change above.
	if pg {
		if _, err := dbConn.ExecContext(ctx,
			// Postgres only. An existing local-dev SQLite database keeps
			// session_encrypted NOT NULL forever: SQLite has no ALTER COLUMN
			// and CREATE TABLE IF NOT EXISTS does not revisit an existing
			// table, so the relaxed definition below reaches fresh databases
			// only. Provisioning a local-only account against such a database
			// fails with a NOT NULL constraint error; recreate the dev
			// database. Production is Postgres, so this affects no deployment.
			`ALTER TABLE telegram_accounts ALTER COLUMN session_encrypted DROP NOT NULL`,
		); err != nil {
			return fmt.Errorf("drop not null on telegram_accounts.session_encrypted: %w", err)
		}
	}
	// Backfill: rows that pre-date the columns get last_used_at = connected_at
	// and expires_at = connected_at + 90 days. We do this on every Migrate run
	// rather than as a one-shot script because the platform's gitops loop is
	// re-run on every deploy and we want this to converge regardless.
	backfill := []string{
		`UPDATE telegram_accounts
		 SET last_used_at = connected_at
		 WHERE last_used_at IS NULL AND mode <> 'local'`,
	}
	// Keep exempt identities out of the backfill — see the doc comment.
	exemptClause := ""
	if len(ttlExemptTelegramIDs) > 0 {
		lits := make([]string, 0, len(ttlExemptTelegramIDs))
		for _, id := range ttlExemptTelegramIDs {
			// Integers only: formatted, never interpolated from user input.
			lits = append(lits, strconv.FormatInt(id, 10))
		}
		exemptClause = "\n\t\t\t   AND (telegram_user_id IS NULL OR telegram_user_id NOT IN (" +
			strings.Join(lits, ",") + "))"
	}
	if pg {
		backfill = append(backfill,
			`UPDATE telegram_accounts
			 SET expires_at = connected_at + INTERVAL '90 days'
			 WHERE expires_at IS NULL AND mode <> 'local'`+exemptClause,
		)
	} else {
		// SQLite has no INTERVAL syntax; use the datetime() function.
		backfill = append(backfill,
			`UPDATE telegram_accounts
			 SET expires_at = datetime(connected_at, '+90 days')
			 WHERE expires_at IS NULL AND mode <> 'local'`+exemptClause,
		)
	}
	for _, s := range backfill {
		if _, err := dbConn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("backfill: %w\nstmt: %s", err, s)
		}
	}
	// Communication-agent domain tables (M6). Kept in a separate file so the
	// agent schema evolves without touching the core auth/session tables.
	if err := migrateAgent(ctx, dbConn, pg); err != nil {
		return err
	}
	// Local Bridge device-bound credentials (issue-483). All four columns are
	// additive and nullable (device_pubkey_algo carries a default so existing
	// rows read as 'ed25519'), so this migration is safe to run against an
	// existing local dev DB or a fresh one, and idempotent on re-run via
	// addColumnIfMissing.
	//
	// device_pubkey / device_pubkey_algo: the Ed25519 public key registered at
	// activation (task 3/4) and the algorithm it uses, so issuance/refresh can
	// verify a proof-of-possession signature. A row with no device_pubkey can
	// never complete issuance -- see local_bridge_credential.go.
	if err := addColumnIfMissing(ctx, dbConn, pg, "local_bridge_devices", "device_pubkey",
		"BYTEA", "BLOB"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, dbConn, pg, "local_bridge_devices", "device_pubkey_algo",
		"TEXT NOT NULL DEFAULT 'ed25519'", "TEXT NOT NULL DEFAULT 'ed25519'"); err != nil {
		return err
	}
	// current_jti / credential_issued_at: the ONE credential lineage claimed
	// atomically at first issuance (see local_bridge_credential.go's
	// conditional UPDATE) and carried forward unchanged by every later PoP
	// refresh. revoke_local_bridge_device denylists current_jti to revoke the
	// whole lineage in one call.
	if err := addColumnIfMissing(ctx, dbConn, pg, "local_bridge_devices", "current_jti",
		"TEXT", "TEXT"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, dbConn, pg, "local_bridge_devices", "credential_issued_at",
		"TIMESTAMPTZ", "DATETIME"); err != nil {
		return err
	}
	return dropLegacyColumns(ctx, dbConn, pg)
}

// dropLegacyColumns removes columns that were declared for a design that was
// then implemented some other way. Runs after the additive pass, so a fresh
// database creates its tables, adds nothing, and drops nothing.
//
// telegram_accounts.bridge_token_hash (M4): declared as the SHA-256 of the
// most recent daemon registration JWT, to "drop stale connections when a new
// token rotates in", and never read or written by any code path. Both halves
// of its job were answered elsewhere:
//
//   - Evicting the stale connection is Hub.Register's (internal/bridge/hub.go),
//     which replaces h.conn[userID] and retires the predecessor on every
//     registration, whatever token it arrived with. A stored hash would not
//     change that decision.
//   - Tying a registered daemon to an issued credential is
//     local_bridge_devices.current_jti / credential_issued_at, claimed
//     atomically at first issuance and denylisted wholesale by
//     revoke_local_bridge_device. That is per device, which is the granularity
//     the question actually has; bridge_token_hash sits on telegram_accounts
//     and so cannot represent a user's second daemon at all.
//
// Wiring it up now would mean a coarser second source of truth for a question
// already answered, so it goes instead. Dropping rather than leaving it is the
// point: DESIGN.md described it as load-bearing, which is a live trap for the
// next reader.
func dropLegacyColumns(ctx context.Context, dbConn *sql.DB, pg bool) error {
	return dropColumnIfPresent(ctx, dbConn, pg, "telegram_accounts", "bridge_token_hash")
}

// dropColumnIfPresent runs an ALTER TABLE ... DROP COLUMN that is a no-op when
// the column is already gone -- the mirror of addColumnIfMissing, and it has
// to be, because both dialects reach that no-op differently.
//
// Postgres has DROP COLUMN IF EXISTS. SQLite has neither the IF EXISTS clause
// nor DROP COLUMN before 3.35.0, so the column is looked up in
// pragma_table_info first and the statement is issued only when it is really
// there. That pre-check is also what keeps an older SQLite working: it never
// reaches the unsupported statement unless the column exists, and a database
// old enough to be missing DROP COLUMN support predates the column itself.
func dropColumnIfPresent(ctx context.Context, dbConn *sql.DB, pg bool, table, column string) error {
	if pg {
		stmt := fmt.Sprintf(`ALTER TABLE %s DROP COLUMN IF EXISTS %s`, table, column)
		if _, err := dbConn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("drop column %s.%s: %w", table, column, err)
		}
		return nil
	}
	var count int
	if err := dbConn.QueryRowContext(ctx,
		`SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`,
		table, column,
	).Scan(&count); err != nil {
		return fmt.Errorf("pragma table_info(%s): %w", table, err)
	}
	if count == 0 {
		return nil
	}
	stmt := fmt.Sprintf(`ALTER TABLE %s DROP COLUMN %s`, table, column)
	if _, err := dbConn.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("drop column %s.%s: %w", table, column, err)
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
			session_encrypted BLOB,
			send_enabled INTEGER NOT NULL DEFAULT 0,
			connected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			revoked_at DATETIME,
			last_used_at DATETIME,
			expires_at DATETIME,
			mode TEXT NOT NULL DEFAULT 'hosted'
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
			client_name TEXT NOT NULL DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			revoked_at DATETIME,
			parent_token_hash BLOB,
			revoked_reason TEXT
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_hash ON oauth_refresh_tokens(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_family ON oauth_refresh_tokens(family_id)`,
		// Worker token revocations (jti denylist). A row with jti set is a
		// single-token revocation; a row with jti NULL is a blanket
		// revocation for telegram_id (every worker token for that id issued
		// at or before revoked_at). Expected to hold single-digit rows —
		// see internal/auth/localjwt.RevocationCache, which caches this
		// table rather than querying it per request.
		`CREATE TABLE IF NOT EXISTS worker_token_revocations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			jti TEXT,
			telegram_id INTEGER NOT NULL,
			revoked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			reason TEXT,
			revoked_by INTEGER
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_worker_token_revocations_jti ON worker_token_revocations(jti) WHERE jti IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_worker_token_revocations_tg ON worker_token_revocations(telegram_id)`,
		// Local Bridge device registry (issue-481). One row per registered
		// daemon installation, distinct from the account-wide
		// telegram_accounts.mode flag. Additive only: nothing reads or
		// writes this table yet (see internal/db/local_bridge_devices.go).
		`CREATE TABLE IF NOT EXISTS local_bridge_devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			device_id TEXT NOT NULL,
			device_label TEXT,
			idempotency_key TEXT,
			registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_seen_at DATETIME,
			revoked_at DATETIME,
			revoked_reason TEXT
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_local_bridge_devices_device_id ON local_bridge_devices(device_id)`,
		// Scoped to (user_id, idempotency_key), not idempotency_key alone:
		// the key is client-supplied, so a global unique index lets one
		// user's retry token collide with another's, silently dropping the
		// second registration.
		//
		// Also scoped to live rows. The original predicate covered revoked
		// rows too, which made revocation irreversible: the unique index
		// blocked inserting a replacement, so RegisterDevice's read-back
		// handed back the revoked device_id forever. Dropped and recreated
		// under a new name so existing deployments migrate on boot; the DROP
		// is a no-op on every run after the first.
		//
		// Dropping in place is safe here only because this service deploys
		// stop-before-start: platform-gitops pins mctl-telegram to
		// strategy: Recreate with a single replica, because MTProto auth
		// keys must never be opened by overlapping pods. No pre-#490
		// instance is ever running against the migrated schema. Under a
		// rolling deployment it would not be safe: an old pod's ON CONFLICT
		// names the wider predicate (idempotency_key IS NOT NULL), which
		// does not imply this index's narrower one, so Postgres would find
		// no arbiter index and fail every registration with "no unique or
		// exclusion constraint matching the ON CONFLICT specification".
		// The same asymmetry makes this migration forward-only: rolling the
		// image back to a pre-#490 build after it has run breaks device
		// registration until the old index is recreated by hand.
		`DROP INDEX IF EXISTS idx_local_bridge_devices_idempotency_key`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_local_bridge_devices_idem_live ON local_bridge_devices(user_id, idempotency_key) WHERE idempotency_key IS NOT NULL AND revoked_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_local_bridge_devices_user ON local_bridge_devices(user_id) WHERE revoked_at IS NULL`,
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
			mode TEXT NOT NULL DEFAULT 'hosted'
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
			client_name TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			expires_at TIMESTAMPTZ NOT NULL,
			revoked_at TIMESTAMPTZ,
			parent_token_hash BYTEA,
			revoked_reason TEXT
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
		// Worker token revocations (jti denylist) — see the sqliteSchema
		// comment on this table for the row-shape explanation.
		`CREATE TABLE IF NOT EXISTS worker_token_revocations (
			id BIGSERIAL PRIMARY KEY,
			jti TEXT,
			telegram_id BIGINT NOT NULL,
			revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			reason TEXT,
			revoked_by BIGINT
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_worker_token_revocations_jti ON worker_token_revocations(jti) WHERE jti IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_worker_token_revocations_tg ON worker_token_revocations(telegram_id)`,
		// Local Bridge device registry (issue-481) -- see the sqliteSchema
		// comment on this table for the column-shape rationale.
		`CREATE TABLE IF NOT EXISTS local_bridge_devices (
			id BIGSERIAL PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			device_id TEXT NOT NULL,
			device_label TEXT,
			idempotency_key TEXT,
			registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_seen_at TIMESTAMPTZ,
			revoked_at TIMESTAMPTZ,
			revoked_reason TEXT
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_local_bridge_devices_device_id ON local_bridge_devices(device_id)`,
		// Scoped to (user_id, idempotency_key), not idempotency_key alone:
		// the key is client-supplied, so a global unique index lets one
		// user's retry token collide with another's, silently dropping the
		// second registration.
		//
		// Also scoped to live rows. The original predicate covered revoked
		// rows too, which made revocation irreversible: the unique index
		// blocked inserting a replacement, so RegisterDevice's read-back
		// handed back the revoked device_id forever. Dropped and recreated
		// under a new name so existing deployments migrate on boot; the DROP
		// is a no-op on every run after the first.
		//
		// Dropping in place is safe here only because this service deploys
		// stop-before-start: platform-gitops pins mctl-telegram to
		// strategy: Recreate with a single replica, because MTProto auth
		// keys must never be opened by overlapping pods. No pre-#490
		// instance is ever running against the migrated schema. Under a
		// rolling deployment it would not be safe: an old pod's ON CONFLICT
		// names the wider predicate (idempotency_key IS NOT NULL), which
		// does not imply this index's narrower one, so Postgres would find
		// no arbiter index and fail every registration with "no unique or
		// exclusion constraint matching the ON CONFLICT specification".
		// The same asymmetry makes this migration forward-only: rolling the
		// image back to a pre-#490 build after it has run breaks device
		// registration until the old index is recreated by hand.
		`DROP INDEX IF EXISTS idx_local_bridge_devices_idempotency_key`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_local_bridge_devices_idem_live ON local_bridge_devices(user_id, idempotency_key) WHERE idempotency_key IS NOT NULL AND revoked_at IS NULL`,
		`CREATE INDEX IF NOT EXISTS idx_local_bridge_devices_user ON local_bridge_devices(user_id) WHERE revoked_at IS NULL`,
	}
}
