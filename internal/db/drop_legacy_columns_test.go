package db

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

func columnPresent(t *testing.T, conn *sql.DB, table, column string) bool {
	t.Helper()
	var n int
	if err := conn.QueryRowContext(context.Background(),
		`SELECT count(*) FROM pragma_table_info(?) WHERE name = ?`,
		table, column,
	).Scan(&n); err != nil {
		t.Fatalf("pragma table_info(%s): %v", table, err)
	}
	return n > 0
}

func openMigrated(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	conn, err := Open(context.Background(), dsn, 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(context.Background(), conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return conn
}

// TestMigrate_DropsBridgeTokenHashFromALegacyDatabase is the half that matters
// in production: the column exists on every database migrated before this
// change, and a schema declaration DESIGN.md called load-bearing has to
// actually leave when the doc stops claiming it.
//
// The column is added back by hand rather than fabricating a whole legacy
// schema: `ALTER TABLE ... ADD COLUMN bridge_token_hash BLOB` is byte for byte
// what the removed addColumnIfMissing call used to run, so the state under
// test is the real one.
func TestMigrate_DropsBridgeTokenHashFromALegacyDatabase(t *testing.T) {
	ctx := context.Background()
	conn := openMigrated(t, "file:"+t.Name()+"?mode=memory&cache=shared")

	if _, err := conn.ExecContext(ctx,
		`ALTER TABLE telegram_accounts ADD COLUMN bridge_token_hash BLOB`); err != nil {
		t.Fatalf("recreate the legacy column: %v", err)
	}
	if !columnPresent(t, conn, "telegram_accounts", "bridge_token_hash") {
		t.Fatal("the legacy column was not actually recreated; the test proves nothing")
	}

	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate over a legacy database: %v", err)
	}
	if columnPresent(t, conn, "telegram_accounts", "bridge_token_hash") {
		t.Error("bridge_token_hash survived the migration on a database that had it")
	}
}

// TestMigrate_BridgeTokenHashAbsentAndDropIsIdempotent covers the fresh
// database and the second boot. Migrate runs on every start, so a drop that
// only works when the column is there would turn every restart after the first
// into a failed migration and a pod that never becomes ready.
func TestMigrate_BridgeTokenHashAbsentAndDropIsIdempotent(t *testing.T) {
	ctx := context.Background()
	conn := openMigrated(t, "file:"+t.Name()+"?mode=memory&cache=shared")

	if columnPresent(t, conn, "telegram_accounts", "bridge_token_hash") {
		t.Fatal("a freshly created telegram_accounts still declares bridge_token_hash")
	}
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, conn); err != nil {
			t.Fatalf("re-migrate %d: %v", i, err)
		}
	}
	if columnPresent(t, conn, "telegram_accounts", "bridge_token_hash") {
		t.Error("bridge_token_hash reappeared across re-migrations")
	}
}

// TestMigrate_DropKeepsTheRowsAndTheSiblingColumns pins the blast radius. On
// SQLite an ALTER TABLE ... DROP COLUMN rewrites the table, so the failure mode
// worth guarding is not "the column stayed" but "everything else went with it":
// mode is the live Local Bridge switch and sits directly beside the dropped
// column in the schema.
func TestMigrate_DropKeepsTheRowsAndTheSiblingColumns(t *testing.T) {
	ctx := context.Background()
	conn := openMigrated(t, "file:"+t.Name()+"?mode=memory&cache=shared")

	if _, err := conn.ExecContext(ctx,
		`ALTER TABLE telegram_accounts ADD COLUMN bridge_token_hash BLOB`); err != nil {
		t.Fatalf("recreate the legacy column: %v", err)
	}
	var uid int64
	if err := conn.QueryRowContext(ctx,
		`INSERT INTO users(github_login, provider) VALUES ('alice', 'test') RETURNING id`,
	).Scan(&uid); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, display_name, username,
		                               session_encrypted, mode, send_enabled, bridge_token_hash)
		 VALUES ($1, 42, 'Alice', 'alice_tg', NULL, $2, 0, X'0badc0de')`,
		uid, ModeLocal); err != nil {
		t.Fatalf("insert account: %v", err)
	}

	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate over a legacy database: %v", err)
	}

	var mode, username string
	var tgID int64
	if err := conn.QueryRowContext(ctx,
		`SELECT mode, username, telegram_user_id FROM telegram_accounts WHERE user_id = $1`,
		uid).Scan(&mode, &username, &tgID); err != nil {
		t.Fatalf("the account row did not survive the drop: %v", err)
	}
	if mode != ModeLocal {
		t.Errorf("mode = %q after the drop, want %q", mode, ModeLocal)
	}
	if username != "alice_tg" || tgID != 42 {
		t.Errorf("row contents changed across the drop: username=%q tgID=%d", username, tgID)
	}
}

// TestDropColumnIfPresent_Postgres covers the dialect the SQLite tests cannot
// reach. Following db_test.go's convention it runs only when TEST_DATABASE_URL
// is set, so it is a local/opt-in check rather than a CI gate.
//
// The property under test is not just "the column goes" but "the steady state
// issues no DDL": Migrate runs on every pod start, and an unconditional
// `ALTER TABLE ... DROP COLUMN IF EXISTS` takes its ACCESS EXCLUSIVE lock
// before discovering there is nothing to drop. So the second call is checked
// through pg_stat, by asserting the table's last DDL did not move.
func TestDropColumnIfPresent_Postgres(t *testing.T) {
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

	if _, err := conn.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS drop_probe (id BIGSERIAL PRIMARY KEY, keep TEXT)`); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	t.Cleanup(func() { _, _ = conn.ExecContext(context.Background(), `DROP TABLE IF EXISTS drop_probe`) })
	if _, err := conn.ExecContext(ctx,
		`ALTER TABLE drop_probe ADD COLUMN IF NOT EXISTS legacy BYTEA`); err != nil {
		t.Fatalf("add the legacy column: %v", err)
	}

	present, err := columnExists(ctx, conn, true, "drop_probe", "legacy")
	if err != nil {
		t.Fatalf("columnExists: %v", err)
	}
	if !present {
		t.Fatal("the Postgres catalog lookup does not see a column that is really there")
	}

	if err := dropColumnIfPresent(ctx, conn, true, "drop_probe", "legacy"); err != nil {
		t.Fatalf("drop: %v", err)
	}
	present, err = columnExists(ctx, conn, true, "drop_probe", "legacy")
	if err != nil {
		t.Fatalf("columnExists after the drop: %v", err)
	}
	if present {
		t.Fatal("the column survived the drop")
	}

	keep, err := columnExists(ctx, conn, true, "drop_probe", "keep")
	if err != nil {
		t.Fatalf("columnExists(keep): %v", err)
	}
	if !keep {
		t.Error("the drop took a sibling column with it")
	}

	// The steady state -- every pod boot after the first -- must take no table
	// lock, and this is the assertion that actually pins it rather than
	// restating the intent. Another session holds an ACCESS SHARE lock on the
	// table for the duration; a bare ALTER TABLE ... DROP COLUMN IF EXISTS
	// needs ACCESS EXCLUSIVE, which conflicts, so it would queue behind that
	// lock and hit lock_timeout. The catalog pre-check never asks for the lock,
	// so it returns immediately.
	holder, err := conn.Conn(ctx)
	if err != nil {
		t.Fatalf("holder conn: %v", err)
	}
	defer func() { _ = holder.Close() }()
	tx, err := holder.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("holder begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT 1 FROM drop_probe`); err != nil {
		t.Fatalf("holder take ACCESS SHARE: %v", err)
	}

	// One connection, so the session-level lock_timeout applies to the call.
	dropper, err := Open(ctx, dsn, 1, 1)
	if err != nil {
		t.Fatalf("dropper open: %v", err)
	}
	defer func() { _ = dropper.Close() }()
	if _, err := dropper.ExecContext(ctx, `SET lock_timeout = '2s'`); err != nil {
		t.Fatalf("set lock_timeout: %v", err)
	}

	if err := dropColumnIfPresent(ctx, dropper, true, "drop_probe", "legacy"); err != nil {
		t.Fatalf("the steady-state call waited on a table lock instead of reading the catalog: %v", err)
	}
}
