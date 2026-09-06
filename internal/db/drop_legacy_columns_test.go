package db

import (
	"context"
	"database/sql"
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
		 VALUES ($1, 42, 'Dmitry', 'MashkovD', NULL, $2, 0, X'0badc0de')`,
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
	if username != "MashkovD" || tgID != 42 {
		t.Errorf("row contents changed across the drop: username=%q tgID=%d", username, tgID)
	}
}
