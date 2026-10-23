package db

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
)

// MigrateCached is Migrate for tests. Production code calls Migrate.
//
// On an empty SQLite database it produces the schema and rows Migrate would,
// by replaying them from a template migrated once per process, instead of
// running every step again. Migrate on a fresh SQLite database is dominated
// by its ALTER TABLE ADD COLUMN passes, each of which makes SQLite reparse the
// whole schema; under -race that is about 0.35 s, paid by several hundred
// test stores per CI run. The replay is the template's final DDL (which
// already carries the added columns) plus a copy of whatever rows Migrate
// wrote, so it is the same database without the history.
//
// Anything else gets plain Migrate: Postgres, a database that already holds
// a schema (the upgrade tests), and a call with TTL-exempt identities. That
// TestMigrateCachedMatchesMigrate compares the two byte for byte is what
// makes the replay safe to use in place of Migrate.
func MigrateCached(ctx context.Context, dbConn *sql.DB, ttlExemptTelegramIDs ...int64) error {
	if len(ttlExemptTelegramIDs) > 0 {
		return Migrate(ctx, dbConn, ttlExemptTelegramIDs...)
	}
	var objects int
	if err := dbConn.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master`).Scan(&objects); err != nil || objects > 0 {
		// Not SQLite (Postgres has no sqlite_master), or not empty.
		return Migrate(ctx, dbConn)
	}
	tpl, err := loadMigrateTemplate(ctx)
	if err != nil {
		return err
	}
	return tpl.apply(ctx, dbConn)
}

// migrateTemplate is a database Migrate ran on, kept open for the life of
// the process so apply can ATTACH it by name.
type migrateTemplate struct {
	db     *sql.DB
	uri    string
	ddl    []string // sqlite_master.sql in creation order
	tables []string // tables Migrate wrote rows into
}

var (
	migrateTemplateOnce sync.Once
	migrateTemplateVal  *migrateTemplate
	migrateTemplateErr  error
)

func loadMigrateTemplate(ctx context.Context) (*migrateTemplate, error) {
	migrateTemplateOnce.Do(func() {
		migrateTemplateVal, migrateTemplateErr = buildMigrateTemplate(context.WithoutCancel(ctx))
	})
	return migrateTemplateVal, migrateTemplateErr
}

func buildMigrateTemplate(ctx context.Context) (*migrateTemplate, error) {
	uri := "file:mctl_migrate_template?mode=memory&cache=shared"
	conn, err := Open(ctx, uri, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("migrate template: %w", err)
	}
	if err := Migrate(ctx, conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("migrate template: %w", err)
	}
	t := &migrateTemplate{db: conn, uri: uri}
	// sqlite_autoindex_* rows have no sql (they come with their table), and
	// sqlite_sequence is created by the first AUTOINCREMENT table.
	rows, err := conn.QueryContext(ctx,
		`SELECT type, name, sql FROM sqlite_master
		 WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY rowid`)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("migrate template: read schema: %w", err)
	}
	var tables []string
	for rows.Next() {
		var typ, name, ddl string
		if err := rows.Scan(&typ, &name, &ddl); err != nil {
			_ = rows.Close()
			_ = conn.Close()
			return nil, fmt.Errorf("migrate template: read schema: %w", err)
		}
		t.ddl = append(t.ddl, ddl)
		if typ == "table" {
			tables = append(tables, name)
		}
	}
	if err := rows.Close(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("migrate template: read schema: %w", err)
	}
	if err := rows.Err(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("migrate template: read schema: %w", err)
	}
	// sqlite_sequence is not copied: Migrate writes no AUTOINCREMENT rows.
	// If it ever does, TestMigrateCachedMatchesMigrate sees the table differ.
	for _, name := range tables {
		var n int
		if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM "`+name+`"`).Scan(&n); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("migrate template: count %s: %w", name, err)
		}
		if n > 0 {
			t.tables = append(t.tables, name)
		}
	}
	return t, nil
}

func (t *migrateTemplate) apply(ctx context.Context, dbConn *sql.DB) error {
	// ATTACH is per connection, so the copy runs on one.
	c, err := dbConn.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrate from template: %w", err)
	}
	defer c.Close()
	tx, err := c.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrate from template: %w", err)
	}
	for _, ddl := range t.ddl {
		if _, err := tx.ExecContext(ctx, ddl); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrate from template: %w\nstmt: %s", err, ddl)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrate from template: %w", err)
	}
	if len(t.tables) == 0 {
		return nil
	}
	if _, err := c.ExecContext(ctx, `ATTACH DATABASE '`+t.uri+`' AS migrate_template`); err != nil {
		return fmt.Errorf("migrate from template: attach: %w", err)
	}
	var copyErr error
	for _, name := range t.tables {
		q := fmt.Sprintf(`INSERT INTO main."%s" SELECT * FROM migrate_template."%s"`, name, name)
		if _, err := c.ExecContext(ctx, q); err != nil {
			copyErr = fmt.Errorf("migrate from template: copy %s: %w", name, err)
			break
		}
	}
	if _, err := c.ExecContext(ctx, `DETACH DATABASE migrate_template`); err != nil && copyErr == nil {
		copyErr = fmt.Errorf("migrate from template: detach: %w", err)
	}
	return copyErr
}
