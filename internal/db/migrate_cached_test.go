package db

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// dumpSQLite renders everything Migrate leaves in a database: every schema
// object, the schema-level pragmas, and every row of every table.
func dumpSQLite(t *testing.T, conn *sql.DB) []string {
	t.Helper()
	ctx := context.Background()
	var out []string
	rows, err := conn.QueryContext(ctx,
		`SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name`)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var tables []string
	for rows.Next() {
		var typ, name, tbl, ddl string
		if err := rows.Scan(&typ, &name, &tbl, &ddl); err != nil {
			t.Fatalf("scan schema: %v", err)
		}
		out = append(out, fmt.Sprintf("%s %s on %s: %s", typ, name, tbl, ddl))
		if typ == "table" {
			tables = append(tables, name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read schema: %v", err)
	}
	_ = rows.Close()
	for _, pragma := range []string{"user_version", "application_id", "foreign_keys"} {
		var v int
		if err := conn.QueryRowContext(ctx, "PRAGMA "+pragma).Scan(&v); err != nil {
			t.Fatalf("pragma %s: %v", pragma, err)
		}
		out = append(out, fmt.Sprintf("pragma %s = %d", pragma, v))
	}
	for _, table := range tables {
		rows, err := conn.QueryContext(ctx, `SELECT * FROM "`+table+`"`)
		if err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		cols, _ := rows.Columns()
		var lines []string
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatalf("scan %s: %v", table, err)
			}
			cells := make([]string, len(cols))
			for i, v := range vals {
				// The one clock reading Migrate writes. The replay copies the
				// template's, taken when the template was migrated, so it is
				// earlier than a fresh Migrate's and otherwise meaningless.
				if (table == "agent_migrations" && cols[i] == "applied_at") ||
					(table == "acquisition_capture_epoch" && cols[i] == "enabled_at") {
					v = "<time>"
				}
				cells[i] = fmt.Sprintf("%s=%v", cols[i], v)
			}
			lines = append(lines, table+": "+strings.Join(cells, " "))
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		_ = rows.Close()
		sort.Strings(lines)
		out = append(out, lines...)
	}
	return out
}

// The replay is only a stand-in for Migrate if nothing can tell them apart.
func TestMigrateCachedMatchesMigrate(t *testing.T) {
	ctx := context.Background()
	open := func(name string) *sql.DB {
		conn, err := Open(ctx, "file:"+name+"?mode=memory&cache=shared", 0, 0)
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	want := open("migrate_cached_want")
	if err := Migrate(ctx, want); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Twice: the first call may be the one that builds the template.
	for i := 0; i < 2; i++ {
		got := open(fmt.Sprintf("migrate_cached_got_%d", i))
		if err := MigrateCached(ctx, got); err != nil {
			t.Fatalf("MigrateCached #%d: %v", i, err)
		}
		w, g := dumpSQLite(t, want), dumpSQLite(t, got)
		if !reflect.DeepEqual(w, g) {
			for j := 0; j < len(w) || j < len(g); j++ {
				var a, b string
				if j < len(w) {
					a = w[j]
				}
				if j < len(g) {
					b = g[j]
				}
				if a != b {
					t.Fatalf("MigrateCached #%d differs from Migrate at line %d:\nMigrate:       %s\nMigrateCached: %s", i, j, a, b)
				}
			}
		}
		// And it stays a database Migrate accepts as current.
		if err := Migrate(ctx, got); err != nil {
			t.Fatalf("Migrate after MigrateCached #%d: %v", i, err)
		}
		if g2 := dumpSQLite(t, got); !reflect.DeepEqual(g, g2) {
			t.Fatalf("Migrate changed a MigrateCached database #%d", i)
		}
	}
}

// A database that already has a schema is Migrate's to upgrade; replaying
// the template over it would duplicate the rows Migrate wrote.
func TestMigrateCachedLeavesAPopulatedDatabaseToMigrate(t *testing.T) {
	ctx := context.Background()
	conn, err := Open(ctx, "file:migrate_cached_populated?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	before := dumpSQLite(t, conn)
	if err := MigrateCached(ctx, conn); err != nil {
		t.Fatalf("MigrateCached on a migrated database: %v", err)
	}
	if after := dumpSQLite(t, conn); !reflect.DeepEqual(before, after) {
		t.Fatal("MigrateCached changed a database Migrate had already brought up to date")
	}
}

// MigrateCached is exported so other packages' tests can use it, which means
// it is also compiled into the binaries. This keeps it out of their code: a
// production caller would hold a template database open for the life of the
// process and skip the upgrade path Migrate is for.
func TestMigrateCachedHasNoProductionCaller(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == ".git" || name == "vendor" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") ||
			filepath.Base(path) == "migrate_cached.go" {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "MigrateCached(") {
			t.Errorf("%s calls MigrateCached; production code must call Migrate", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}
