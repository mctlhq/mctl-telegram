package db

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// countingDriver is a database/sql driver that is neither pgx nor modernc
// sqlite. It refuses every connection and counts the attempts, so a test
// can tell whether anything ran SQL against it.
type countingDriver struct{ opens atomic.Int64 }

func (d *countingDriver) Open(string) (driver.Conn, error) {
	d.opens.Add(1)
	return nil, errors.New("counting driver: no connections")
}

var unknownDriver = &countingDriver{}

func init() { sql.Register("mctl-test-unknown", unknownDriver) }

// TestMigrate_UnknownDriverFailsClosed: Migrate on a pool whose driver is
// neither Postgres nor SQLite returns an error before touching the
// database. It must not guess a dialect (an earlier SQL probe read any
// failed probe as "SQLite", so a transient error on Postgres ran the
// SQLite DDL without the migration lock).
func TestMigrate_UnknownDriverFailsClosed(t *testing.T) {
	conn, err := sql.Open("mctl-test-unknown", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	before := unknownDriver.opens.Load()
	err = Migrate(context.Background(), conn)
	if err == nil || !strings.Contains(err.Error(), "unsupported database driver") {
		t.Fatalf("Migrate on an unknown driver = %v, want an unsupported-driver error", err)
	}
	if n := unknownDriver.opens.Load() - before; n != 0 {
		t.Fatalf("Migrate opened %d connections on an unknown driver; it must decide the dialect without I/O", n)
	}
}

// TestDialectOf: the pools Open returns are told apart by their driver.
func TestDialectOf(t *testing.T) {
	ctx := context.Background()
	lite, err := Open(ctx, fmt.Sprintf("file:dialect_%d?mode=memory&cache=shared", time.Now().UnixNano()), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lite.Close() })
	if pg, err := dialectOf(lite); err != nil || pg {
		t.Fatalf("sqlite pool: pg=%v err=%v", pg, err)
	}
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		return
	}
	pool, err := Open(ctx, dsn, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if pg, err := dialectOf(pool); err != nil || !pg {
		t.Fatalf("postgres pool: pg=%v err=%v", pg, err)
	}
}
