package mcp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	sqlite "modernc.org/sqlite"
)

// The account row must be read exactly once per get_my_send_status call, with
// the verdict and the booleans both derived from that one snapshot. Two reads
// would let a concurrent set_account_send toggle land between them and produce
// a self-contradicting answer — can_send=false because send_enabled was false,
// printed next to send_enabled=true.
//
// A race is not reproducible on demand, so the invariant is enforced on the
// property that causes it: the number of SELECTs against telegram_accounts.
// modernc.org/sqlite exposes NewConnector precisely so callers can interpose
// on the driver this way.

type countingConnector struct {
	inner driver.Connector
	n     *int32
}

func (c countingConnector) Connect(ctx context.Context) (driver.Conn, error) {
	cn, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: cn, n: c.n}, nil
}

func (c countingConnector) Driver() driver.Driver { return c.inner.Driver() }

type countingConn struct {
	driver.Conn
	n *int32
}

// countAccountSelect records reads of the account row and ignores everything
// else, so unrelated queries (migrations, user lookups) cannot mask a
// regression here.
func countAccountSelect(n *int32, query string) {
	q := strings.ToUpper(strings.TrimSpace(query))
	if strings.HasPrefix(q, "SELECT") && strings.Contains(q, "TELEGRAM_ACCOUNTS") {
		atomic.AddInt32(n, 1)
	}
}

func (c *countingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	q, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		// Let database/sql fall back to the prepare path, which counts below.
		return nil, driver.ErrSkip
	}
	countAccountSelect(c.n, query)
	return q.QueryContext(ctx, query, args)
}

func (c *countingConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	countAccountSelect(c.n, query)
	if p, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return p.PrepareContext(ctx, query)
	}
	return c.Conn.Prepare(query)
}

func newCountingStore(t *testing.T, dsn string) (*db.Store, *int32) {
	t.Helper()
	inner, err := sqlite.NewConnector(dsn)
	if err != nil {
		t.Fatalf("NewConnector: %v", err)
	}
	var n int32
	conn := sql.OpenDB(countingConnector{inner: inner, n: &n})
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(context.Background(), conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &db.Store{DB: conn}, &n
}

func TestGetMySendStatus_ReadsTheAccountRowExactlyOnce(t *testing.T) {
	store, reads := newCountingStore(t, "file:sendstatus-reads?mode=memory&cache=shared")
	uid := seedHostedAccount(t, store, 4747, false)
	srv := &Server{AllowSend: true, Store: store}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	atomic.StoreInt32(reads, 0)
	out := parseSendStatus(t, callSendStatus(t, srv, id))

	if got := atomic.LoadInt32(reads); got != 1 {
		t.Errorf("account row read %d times, want exactly 1 — the verdict and the\nreported booleans must come from one snapshot", got)
	}
	// The snapshot must also actually be the one reported on, not a read whose
	// result was discarded.
	if out["can_send"] != false || out["send_enabled"] != false {
		t.Errorf("can_send=%v send_enabled=%v, want both false", out["can_send"], out["send_enabled"])
	}
}
