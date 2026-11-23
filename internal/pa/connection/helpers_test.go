package connection_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
)

// Test ids in this package are the threat model's
// (docs/agent-runtime/personal-assistant-threat-model.md): S1-C*, S1-K1,
// S1-T9, S1-T10, S1-X1. Every acceptance test runs against the real
// internal/db store, on SQLite always and on Postgres when TEST_DATABASE_URL
// is set (CI sets it).

// forEachDialect runs fn once per available database dialect.
func forEachDialect(t *testing.T, fn func(t *testing.T, s *db.Store)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) { fn(t, newSQLiteStore(t)) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		fn(t, newPostgresStore(t, dsn))
	})
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func newSQLiteStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:pa_conn_"+randHex(t, 8)+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &db.Store{DB: conn}
}

func newPostgresStore(t *testing.T, dsn string) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, dsn, 5, 2)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	return &db.Store{DB: conn}
}

// principals returns two synthetic principals, Alice and Bob, unique per
// test so tests sharing one Postgres database never see each other's rows.
// They are not real Telegram ids.
func principals(t *testing.T, s *db.Store) (alice, bob int64) {
	t.Helper()
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000_000))
	if err != nil {
		t.Fatal(err)
	}
	alice = 9_000_000_000 + n.Int64()*2
	bob = alice + 1
	t.Cleanup(func() {
		_, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal IN ($1, $2)`, alice, bob)
	})
	acceptConsent(t, s, alice)
	acceptConsent(t, s, bob)
	return alice, bob
}

// acceptConsent records principal's current data-flow consent, which
// activation (pending_confirm -> active) requires under the principal lock.
func acceptConsent(t *testing.T, s *db.Store, principal int64) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AcceptPAConsent(ctx, tx, principal, convo.ConsentVersion, convo.ConsentTextSHA256(), time.Now()); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_consents WHERE principal = $1`, principal) })
}

type revokeCall struct {
	Server connection.Server
	Token  string
	Hint   connection.TokenHint
}

type fakeRevoker struct {
	mu    sync.Mutex
	calls []revokeCall
	err   error
}

func (r *fakeRevoker) Revoke(_ context.Context, server connection.Server, token connection.Secret, hint connection.TokenHint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, revokeCall{server, token.Reveal(), hint})
	return r.err
}

func (r *fakeRevoker) revoked() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, c := range r.calls {
		out = append(out, c.Token)
	}
	return out
}

type fakeAuditor struct {
	mu     sync.Mutex
	events []connection.FenceEvent
}

func (a *fakeAuditor) RecordFenced(_ context.Context, ev connection.FenceEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

func (a *fakeAuditor) all() []connection.FenceEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]connection.FenceEvent(nil), a.events...)
}

var testKEKKey = []byte("0123456789abcdef0123456789abcdef")

type env struct {
	store   connection.Store
	db      *db.Store
	m       *connection.Manager
	revoker *fakeRevoker
	auditor *fakeAuditor
}

func newEnv(t *testing.T, s *db.Store) *env {
	t.Helper()
	return newEnvWithStore(t, s, s)
}

func newEnvWithStore(t *testing.T, raw *db.Store, store connection.Store) *env {
	t.Helper()
	kek, err := connection.NewLocalKEK(testKEKKey, "test")
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	e := &env{store: store, db: raw, revoker: &fakeRevoker{}, auditor: &fakeAuditor{}}
	e.m, err = connection.NewManager(connection.Config{Store: store, KEK: kek, Revoker: e.revoker, Auditor: e.auditor})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
	return e
}

// tokenResponse is a fake authorization server's token response. Token
// values carry the fake-token pattern S1-K1 scans for.
func tokenResponse(access, refresh, scope string) []byte {
	parts := []string{`"access_token":"` + access + `"`, `"token_type":"Bearer"`, `"expires_in":3600`}
	if refresh != "" {
		parts = append(parts, `"refresh_token":"`+refresh+`"`)
	}
	if scope != "" {
		parts = append(parts, `"scope":"`+scope+`"`)
	}
	return []byte("{" + strings.Join(parts, ",") + "}")
}

const tgScope = "telegram:dialogs:read telegram:messages:read"

// toPendingReturn drives a new connection to pending_return.
func (e *env) toPendingReturn(t *testing.T, principal int64, server connection.Server) connection.Connection {
	t.Helper()
	ctx := context.Background()
	c, err := e.m.Begin(ctx, principal, server)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if c, err = e.m.StartOAuth(ctx, principal, c.ID, c.AuthorityRevision); err != nil {
		t.Fatalf("start oauth: %v", err)
	}
	if c, err = e.m.StoreAuthorizationCode(ctx, principal, c.ID, c.AuthorityRevision, connection.NewSecret("fake-code-"+c.ID)); err != nil {
		t.Fatalf("store code: %v", err)
	}
	return c
}

// toActive drives a new tg connection to active with fake tokens.
func (e *env) toActive(t *testing.T, principal int64) connection.Connection {
	t.Helper()
	ctx := context.Background()
	c := e.toPendingReturn(t, principal, connection.ServerTG)
	c, err := e.m.CompleteExchange(ctx, principal, c.ID, c.AuthorityRevision, "acct-alice",
		tokenResponse("fake-at-1-"+c.ID, "fake-rt-1-"+c.ID, tgScope))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if c, err = e.m.Confirm(ctx, principal, c.ID, c.AuthorityRevision); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if c.State != connection.StateActive {
		t.Fatalf("state %s, want active", c.State)
	}
	return c
}

// failingStore wraps a Store and fails the reads named in failReads.
type failingStore struct {
	connection.Store
	mu        sync.Mutex
	failReads bool
}

var errInjected = errors.New("injected store error")

func (f *failingStore) setFail(v bool) { f.mu.Lock(); f.failReads = v; f.mu.Unlock() }
func (f *failingStore) failing() bool  { f.mu.Lock(); defer f.mu.Unlock(); return f.failReads }

func (f *failingStore) GetPAConnection(ctx context.Context, p int64, id string) (connection.Connection, error) {
	if f.failing() {
		return connection.Connection{}, errInjected
	}
	return f.Store.GetPAConnection(ctx, p, id)
}

func (f *failingStore) GetPAConnectionSealed(ctx context.Context, p int64, id string) (connection.Connection, connection.Sealed, error) {
	if f.failing() {
		return connection.Connection{}, connection.Sealed{}, errInjected
	}
	return f.Store.GetPAConnectionSealed(ctx, p, id)
}

func (f *failingStore) ListPAConnections(ctx context.Context, p int64) ([]connection.Connection, error) {
	if f.failing() {
		return nil, errInjected
	}
	return f.Store.ListPAConnections(ctx, p)
}

// withLease rebuilds e's manager with a refresh lease of d.
func (e *env) withLease(t *testing.T, d time.Duration) {
	t.Helper()
	kek, err := connection.NewLocalKEK(testKEKKey, "test")
	if err != nil {
		t.Fatalf("kek: %v", err)
	}
	e.m, err = connection.NewManager(connection.Config{
		Store: e.store, KEK: kek, Revoker: e.revoker, Auditor: e.auditor, RefreshLease: d,
	})
	if err != nil {
		t.Fatalf("manager: %v", err)
	}
}
