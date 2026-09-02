package bridge_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// newProvisionTestStore opens an in-memory SQLite DB and applies the schema,
// mirroring internal/db's own newTestStore helper (unexported, so it cannot
// be reused directly from this external test package).
func newProvisionTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &db.Store{DB: conn}
}

// TestBridgeHandler_AcceptsProvisionedLocalAccount is the real end-to-end
// counterpart of TestGetAccountMode_SurvivesRevocationWhenLocal: an account
// that was created ONLY via Store.ProvisionLocalAccount -- no hosted login
// ever performed -- must be accepted by the real NewBridgeHandler, exercising
// the actual GetAccountMode call it makes rather than a stubbed-out one.
func TestBridgeHandler_AcceptsProvisionedLocalAccount(t *testing.T) {
	ctx := context.Background()
	store := newProvisionTestStore(t)

	const tgID = 700000010
	uid, err := store.EnsureUserByTelegramID(ctx, tgID, "bridgeonly", "Bridge Only")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := store.ProvisionLocalAccount(ctx, uid, tgID, "Bridge Only", "bridgeonly"); err != nil {
		t.Fatalf("provision local account: %v", err)
	}

	provider := &stubProvider{id: &auth.Identity{UserID: uid, Subject: "tg:700000010"}}
	hub := bridge.NewHub()
	handler := bridge.NewBridgeHandler(hub, provider, store, context.Background())

	srv := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(srv.Close)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/bridge"
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer fake-token"}},
	})
	if err != nil {
		t.Fatalf("expected a provisioned local-only account to be accepted, dial failed: %v", err)
	}
	defer conn.CloseNow()

	deadline := time.Now().Add(2 * time.Second)
	for !hub.HasDaemon(uid) {
		if time.Now().After(deadline) {
			t.Fatal("daemon should be registered after a successful dial")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
