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

type pausedProvider struct {
	id            *auth.Identity
	authenticated chan struct{}
	release       chan struct{}
}

func (p *pausedProvider) Authenticate(*http.Request) (*auth.Identity, error) {
	close(p.authenticated)
	<-p.release
	return p.id, nil
}

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
	deviceID, err := store.RegisterDevice(ctx, uid, "bridge-only", "bridge-only", nil)
	if err != nil {
		t.Fatalf("register device: %v", err)
	}

	provider := &stubProvider{id: &auth.Identity{UserID: uid, Subject: "tg:700000010", DeviceID: deviceID}}
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

func TestBridgeHandler_RevocationDuringAuthenticationCannotRegister(t *testing.T) {
	ctx := context.Background()
	store := newProvisionTestStore(t)
	const tgID = 700000011
	uid, err := store.EnsureUserByTelegramID(ctx, tgID, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := store.ProvisionLocalAccount(ctx, uid, tgID, "Alice", "alice"); err != nil {
		t.Fatalf("provision local account: %v", err)
	}
	deviceID, err := store.RegisterDevice(ctx, uid, "alice-device", "alice-device", nil)
	if err != nil {
		t.Fatalf("register device: %v", err)
	}

	provider := &pausedProvider{
		id:            &auth.Identity{UserID: uid, TelegramID: tgID, Subject: "tg:700000011", DeviceID: deviceID},
		authenticated: make(chan struct{}),
		release:       make(chan struct{}),
	}
	hub := bridge.NewHub()
	admitted := make(chan struct{})
	releaseAdmission := make(chan struct{})
	srv := httptest.NewServer(bridge.NewBridgeHandlerWithAdmissionHook(hub, provider, store, context.Background(), func() {
		close(admitted)
		<-releaseAdmission
	}))
	t.Cleanup(srv.Close)

	type dialResult struct {
		conn *websocket.Conn
		err  error
	}
	dialed := make(chan dialResult, 1)
	go func() {
		conn, _, dialErr := websocket.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		dialed <- dialResult{conn: conn, err: dialErr}
	}()
	<-provider.authenticated
	// Let authentication and the durable pre-upgrade check complete, then
	// pause at the exact check-to-registration window that revocation must
	// close.
	close(provider.release)
	<-admitted
	if _, err := store.RevokeDeviceAndDenylist(ctx, deviceID, tgID, "test revoke", uid); err != nil {
		t.Fatalf("revoke device: %v", err)
	}
	hub.BlockDevice(uid, deviceID)
	close(releaseAdmission)

	result := <-dialed
	if result.conn != nil {
		result.conn.CloseNow()
	}
	// The upgrade may fail before the hook depending on timing; that is also
	// a valid fail-closed outcome. A successful upgrade must still not leave a
	// routable hub entry.
	if hub.HasDaemon(uid) {
		t.Fatal("revoked device became routable after eviction")
	}
}
