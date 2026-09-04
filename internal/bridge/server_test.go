package bridge_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
)

// stubProvider is a minimal auth.Provider used in tests.
type stubProvider struct {
	id  *auth.Identity
	err error
}

func (p *stubProvider) Authenticate(_ *http.Request) (*auth.Identity, error) {
	return p.id, p.err
}

// stubStore is a minimal db.Store stand-in that only implements the one method
// NewBridgeHandler needs. We use the real bridge.NewBridgeHandler signature
// which accepts *db.Store; instead of coupling to SQLite here we inject a
// thin interface via a wrapper that satisfies the handler's call to
// store.GetAccountMode.
//
// Because Go does not allow partial struct satisfaction we build a tiny
// httptest-only shim that wraps a closure.

// accountModeFunc wraps GetAccountMode behind the same signature the handler
// calls so we can inject test behaviour without a live DB.
type accountModeFunc func(ctx context.Context, userID int64) (string, error)

// testServer wires a Hub + stubProvider + mode function together into an
// httptest.Server that mimics the /bridge endpoint.
func testServer(t *testing.T, id *auth.Identity, mode accountModeFunc) (*httptest.Server, *bridge.Hub) {
	t.Helper()
	hub := bridge.NewHub()
	provider := &stubProvider{id: id}

	// We cannot pass a closure directly to NewBridgeHandler because it
	// requires a *db.Store. Instead, inline the handler logic the same way
	// server.go does but substitute the mode check with our closure — this
	// exercises the websocket plumbing end-to-end without needing a DB.
	mux := http.NewServeMux()
	mux.HandleFunc("/bridge", func(w http.ResponseWriter, r *http.Request) {
		rid, err := provider.Authenticate(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if rid == nil {
			http.Error(w, "auth required", http.StatusUnauthorized)
			return
		}
		m, err := mode(r.Context(), rid.UserID)
		if err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		if m != "local" {
			http.Error(w, "account is in hosted mode", http.StatusBadRequest)
			return
		}
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			return
		}
		send := hub.Register(rid.UserID, "")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan struct{}, 2)
		go func() {
			defer func() { done <- struct{}{} }()
			for {
				var env bridge.Envelope
				if err := wsjson.Read(ctx, conn, &env); err != nil {
					return
				}
				switch env.Type {
				case bridge.TypePing:
					_ = wsjson.Write(ctx, conn, bridge.Envelope{Type: bridge.TypePong, ID: env.ID})
				case bridge.TypeResponse, bridge.TypeError:
					hub.Deliver(rid.UserID, env)
				}
			}
		}()
		go func() {
			defer func() { done <- struct{}{} }()
			for {
				select {
				case env, ok := <-send:
					if !ok {
						return
					}
					if err := wsjson.Write(ctx, conn, env); err != nil {
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()
		<-done
		cancel()
		hub.Unregister(rid.UserID)
		_ = conn.Close(websocket.StatusNormalClosure, "done")
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, hub
}

// TestBridgeRoundTrip verifies that a call placed via Hub.Call is forwarded to
// the websocket client as a TypeCall envelope, and that the response the client
// writes back is delivered to the Hub.Call caller.
func TestBridgeRoundTrip(t *testing.T) {
	id := &auth.Identity{UserID: 42, GitHubLogin: "testuser"}
	srv, hub := testServer(t, id, func(_ context.Context, _ int64) (string, error) {
		return "local", nil
	})

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/bridge"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Connect a fake daemon.
	daemonConn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer fake-token"},
		},
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer daemonConn.CloseNow()

	// Poll until the server goroutines have called Register.
	deadline := time.Now().Add(2 * time.Second)
	for !hub.HasDaemon(42) {
		if time.Now().After(deadline) {
			t.Fatal("daemon should be registered after dial")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Simulate a daemon that echoes a successful response.
	go func() {
		var env bridge.Envelope
		if err := wsjson.Read(ctx, daemonConn, &env); err != nil {
			return
		}
		if env.Type != bridge.TypeCall {
			t.Errorf("daemon: expected TypeCall, got %s", env.Type)
			return
		}
		resp := bridge.EncodeResponse(env.ID, json.RawMessage(`{"dialogs":[]}`))
		_ = wsjson.Write(ctx, daemonConn, resp)
	}()

	// Issue a call through the hub.
	callEnv := bridge.EncodeCall("test-1", "list_dialogs", json.RawMessage(`{}`))
	got, err := hub.Call(ctx, 42, callEnv)
	if err != nil {
		t.Fatalf("hub.Call: %v", err)
	}
	if got.Type != bridge.TypeResponse {
		t.Fatalf("expected TypeResponse, got %s", got.Type)
	}
	if string(got.Result) != `{"dialogs":[]}` {
		t.Fatalf("unexpected result: %s", got.Result)
	}
}

// TestBridgeHostedModeRejected verifies that a hosted-mode account cannot
// register a daemon connection.
func TestBridgeHostedModeRejected(t *testing.T) {
	id := &auth.Identity{UserID: 99, GitHubLogin: "hosteduser"}
	srv, _ := testServer(t, id, func(_ context.Context, _ int64) (string, error) {
		return "hosted", nil
	})

	resp, err := http.Get(srv.URL + "/bridge")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}
