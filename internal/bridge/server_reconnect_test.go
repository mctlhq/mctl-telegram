package bridge_test

import (
	"context"
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
)

// TestBridgeReconnect verifies that after a server-side connection drop the hub
// correctly accepts a new daemon registration and continues to serve calls.
//
// Steps:
//  1. Connect fake daemon A; verify a round-trip call succeeds.
//  2. Force-close the server-side websocket (by dropping daemon A's send channel
//     via Hub.Unregister which makes the server-side writer goroutine exit).
//  3. Connect fake daemon B; verify a round-trip call succeeds.
//  4. Verify no goroutine leak: the goroutine count after cleanup should not
//     grow unboundedly compared to the count at test start.
func TestBridgeReconnect(t *testing.T) {
	goroutinesBefore := runtime.NumGoroutine()

	id := &auth.Identity{UserID: 55, GitHubLogin: "reconnect-user"}
	srv, hub := testServer(t, id, func(_ context.Context, _ int64) (string, error) {
		return "local", nil
	})

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/bridge"

	// --- Step 1: Connect daemon A and verify a round-trip call ---

	ctx1, cancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel1()

	daemonA, _, err := websocket.Dial(ctx1, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer fake-token"}},
	})
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}

	// Wait for daemon A to register.
	waitForDaemon(t, hub, 55, true, 2*time.Second)

	// Drive daemon A: read the call, send a response.
	go func() {
		var env bridge.Envelope
		if err := wsjson.Read(ctx1, daemonA, &env); err != nil {
			return
		}
		if env.Type != bridge.TypeCall {
			t.Errorf("daemon A: expected TypeCall, got %s", env.Type)
			return
		}
		resp := bridge.EncodeResponse(env.ID, json.RawMessage(`{"step":1}`))
		_ = wsjson.Write(ctx1, daemonA, resp)
	}()

	callEnv := bridge.EncodeCall("step1", "list_dialogs", json.RawMessage(`{}`))
	got, err := hub.Call(ctx1, 55, callEnv)
	if err != nil {
		t.Fatalf("step 1 call: %v", err)
	}
	if got.Type != bridge.TypeResponse {
		t.Fatalf("step 1: expected TypeResponse, got %s", got.Type)
	}
	if string(got.Result) != `{"step":1}` {
		t.Fatalf("step 1: unexpected result: %s", got.Result)
	}

	// --- Step 2: Force-close the server-side connection for daemon A ---
	// CloseNow drops the TCP connection from the client side, which makes the
	// server-side wsjson.Read return an error. The server handler then calls
	// hub.Unregister, removing daemon A.
	daemonA.CloseNow()

	// Wait for the hub to unregister daemon A.
	waitForDaemon(t, hub, 55, false, 2*time.Second)

	// --- Step 3: Connect daemon B and verify a round-trip call ---

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	daemonB, _, err := websocket.Dial(ctx2, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer fake-token"}},
	})
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer daemonB.CloseNow()

	// Wait for daemon B to register.
	waitForDaemon(t, hub, 55, true, 2*time.Second)

	// Drive daemon B.
	go func() {
		var env bridge.Envelope
		if err := wsjson.Read(ctx2, daemonB, &env); err != nil {
			return
		}
		if env.Type != bridge.TypeCall {
			t.Errorf("daemon B: expected TypeCall, got %s", env.Type)
			return
		}
		resp := bridge.EncodeResponse(env.ID, json.RawMessage(`{"step":2}`))
		_ = wsjson.Write(ctx2, daemonB, resp)
	}()

	callEnv2 := bridge.EncodeCall("step2", "list_dialogs", json.RawMessage(`{}`))
	got2, err := hub.Call(ctx2, 55, callEnv2)
	if err != nil {
		t.Fatalf("step 2 call: %v", err)
	}
	if got2.Type != bridge.TypeResponse {
		t.Fatalf("step 2: expected TypeResponse, got %s", got2.Type)
	}
	if string(got2.Result) != `{"step":2}` {
		t.Fatalf("step 2: unexpected result: %s", got2.Result)
	}

	// --- Step 4: Verify no goroutine leak ---
	// Close daemon B cleanly so its server-side goroutines exit.
	daemonB.Close(websocket.StatusNormalClosure, "done")
	waitForDaemon(t, hub, 55, false, 2*time.Second)

	// Give goroutines time to exit.
	time.Sleep(100 * time.Millisecond)

	goroutinesAfter := runtime.NumGoroutine()
	// Allow a small slack for background goroutines added by the test
	// runtime (GC, timers, etc.) — the count should not grow by more than
	// 10 compared to the baseline taken before this test started.
	if goroutinesAfter > goroutinesBefore+10 {
		t.Errorf("potential goroutine leak: %d goroutines before, %d after (slack 10)",
			goroutinesBefore, goroutinesAfter)
	}
}

// waitForDaemon polls hub.HasDaemon(userID) until it reaches want or the
// timeout elapses. Fails the test if the condition is not met in time.
func waitForDaemon(t *testing.T, hub *bridge.Hub, userID int64, want bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if hub.HasDaemon(userID) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for HasDaemon(%d) == %v", userID, want)
}
