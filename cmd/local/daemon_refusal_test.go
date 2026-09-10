package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// legacyTokenOnDisk writes a legacy-path bridge_token.json (no device
// credential on disk, so runDaemon takes the connect --token branch) whose
// bridge token expired an hour ago and therefore needs a refresh first.
func legacyTokenOnDisk(t *testing.T) {
	t.Helper()
	expired := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := saveBridgeToken(&bridgeTokenFile{MCPToken: "legacy.mcp.token", BridgeToken: "old.bridge.token", ExpiresAt: expired}); err != nil {
		t.Fatalf("saveBridgeToken: %v", err)
	}
}

// A 403 from the token endpoint is the server's verdict on the stored
// credential, not a blip: retrying cannot change it, and dialing /bridge
// with the expired bridge token only adds a 401 to the server's log per
// retry. This is the shape of #612 -- a legacy daemon after device binding
// became mandatory -- and the daemon must exit saying what to do, not loop.
func TestRunDaemon_RefusedRefreshExitsNamingTheFix(t *testing.T) {
	dir := t.TempDir()
	setHome(t, dir)
	legacyTokenOnDisk(t)

	var bridgeDials atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/bridge/token":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"device-bound credential required; run activate to register this device"}`))
		case "/bridge":
			bridgeDials.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := runDaemon(ctx, &localConfig{Server: srv.URL}, nil, 1, nil)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("daemon kept looping on a refused refresh instead of exiting: err=%v", err)
	}
	if !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("exit error does not name the refusal: %v", err)
	}
	if n := bridgeDials.Load(); n != 0 {
		t.Fatalf("daemon dialed /bridge %d times with a token it knew was expired", n)
	}
}

// A transient failure of the token endpoint (here a 503) with a bridge token
// that has already lapsed must keep retrying -- the endpoint may come back --
// but must not dial /bridge in the meantime: that connection is refused with
// certainty and only produces the per-minute 401 the server-side log showed.
func TestRunDaemon_TransientRefreshFailureWithExpiredTokenWaitsWithoutDialing(t *testing.T) {
	dir := t.TempDir()
	setHome(t, dir)
	legacyTokenOnDisk(t)

	var bridgeDials, tokenCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/bridge/token":
			tokenCalls.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("no available server"))
		case "/bridge":
			bridgeDials.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// reconnectBase is 2s; a 5s window allows two refresh attempts.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := runDaemon(ctx, &localConfig{Server: srv.URL}, nil, 1, nil)
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon gave up on a transient failure: %v", err)
	}
	if n := tokenCalls.Load(); n < 2 {
		t.Fatalf("expected the daemon to keep retrying the refresh, saw %d attempts", n)
	}
	if n := bridgeDials.Load(); n != 0 {
		t.Fatalf("daemon dialed /bridge %d times while its token was expired and the refresh was failing", n)
	}
}

// The verdict is read from the status, not the body: a 401 is a refusal
// too, and anything else from the endpoint is treated as transient.
func TestIsRefusedRefresh(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{&tokenEndpointError{Status: 403, Body: "device-bound credential required"}, true},
		{&tokenEndpointError{Status: 401, Body: "invalid credentials"}, true},
		{&tokenEndpointError{Status: 503, Body: "no available server"}, false},
		{&tokenEndpointError{Status: 500, Body: ""}, false},
		{errors.New("dial tcp: connection refused"), false},
	} {
		if got := isRefusedRefresh(tc.err); got != tc.want {
			t.Errorf("isRefusedRefresh(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// The device-signed path gets the same verdict: a 403 from the device
// refresh endpoint is the server saying this device is revoked or unknown,
// and the daemon exits naming activate rather than retrying forever.
func TestRunDaemon_RefusedDeviceRefreshExits(t *testing.T) {
	dir := t.TempDir()
	setHome(t, dir)
	_, _, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}
	future := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := mergeDeviceCredential(pub, "dev_revoked", "a.b.c", future, "jti1"); err != nil {
		t.Fatalf("mergeDeviceCredential: %v", err)
	}
	var bridgeDials atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bridge" {
			bridgeDials.Add(1)
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"device revoked"}`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = runDaemon(ctx, &localConfig{Server: srv.URL}, nil, 1, nil)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("daemon did not exit on a refused device refresh: %v", err)
	}
	if n := bridgeDials.Load(); n != 0 {
		t.Fatalf("daemon dialed /bridge %d times after a refused refresh", n)
	}
}
