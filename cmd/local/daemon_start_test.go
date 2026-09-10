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

// startableLegacyHome writes the minimum a real `daemon` run needs on disk --
// a config with a server and a key salt, an expired legacy bridge token, and
// the passphrase in the environment -- so serveDaemon itself can be driven,
// pre-loop refresh included. KeyCheck is left empty: the key derives from
// the passphrase either way, and nothing here decrypts.
func startableLegacyHome(t *testing.T, server string) {
	t.Helper()
	setHome(t, t.TempDir())
	t.Setenv(passphraseEnv, "test-passphrase")
	t.Setenv(passphraseFileEnv, "")
	salt, err := generateSalt()
	if err != nil {
		t.Fatalf("generateSalt: %v", err)
	}
	if err := saveConfig(&localConfig{APIID: 1, APIHash: "h", Server: server, KeySalt: salt}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	legacyTokenOnDisk(t)
}

// A transient failure of the pre-start refresh must start the daemon
// unprimed: the loop then re-reads the expired token, sees it expired and
// waits, so nothing dials /bridge with a token the process knows is dead.
// 6eacd7f primed the loop with the stale token and dialed once per start;
// this pins the shape that fixed it.
func TestServeDaemon_TransientStartupRefreshStartsUnprimedWithoutDialing(t *testing.T) {
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
	startableLegacyHome(t, srv.URL)

	// One pre-start attempt plus at least one from the loop (reconnectBase
	// is 2s) fit in a 5s window; the daemon must still be running at the end.
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(5*time.Second, cancel)
	if err := serveDaemon(ctx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("daemon gave up on a transient startup failure: %v", err)
	}
	if n := tokenCalls.Load(); n < 2 {
		t.Fatalf("expected the pre-start refresh and at least one retry from the loop, saw %d attempts", n)
	}
	if n := bridgeDials.Load(); n != 0 {
		t.Fatalf("daemon dialed /bridge %d times with a token it knew was expired", n)
	}
}

// A refusal at the pre-start refresh is the server's verdict: the daemon
// exits naming activate, before the passphrase is even used, and never
// dials /bridge.
func TestServeDaemon_RefusedStartupRefreshExitsNamingActivate(t *testing.T) {
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
	startableLegacyHome(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := serveDaemon(ctx)
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("daemon started on a refused credential instead of exiting: err=%v", err)
	}
	if !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), "activate --server "+srv.URL) {
		t.Fatalf("exit error does not name the refusal and the fix: %v", err)
	}
	if n := bridgeDials.Load(); n != 0 {
		t.Fatalf("daemon dialed /bridge %d times after a refused refresh", n)
	}
}
