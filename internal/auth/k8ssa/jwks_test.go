package k8ssa

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func jwksServer(t *testing.T, status *atomic.Int32, hits *atomic.Int32, gotAuth *atomic.Value) *httptest.Server {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	body, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotAuth.Store(r.Header.Get("Authorization"))
		if s := status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		_, _ = w.Write(body)
	}))
}

func tokenFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("own-sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClusterKeys_CachesAndRateLimitsRefresh(t *testing.T) {
	var status, hits atomic.Int32
	var gotAuth atomic.Value
	srv := jwksServer(t, &status, &hits, &gotAuth)
	defer srv.Close()
	now := t0
	c := newClusterKeys(srv.Client(), srv.URL, tokenFile(t), func() time.Time { return now })
	ctx := context.Background()

	if set, err := c.Keys(ctx, false); err != nil || len(set.Keys) != 1 {
		t.Fatalf("first fetch: %v", err)
	}
	if gotAuth.Load() != "Bearer own-sa-token" {
		t.Fatalf("must authenticate with own SA token, got %v", gotAuth.Load())
	}
	_, _ = c.Keys(ctx, false)
	_, _ = c.Keys(ctx, true) // refresh inside minRefresh: served from cache
	if hits.Load() != 1 {
		t.Fatalf("want 1 fetch, got %d", hits.Load())
	}
	now = now.Add(minRefresh + time.Second)
	_, _ = c.Keys(ctx, true)
	if hits.Load() != 2 {
		t.Fatalf("forced refresh after minRefresh should fetch, got %d", hits.Load())
	}
	now = now.Add(cacheTTL + time.Second)
	_, _ = c.Keys(ctx, false)
	if hits.Load() != 3 {
		t.Fatalf("expired cache should fetch, got %d", hits.Load())
	}
}

func TestClusterKeys_FailedReadIsError(t *testing.T) {
	var status, hits atomic.Int32
	var gotAuth atomic.Value
	srv := jwksServer(t, &status, &hits, &gotAuth)
	defer srv.Close()
	status.Store(http.StatusForbidden)
	c := newClusterKeys(srv.Client(), srv.URL, tokenFile(t), func() time.Time { return t0 })
	if set, err := c.Keys(context.Background(), false); err == nil || set != nil {
		t.Fatal("a refused JWKS read must be an error, not an empty key set")
	}
	missing := newClusterKeys(srv.Client(), srv.URL, filepath.Join(t.TempDir(), "absent"), func() time.Time { return t0 })
	if _, err := missing.Keys(context.Background(), false); err == nil {
		t.Fatal("missing own token must be an error")
	}
}

// A failed fetch must back off: an attacker-controlled stream of tokens with
// the cluster iss cannot turn an erroring API server into one request per call.
func TestClusterKeys_BacksOffAfterFailure(t *testing.T) {
	var status, hits atomic.Int32
	var gotAuth atomic.Value
	srv := jwksServer(t, &status, &hits, &gotAuth)
	defer srv.Close()
	status.Store(http.StatusServiceUnavailable)
	now := t0
	c := newClusterKeys(srv.Client(), srv.URL, tokenFile(t), func() time.Time { return now })
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if set, err := c.Keys(ctx, i%2 == 1); err == nil || set != nil {
			t.Fatalf("call %d: a failed read must stay an error", i)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("want 1 fetch inside the backoff window, got %d", hits.Load())
	}
	status.Store(0)
	now = now.Add(minRefresh + time.Second)
	if set, err := c.Keys(ctx, false); err != nil || len(set.Keys) != 1 {
		t.Fatalf("after backoff a healthy server must be read again: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("want 2 fetches, got %d", hits.Load())
	}
	// A failed forced refresh keeps serving the cached good set.
	now = now.Add(minRefresh + time.Second)
	status.Store(http.StatusServiceUnavailable)
	if set, err := c.Keys(ctx, true); err == nil || set != nil {
		t.Fatalf("the failing refresh itself reports its error, got %v", err)
	}
	if set, err := c.Keys(ctx, true); err != nil || len(set.Keys) != 1 {
		t.Fatalf("inside backoff a fresh cached set must still be served: %v", err)
	}
	if hits.Load() != 3 {
		t.Fatalf("want 3 fetches, got %d", hits.Load())
	}
}

// A caller cancelling its own request must not start the backoff.
func TestClusterKeys_CancelledCallerDoesNotBackOff(t *testing.T) {
	var status, hits atomic.Int32
	var gotAuth atomic.Value
	srv := jwksServer(t, &status, &hits, &gotAuth)
	defer srv.Close()
	c := newClusterKeys(srv.Client(), srv.URL, tokenFile(t), func() time.Time { return t0 })
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Keys(cancelled, false); err == nil {
		t.Fatal("a cancelled fetch must fail")
	}
	if set, err := c.Keys(context.Background(), false); err != nil || len(set.Keys) != 1 {
		t.Fatalf("the next caller must fetch, not inherit a backoff: %v", err)
	}
}
