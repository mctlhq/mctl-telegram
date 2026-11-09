package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJWKSStaleRefreshIsThrottled(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	c := newJWKSCache(srv.URL, srv.Client(), func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	c.loaded = true
	c.fetchedAt = now.Add(-2 * jwksTTL)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.key(context.Background(), "kid-1")
		}()
	}
	wg.Wait()
	if got := hits.Load(); got > 1 {
		t.Fatalf("expected at most 1 fetch while JWKS is down, got %d", got)
	}
}
