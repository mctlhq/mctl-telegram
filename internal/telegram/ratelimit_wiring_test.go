package telegram

import (
	"testing"

	"github.com/gotd/contrib/middleware/floodwait"
	"github.com/gotd/contrib/middleware/ratelimit"
	"golang.org/x/time/rate"
)

func TestLoginMiddlewares_NoGlobalLimiter(t *testing.T) {
	mws := loginMiddlewares(LoginConfig{})
	if len(mws) != 2 {
		t.Fatalf("expected 2 middlewares (floodwait, rpcTimeout), got %d", len(mws))
	}
	if _, ok := mws[0].(*floodwait.SimpleWaiter); !ok {
		t.Errorf("middleware[0] should be the floodwait waiter, got %T", mws[0])
	}
}

func TestLoginMiddlewares_WithGlobalLimiter(t *testing.T) {
	limiter := ratelimit.New(rate.Limit(25), 50)
	mws := loginMiddlewares(LoginConfig{GlobalMiddleware: limiter})
	if len(mws) != 3 {
		t.Fatalf("expected 3 middlewares (floodwait, global, rpcTimeout), got %d", len(mws))
	}
	if _, ok := mws[0].(*floodwait.SimpleWaiter); !ok {
		t.Errorf("middleware[0] should be the floodwait waiter, got %T", mws[0])
	}
	// floodwait must stay outermost so its retry sleep re-acquires a token from
	// the global limiter rather than being throttled before it can back off.
	if mws[1] != limiter {
		t.Errorf("middleware[1] should be the shared global limiter instance")
	}
}

func TestClientPool_WithGlobalMiddleware(t *testing.T) {
	limiter := ratelimit.New(rate.Limit(10), 10)
	p := NewClientPool(1, "hash", 0, nil)
	if p.globalMW != nil {
		t.Fatal("globalMW should be nil before WithGlobalMiddleware")
	}
	if got := p.WithGlobalMiddleware(limiter); got != p {
		t.Error("WithGlobalMiddleware should return the receiver for chaining")
	}
	if p.globalMW != limiter {
		t.Error("WithGlobalMiddleware should store the shared limiter instance")
	}
	// nil is a no-op contract: the pool must not wrap clients when disabled.
	p.WithGlobalMiddleware(nil)
	if p.globalMW != nil {
		t.Error("WithGlobalMiddleware(nil) should clear the middleware")
	}
}
