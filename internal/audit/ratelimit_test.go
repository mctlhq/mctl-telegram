package audit

import (
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

func TestRateLimiter_BurstAndRefill(t *testing.T) {
	r := NewRateLimiter(6) // 6 per minute = 0.1/sec
	base := time.Now()
	r.now = func() time.Time { return base }

	// Burst: 6 allowed, 7th denied.
	for i := 0; i < 6; i++ {
		if !r.allow("u:a") {
			t.Fatalf("burst hit at %d, want all 6 allowed", i)
		}
	}
	if r.allow("u:a") {
		t.Fatal("7th call should be denied")
	}

	// Move forward 30s — should add 3 tokens (6 * 30/60).
	r.now = func() time.Time { return base.Add(30 * time.Second) }
	allowed := 0
	for i := 0; i < 10; i++ {
		if r.allow("u:a") {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("after 30s refill expected 3 tokens, got %d", allowed)
	}
}

func TestRateLimiter_IsolatedBuckets(t *testing.T) {
	r := NewRateLimiter(2)
	if !r.allow("u:a") || !r.allow("u:a") {
		t.Fatal("u:a should get 2")
	}
	if r.allow("u:a") {
		t.Fatal("u:a should be empty")
	}
	if !r.allow("u:b") {
		t.Fatal("u:b should still have tokens — buckets are per-key")
	}
}

func TestAllowPeer_ExhaustsCapAndIsolatesPerPeer(t *testing.T) {
	r := NewRateLimiter(0) // global cap off — focus on the peer cap
	id := &auth.Identity{GitHubLogin: "alice"}
	base := time.Now()
	r.now = func() time.Time { return base }

	// 3-call cap across 1 hour for the test.
	for i := 0; i < 3; i++ {
		if !r.AllowPeer(id, "peerA", 3, time.Hour) {
			t.Fatalf("call %d to peerA should be allowed", i)
		}
	}
	if r.AllowPeer(id, "peerA", 3, time.Hour) {
		t.Fatal("4th call to peerA must be denied")
	}
	// Different peer — independent bucket.
	if !r.AllowPeer(id, "peerB", 3, time.Hour) {
		t.Fatal("first call to peerB must be allowed (independent bucket)")
	}
	// Different identity, same peer — also independent.
	bob := &auth.Identity{GitHubLogin: "bob"}
	if !r.AllowPeer(bob, "peerA", 3, time.Hour) {
		t.Fatal("first call from bob to peerA must be allowed (different identity)")
	}
}

func TestAllowPeer_RefillOverWindow(t *testing.T) {
	r := NewRateLimiter(0)
	id := &auth.Identity{GitHubLogin: "alice"}
	base := time.Now()
	r.now = func() time.Time { return base }
	// 3-token cap over 1 hour
	for i := 0; i < 3; i++ {
		r.AllowPeer(id, "p", 3, time.Hour)
	}
	// Half-window later → ~1.5 tokens added → 1 more call allowed.
	r.now = func() time.Time { return base.Add(30 * time.Minute) }
	if !r.AllowPeer(id, "p", 3, time.Hour) {
		t.Fatal("after half-window refill, one more call should be allowed")
	}
	if r.AllowPeer(id, "p", 3, time.Hour) {
		t.Fatal("only one refill should be available at the half-window mark")
	}
}
