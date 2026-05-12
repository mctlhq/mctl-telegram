package audit

import (
	"testing"
	"time"
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
