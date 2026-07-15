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

func TestAllowPeerN_DebitsBatchCostNotOne(t *testing.T) {
	r := NewRateLimiter(0)
	id := &auth.Identity{GitHubLogin: "alice"}
	base := time.Now()
	r.now = func() time.Time { return base }

	// 20-token cap (matches PeerSendCap); a single batch of 15 should debit
	// 15, not 1 — leaving only 5 for a subsequent call.
	if !r.AllowPeerN(id, "peerA", 15, 20, time.Hour) {
		t.Fatal("first batch of 15 should be allowed under a cap of 20")
	}
	if r.AllowPeerN(id, "peerA", 10, 20, time.Hour) {
		t.Fatal("second batch of 10 should be denied — only 5 tokens remain")
	}
	if !r.AllowPeerN(id, "peerA", 5, 20, time.Hour) {
		t.Fatal("batch of exactly the remaining 5 tokens should be allowed")
	}
}

func TestAllowPeerN_OversizedBatchDeniedWithoutPartialDebit(t *testing.T) {
	r := NewRateLimiter(0)
	id := &auth.Identity{GitHubLogin: "alice"}
	base := time.Now()
	r.now = func() time.Time { return base }

	// A batch larger than the whole cap must be denied outright, and must
	// not silently consume whatever tokens happen to be available.
	if r.AllowPeerN(id, "peerA", 25, 20, time.Hour) {
		t.Fatal("batch of 25 must be denied against a cap of 20")
	}
	if !r.AllowPeerN(id, "peerA", 20, 20, time.Hour) {
		t.Fatal("the full cap should still be available — the oversized attempt must not have debited anything")
	}
}

func TestAllowPeerN_NonPositiveCostTreatedAsOne(t *testing.T) {
	r := NewRateLimiter(0)
	id := &auth.Identity{GitHubLogin: "alice"}
	if !r.AllowPeerN(id, "peerA", 0, 1, time.Hour) {
		t.Fatal("cost=0 should behave like cost=1 and be allowed against a fresh bucket")
	}
	if r.AllowPeerN(id, "peerA", 0, 1, time.Hour) {
		t.Fatal("cost=0 treated as 1 should have exhausted a cap-1 bucket")
	}
}
