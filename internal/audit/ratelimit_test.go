package audit

import (
	"strings"
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

func TestDecidePeer_RetryAfterAndTooLarge(t *testing.T) {
	r := NewRateLimiter(0)
	base := time.Now()
	r.now = func() time.Time { return base }
	id := &auth.Identity{Subject: "tg:1"}

	// 20/hour refills one token per 180 s.
	if d := r.DecidePeer(id, "u:7001", 20, 20, time.Hour); !d.Allowed {
		t.Fatalf("draining a fresh bucket was refused: %+v", d)
	}
	d := r.DecidePeer(id, "u:7001", 1, 20, time.Hour)
	if d.Allowed || d.TooLarge || d.RetryAfter != 180*time.Second {
		t.Fatalf("empty bucket = %+v, want refused with RetryAfter 180s", d)
	}
	r.now = func() time.Time { return base.Add(60 * time.Second) }
	if d := r.DecidePeer(id, "u:7001", 1, 20, time.Hour); d.Allowed || d.RetryAfter != 120*time.Second {
		t.Fatalf("after 60 s = %+v, want refused with RetryAfter 120s", d)
	}
	r.now = func() time.Time { return base.Add(180 * time.Second) }
	if d := r.DecidePeer(id, "u:7001", 1, 20, time.Hour); !d.Allowed {
		t.Fatalf("after 180 s = %+v, want allowed", d)
	}
	if d := r.DecidePeer(id, "u:7002", 21, 20, time.Hour); d.Allowed || !d.TooLarge || d.RetryAfter != 0 {
		t.Fatalf("batch above capacity = %+v, want TooLarge", d)
	}
}

func TestRateLimiter_SweepDropsOnlyFullBuckets(t *testing.T) {
	r := NewRateLimiter(0)
	base := time.Now()
	r.now = func() time.Time { return base }
	r.lastSweep = base
	id := &auth.Identity{Subject: "tg:1"}

	r.AllowPeer(id, "u:7001", 20, time.Hour)      // one token spent, refills in 180 s
	r.AllowPeerN(id, "u:7002", 20, 20, time.Hour) // drained, refills in 1 h
	if n := len(r.buckets); n != 2 {
		t.Fatalf("buckets = %d, want 2", n)
	}

	r.now = func() time.Time { return base.Add(sweepEvery) }
	r.AllowPeer(id, "u:7003", 20, time.Hour) // triggers the sweep
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.buckets[identityKey(id)+":peer:"+r.peerDigest("u:7001")]; ok {
		t.Error("a bucket that refilled to capacity survived the sweep")
	}
	if _, ok := r.buckets[identityKey(id)+":peer:"+r.peerDigest("u:7002")]; !ok {
		t.Error("a bucket still draining was swept, which would reset its budget")
	}
}

func TestRateLimiter_PeerKeyIsNotStoredRaw(t *testing.T) {
	r := NewRateLimiter(0)
	id := &auth.Identity{Subject: "tg:1"}
	r.AllowPeer(id, "u:7001", 20, time.Hour)
	// Match the exact digest key rather than scanning for "7001": a random
	// hex digest can contain those digits by chance. The raw key has a
	// colon, which hex never does, so it cannot appear in a digest.
	want := identityKey(id) + ":peer:" + r.peerDigest("u:7001")
	if len(r.buckets) != 1 || r.buckets[want] == nil {
		t.Fatalf("buckets = %v, want exactly the digest key %q", r.buckets, want)
	}
	for k := range r.buckets {
		if strings.Contains(k, "u:7001") {
			t.Fatalf("bucket key %q carries the raw peer key", k)
		}
	}
}

// HoldWrites pauses one account until the hold runs out, never shortens an
// earlier hold, and leaves other accounts alone (#849).
func TestWriteHold_PausesOneAccountUntilExpiry(t *testing.T) {
	r := NewRateLimiter(0)
	base := time.Unix(1_700_000_000, 0)
	r.now = func() time.Time { return base }
	r.HoldWrites(1, PeerFloodHold)
	if got := r.WriteHold(1); got != PeerFloodHold {
		t.Fatalf("WriteHold(1) = %v, want %v", got, PeerFloodHold)
	}
	if got := r.WriteHold(2); got != 0 {
		t.Fatalf("WriteHold(2) = %v, want 0: the hold leaked to another account", got)
	}
	r.HoldWrites(1, time.Minute)
	if got := r.WriteHold(1); got != PeerFloodHold {
		t.Fatalf("a shorter hold shortened the pause to %v", got)
	}
	r.now = func() time.Time { return base.Add(PeerFloodHold - time.Second) }
	if got := r.WriteHold(1); got != time.Second {
		t.Fatalf("WriteHold(1) one second before expiry = %v", got)
	}
	r.now = func() time.Time { return base.Add(PeerFloodHold) }
	if got := r.WriteHold(1); got != 0 {
		t.Fatalf("WriteHold(1) after expiry = %v, want 0", got)
	}
}

// sweep drops expired holds, so an account that never writes again does not
// keep its entry forever.
func TestWriteHold_SweepDropsExpiredHolds(t *testing.T) {
	r := NewRateLimiter(0)
	base := time.Unix(1_700_000_000, 0)
	r.now = func() time.Time { return base }
	r.HoldWrites(1, PeerFloodHold)
	r.HoldWrites(2, 2*PeerFloodHold)
	r.mu.Lock()
	r.sweep(base.Add(PeerFloodHold + sweepEvery))
	_, kept1 := r.writeHolds[1]
	_, kept2 := r.writeHolds[2]
	r.mu.Unlock()
	if kept1 || !kept2 {
		t.Fatalf("after sweep: hold 1 kept=%v (want false), hold 2 kept=%v (want true)", kept1, kept2)
	}
}
