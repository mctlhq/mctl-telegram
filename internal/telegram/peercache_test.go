package telegram

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gotd/td/tg"
)

func TestResolveUserPeerFromDialogs_UsesHashBearingCache(t *testing.T) {
	cache := NewPeerCache()
	cache.Set(7, "user:42", &tg.InputPeerUser{UserID: 42, AccessHash: 9999})
	// A nil client is intentional: a valid cache hit must avoid a network
	// lookup entirely.
	peer, err := ResolveUserPeerFromDialogs(context.Background(), nil, 42, cache, 7)
	if err != nil {
		t.Fatalf("resolve cached peer: %v", err)
	}
	if peer.UserID != 42 || peer.AccessHash != 9999 {
		t.Fatalf("peer=%+v, want cached hash-bearing InputPeerUser", peer)
	}
}

func TestPeerCache_SetAndGet(t *testing.T) {
	pc := NewPeerCache()
	peer := &tg.InputPeerUser{UserID: 42, AccessHash: 99}
	pc.Set(1, "@alice", peer)
	got, ok := pc.Get(1, "@alice")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got != peer {
		t.Errorf("got %v, want %v", got, peer)
	}
}

func TestPeerCache_Miss(t *testing.T) {
	pc := NewPeerCache()
	_, ok := pc.Get(1, "@nobody")
	if ok {
		t.Fatal("expected cache miss for unknown peer")
	}
}

func TestPeerCache_TTLExpiry(t *testing.T) {
	pc := NewPeerCache()
	now := time.Now()
	pc.now = func() time.Time { return now }
	pc.WithTTL(100 * time.Millisecond)

	peer := &tg.InputPeerUser{UserID: 42}
	pc.Set(1, "@alice", peer)

	// Advance time past TTL.
	pc.now = func() time.Time { return now.Add(200 * time.Millisecond) }
	_, ok := pc.Get(1, "@alice")
	if ok {
		t.Fatal("expected cache miss after TTL expiry")
	}
}

func TestPeerCache_Evict(t *testing.T) {
	pc := NewPeerCache()
	peer := &tg.InputPeerUser{UserID: 7}
	pc.Set(1, "@bob", peer)
	pc.Evict(1, "@bob")
	_, ok := pc.Get(1, "@bob")
	if ok {
		t.Fatal("expected cache miss after eviction")
	}
}

func TestPeerCache_Sweep(t *testing.T) {
	pc := NewPeerCache()
	now := time.Now()
	pc.now = func() time.Time { return now }
	pc.WithTTL(50 * time.Millisecond)

	pc.Set(1, "@a", &tg.InputPeerUser{UserID: 1})
	pc.Set(1, "@b", &tg.InputPeerUser{UserID: 2})

	// Advance past TTL, add a fresh entry.
	pc.now = func() time.Time { return now.Add(100 * time.Millisecond) }
	pc.WithTTL(10 * time.Minute)
	pc.Set(1, "@c", &tg.InputPeerUser{UserID: 3})

	pc.Sweep()

	if _, ok := pc.Get(1, "@a"); ok {
		t.Error("@a should have been swept")
	}
	if _, ok := pc.Get(1, "@b"); ok {
		t.Error("@b should have been swept")
	}
	if _, ok := pc.Get(1, "@c"); !ok {
		t.Error("@c should still be cached")
	}
}

func TestPeerCache_ConcurrentAccess(t *testing.T) {
	pc := NewPeerCache()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int64) {
			defer wg.Done()
			peer := &tg.InputPeerUser{UserID: n}
			pc.Set(n, "@peer", peer)
			pc.Get(n, "@peer")
			pc.Evict(n, "@peer")
		}(int64(i))
	}
	wg.Wait()
}
