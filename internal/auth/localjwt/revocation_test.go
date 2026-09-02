package localjwt

import (
	"context"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// newBrokenLocaljwtStore returns a Store wrapping an already-closed *sql.DB,
// so every query against it fails. Used to simulate the revocation table
// being unreachable without needing a real network-backed Postgres outage.
func newBrokenLocaljwtStore(t *testing.T, name string) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+name+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return &db.Store{DB: conn}
}

// T1: a token carrying a revoked jti is rejected by Provider.Authenticate.
// This asserts on actual Authenticate behavior (not merely that
// RevocationCache reports revoked=true in isolation), so it fails if the
// c.Jti != "" check — or the call to RevocationCache.IsRevoked — is ever
// deleted from Authenticate.
func TestProvider_RevokedJtiRejected(t *testing.T) {
	store := newTestLocaljwtStore(t)
	ctx := context.Background()
	if err := store.RevokeWorkerToken(ctx, "revoked-jti-1", 99, "leak", 1); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	cache := NewRevocationCache(store, time.Minute)
	p, err := NewProvider(store, ProviderConfig{
		Secret: testSecret, ExpectedIssuer: testIssuer, RevocationCache: cache,
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, err := iss.Mint(Claims{Subject: "tg:99", TelegramID: 99, Jti: "revoked-jti-1"}, time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if id, err := p.Authenticate(r); err == nil {
		t.Fatalf("revoked jti must be rejected, got identity %+v", id)
	}
}

// A jti that was never revoked still authenticates normally through the same
// RevocationCache-wired provider — the denylist check must be selective, not
// a blanket rejection of every jti-bearing token.
func TestProvider_UnrevokedJtiStillAuthenticates(t *testing.T) {
	store := newTestLocaljwtStore(t)
	ctx := context.Background()
	if err := store.RevokeWorkerToken(ctx, "revoked-jti-2", 99, "leak", 1); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	cache := NewRevocationCache(store, time.Minute)
	p, err := NewProvider(store, ProviderConfig{
		Secret: testSecret, ExpectedIssuer: testIssuer, RevocationCache: cache,
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, err := iss.Mint(Claims{Subject: "tg:100", TelegramID: 100, Jti: "not-revoked"}, time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	id, err := p.Authenticate(r)
	if err != nil {
		t.Fatalf("unrevoked jti should authenticate: %v", err)
	}
	if id == nil || id.TelegramID != 100 {
		t.Fatalf("unexpected identity: %+v", id)
	}
}

// T2 / TE2: a token with no jti (an interactive session) performs zero
// revocation-cache lookups. Proven behaviorally: RevocationCache is backed by
// an already-closed store, so ANY lookup attempt returns an error; a no-jti
// token must still authenticate successfully, which is only possible if
// Authenticate's c.Jti != "" guard skipped the cache entirely. Deleting that
// guard makes this test fail because the broken cache would then be
// consulted and its error would propagate.
func TestProvider_NoJtiSkipsRevocationCacheEntirely(t *testing.T) {
	healthyStore := newTestLocaljwtStore(t)
	brokenStore := newBrokenLocaljwtStore(t, "no_jti_skip")
	cache := NewRevocationCache(brokenStore, time.Millisecond)
	p, err := NewProvider(healthyStore, ProviderConfig{
		Secret: testSecret, ExpectedIssuer: testIssuer, RevocationCache: cache,
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, err := iss.Mint(Claims{Subject: "tg:1", TelegramID: 1}, time.Hour) // no Jti
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	id, err := p.Authenticate(r)
	if err != nil {
		t.Fatalf("no-jti token must not touch the (broken) revocation cache, got err: %v", err)
	}
	if id == nil {
		t.Fatal("expected a non-nil identity")
	}
}

// T7: when the revocation store cannot be reached and the cache has never
// successfully populated, a jti-bearing token's verification fails closed
// (rejected), not silently treated as "not revoked".
func TestProvider_JtiRevocationStoreUnreachableFailsClosed(t *testing.T) {
	brokenStore := newBrokenLocaljwtStore(t, "fail_closed")
	cache := NewRevocationCache(brokenStore, time.Minute)
	p, err := NewProvider(brokenStore, ProviderConfig{
		Secret: testSecret, ExpectedIssuer: testIssuer, RevocationCache: cache,
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, err := iss.Mint(Claims{Subject: "tg:5", TelegramID: 5, Jti: "some-jti"}, time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if id, err := p.Authenticate(r); err == nil {
		t.Fatalf("expected fail-closed rejection when the revocation store is unreachable, got identity %+v", id)
	}
}

// Direct RevocationCache unit tests (not routed through Provider), per
// tasks.md's DoD for the cache itself: cache-hit revoked, cache-hit
// non-revoked, cold-start store error fails closed, and a later refresh
// error on an already-populated cache serves the last-known-good snapshot
// instead of going unavailable.

func TestRevocationCache_JtiHitAndMiss(t *testing.T) {
	store := newTestLocaljwtStore(t)
	ctx := context.Background()
	if err := store.RevokeWorkerToken(ctx, "jti-a", 42, "leak", 1); err != nil {
		t.Fatalf("seed revocation: %v", err)
	}
	cache := NewRevocationCache(store, time.Minute)
	if revoked, err := cache.IsRevoked(ctx, "jti-a", 42, time.Now()); err != nil || !revoked {
		t.Fatalf("revoked jti should be reported revoked: revoked=%v err=%v", revoked, err)
	}
	if revoked, err := cache.IsRevoked(ctx, "jti-b", 42, time.Now()); err != nil || revoked {
		t.Fatalf("unrelated jti should not be revoked: revoked=%v err=%v", revoked, err)
	}
}

func TestRevocationCache_BlanketRevocationHonorsIssuedAt(t *testing.T) {
	store := newTestLocaljwtStore(t)
	ctx := context.Background()
	if err := store.RevokeWorkerTokensForTelegramID(ctx, 7, "compromised", 1); err != nil {
		t.Fatalf("seed blanket revocation: %v", err)
	}
	cache := NewRevocationCache(store, time.Minute)
	if revoked, err := cache.IsRevoked(ctx, "any-jti", 7, time.Now().Add(-time.Hour)); err != nil || !revoked {
		t.Fatalf("token issued before blanket revocation must be revoked: revoked=%v err=%v", revoked, err)
	}
	if revoked, err := cache.IsRevoked(ctx, "any-jti-2", 7, time.Now().Add(time.Hour)); err != nil || revoked {
		t.Fatalf("token issued after blanket revocation must not be revoked: revoked=%v err=%v", revoked, err)
	}
}

func TestRevocationCache_ColdStartStoreErrorFailsClosed(t *testing.T) {
	store := newBrokenLocaljwtStore(t, "cold_start")
	cache := NewRevocationCache(store, time.Minute)
	if _, err := cache.IsRevoked(context.Background(), "x", 1, time.Now()); err == nil {
		t.Fatal("expected error on cold-start refresh failure (fail closed)")
	}
}

func TestRevocationCache_StaleRefreshErrorServesLastKnownGood(t *testing.T) {
	store := newTestLocaljwtStore(t)
	ctx := context.Background()
	if err := store.RevokeWorkerToken(ctx, "jti-c", 1, "", 0); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cache := NewRevocationCache(store, time.Minute)
	if revoked, err := cache.IsRevoked(ctx, "jti-c", 1, time.Now()); err != nil || !revoked {
		t.Fatalf("initial populate should see jti-c revoked: revoked=%v err=%v", revoked, err)
	}
	// Break the backing store, then force the cache to consider itself
	// stale (rather than sleeping past a real TTL) for a deterministic test.
	if err := store.DB.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	cache.now = func() time.Time { return time.Now().Add(time.Hour) }
	revoked, err := cache.IsRevoked(ctx, "jti-c", 1, time.Now())
	if err != nil {
		t.Fatalf("a populated cache must serve its last-known-good snapshot on a later refresh error, got err: %v", err)
	}
	if !revoked {
		t.Fatal("last-known-good snapshot lost jti-c")
	}
}

func TestNewRevocationCache_ClampsTTL(t *testing.T) {
	store := newTestLocaljwtStore(t)
	c := NewRevocationCache(store, 0)
	if c.ttl != DefaultRevocationCacheTTL {
		t.Errorf("ttl<=0 should fall back to DefaultRevocationCacheTTL, got %v", c.ttl)
	}
	c = NewRevocationCache(store, time.Hour)
	if c.ttl != MaxRevocationCacheTTL {
		t.Errorf("ttl above the max should clamp to MaxRevocationCacheTTL, got %v", c.ttl)
	}
}

// TestRevocationCache_StaleSnapshotDoesNotOverwriteNewer reproduces the
// ordering of a race rather than the race itself: a lazy refresh that began
// before a revocation was recorded, but whose database read returns after the
// forced refresh that followed the revocation.
//
// If the later-arriving-but-older snapshot is applied, it overwrites the
// denylist with pre-revocation data AND stamps the cache as freshly loaded, so
// a daemon evicted moments earlier reconnects cleanly for a whole TTL window —
// defeating the containment the forced refresh exists to provide.
//
// The clock is scripted so the second refresh reports a read-start that
// precedes the applied one's; the store is emptied first so the stale snapshot
// carries visibly different data. Without that, the test would pass whether or
// not the guard exists.
func TestRevocationCache_StaleSnapshotDoesNotOverwriteNewer(t *testing.T) {
	store := newTestLocaljwtStore(t)
	ctx := context.Background()
	if err := store.RevokeWorkerToken(ctx, "jti-race", 99, "leak", 1); err != nil {
		t.Fatalf("seed revocation: %v", err)
	}

	var clock atomic.Int64
	clock.Store(100)
	base := time.Unix(0, 0)
	cache := NewRevocationCache(store, time.Minute)
	cache.now = func() time.Time { return base.Add(time.Duration(clock.Load()) * time.Second) }

	// Applied snapshot: read starts at t=100 and sees the revocation.
	if revoked, err := cache.IsRevoked(ctx, "jti-race", 99, time.Now()); err != nil || !revoked {
		t.Fatalf("initial populate should see the revocation: revoked=%v err=%v", revoked, err)
	}

	// The world the stale reader saw: no revocation yet.
	if _, err := store.DB.ExecContext(ctx, `DELETE FROM worker_token_revocations`); err != nil {
		t.Fatalf("clear revocations: %v", err)
	}

	// A refresh whose read began at t=50 — before the applied one — lands now.
	clock.Store(50)
	if err := cache.Refresh(ctx); err != nil {
		t.Fatalf("late refresh: %v", err)
	}

	clock.Store(101) // still within the TTL, so no further reload is triggered
	revoked, err := cache.IsRevoked(ctx, "jti-race", 99, time.Now())
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("a snapshot that read the database earlier overwrote a newer one; the revoked credential would be accepted again")
	}
}

// scriptedClock returns each value once, in order, so a single refresh can be
// given a read-start and a completion time that differ.
type scriptedClock struct {
	mu     sync.Mutex
	values []time.Time
	i      int
}

func (s *scriptedClock) next() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.i >= len(s.values) {
		return s.values[len(s.values)-1]
	}
	v := s.values[s.i]
	s.i++
	return v
}

// TestRevocationCache_FreshSnapshotWinsOverLateStaleOne pins the half of the
// guard that a completion-time comparison gets wrong.
//
// The obvious form of this check — discard if the applied snapshot COMPLETED
// at or after our read began — is right about the stale-overwrites-fresh case
// but wrong here: a read that started earlier and finished later stamps a
// completion time that makes a genuinely newer snapshot look obsolete, so the
// newer one is thrown away and the revocation it carries never lands. The
// guard therefore compares read-START times.
//
// Timeline (all via the scripted clock): applied snapshot reads at t=10; a
// stale snapshot reads at t=50 and lands at t=101; the snapshot that actually
// saw the revocation reads at t=100 and lands at t=102. The last one must win.
func TestRevocationCache_FreshSnapshotWinsOverLateStaleOne(t *testing.T) {
	store := newTestLocaljwtStore(t)
	ctx := context.Background()
	base := time.Unix(0, 0)
	at := func(sec int) time.Time { return base.Add(time.Duration(sec) * time.Second) }

	clock := &scriptedClock{values: []time.Time{
		at(10), at(11), // applied snapshot: empty store
		at(50), at(101), // stale snapshot: still empty, lands late
		at(100), at(102), // the snapshot that sees the revocation
		at(103), // the IsRevoked staleness check below
	}}
	cache := NewRevocationCache(store, time.Minute)
	cache.now = clock.next

	if err := cache.Refresh(ctx); err != nil { // reads at t=10
		t.Fatalf("initial refresh: %v", err)
	}
	if err := cache.Refresh(ctx); err != nil { // reads at t=50, lands at t=101
		t.Fatalf("stale refresh: %v", err)
	}

	if err := store.RevokeWorkerToken(ctx, "jti-late", 5, "leak", 1); err != nil {
		t.Fatalf("seed revocation: %v", err)
	}
	if err := cache.Refresh(ctx); err != nil { // reads at t=100, lands at t=102
		t.Fatalf("fresh refresh: %v", err)
	}

	revoked, err := cache.IsRevoked(ctx, "jti-late", 5, at(0))
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("the snapshot that read the database last was discarded because an older read finished after it started; the revocation never took effect")
	}
}
