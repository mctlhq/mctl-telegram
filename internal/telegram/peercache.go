package telegram

import (
	"sync"
	"time"

	"github.com/gotd/td/tg"
)

// PeerCache is a lightweight in-memory cache of resolved InputPeerClass values
// keyed by (userID, peerSpec). It avoids repeated ContactsResolveUsername calls
// for the same peer within the TTL window. The cache is per-process; a pod
// restart or failover triggers one extra resolve call per peer, which is
// acceptable. Thread-safe.
type PeerCache struct {
	mu  sync.Mutex
	m   map[peerCacheKey]*peerCacheEntry
	ttl time.Duration
	now func() time.Time
}

type peerCacheKey struct {
	userID   int64
	peerSpec string
}

type peerCacheEntry struct {
	peer      tg.InputPeerClass
	expiresAt time.Time
}

const defaultPeerCacheTTL = 10 * time.Minute

// NewPeerCache returns a PeerCache with the default 10-minute TTL.
func NewPeerCache() *PeerCache {
	return &PeerCache{
		m:   make(map[peerCacheKey]*peerCacheEntry),
		ttl: defaultPeerCacheTTL,
		now: time.Now,
	}
}

// WithTTL returns a copy of the cache configured with a different TTL.
// Must be called before the cache is used.
func (pc *PeerCache) WithTTL(d time.Duration) *PeerCache {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.ttl = d
	return pc
}

// Get returns the cached InputPeerClass for (userID, peerSpec) and true if the
// entry exists and has not expired. Returns nil, false otherwise.
func (pc *PeerCache) Get(userID int64, peerSpec string) (tg.InputPeerClass, bool) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	entry, ok := pc.m[peerCacheKey{userID: userID, peerSpec: peerSpec}]
	if !ok {
		return nil, false
	}
	if pc.now().After(entry.expiresAt) {
		delete(pc.m, peerCacheKey{userID: userID, peerSpec: peerSpec})
		return nil, false
	}
	return entry.peer, true
}

// Set stores an InputPeerClass in the cache for (userID, peerSpec) with the
// configured TTL.
func (pc *PeerCache) Set(userID int64, peerSpec string, peer tg.InputPeerClass) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.m[peerCacheKey{userID: userID, peerSpec: peerSpec}] = &peerCacheEntry{
		peer:      peer,
		expiresAt: pc.now().Add(pc.ttl),
	}
}

// Evict removes the cache entry for (userID, peerSpec) so the next call
// re-resolves the peer. Use this when a Telegram API call returns
// PEER_ID_INVALID to purge a stale access hash.
func (pc *PeerCache) Evict(userID int64, peerSpec string) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	delete(pc.m, peerCacheKey{userID: userID, peerSpec: peerSpec})
}

// Sweep removes all expired entries. Call periodically to bound memory usage.
func (pc *PeerCache) Sweep() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	now := pc.now()
	for k, v := range pc.m {
		if now.After(v.expiresAt) {
			delete(pc.m, k)
		}
	}
}
