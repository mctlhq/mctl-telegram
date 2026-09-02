package localjwt

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// MaxRevocationCacheTTL is the hard upper bound on how stale a revocation
// check may be. Required so that "revoked" is a containment control with a
// known propagation delay rather than an open-ended promise: a denylisted
// jti or blanket-revoked telegram id must be rejected within this long of the
// revocation being recorded. NewRevocationCache clamps any longer configured
// TTL down to this.
const MaxRevocationCacheTTL = 15 * time.Second

// DefaultRevocationCacheTTL is used when NewRevocationCache is given ttl<=0.
const DefaultRevocationCacheTTL = 10 * time.Second

// RevocationCache is an in-memory, mutex-protected view of
// worker_token_revocations, lazily refreshed from
// db.Store.ListWorkerTokenRevocations at most once per TTL window. Modeled on
// internal/telegram.PeerCache's shape (single mutex, injectable clock), with
// one addition: a "populated" flag that lets IsRevoked distinguish "never
// successfully loaded" (fail closed — reject) from "loaded before, this
// refresh attempt merely failed" (serve the last-known-good snapshot rather
// than go fully unavailable on a transient store blip).
//
// The refresh itself happens inline on whichever request notices the cache is
// stale, not on a background goroutine: worker_token_revocations is expected
// to hold single-digit rows, so the query is cheap, and this avoids a second
// goroutine lifecycle to wire through cmd/server/main.go's shutdown path. The
// user-visible behavior is identical to a periodic background refresh — the
// backing table is read at most once per TTL window, not once per request.
type RevocationCache struct {
	store *db.Store
	ttl   time.Duration
	now   func() time.Time

	mu        sync.Mutex
	populated bool
	// lastRefresh is when the applied snapshot finished loading; it drives
	// the TTL. readStartedAt is when that same snapshot's read BEGAN, and is
	// what decides whether an arriving snapshot is newer than the applied
	// one. The two are different clocks and the distinction is load-bearing:
	// see refresh.
	lastRefresh   time.Time
	readStartedAt time.Time
	jtis          map[string]struct{}
	blanket       map[int64]time.Time // telegram_id -> most recent blanket revoked_at
}

// NewRevocationCache returns a RevocationCache backed by store, refreshing at
// most every ttl. ttl<=0 uses DefaultRevocationCacheTTL; any ttl above
// MaxRevocationCacheTTL is silently clamped down to it.
func NewRevocationCache(store *db.Store, ttl time.Duration) *RevocationCache {
	if ttl <= 0 {
		ttl = DefaultRevocationCacheTTL
	}
	if ttl > MaxRevocationCacheTTL {
		ttl = MaxRevocationCacheTTL
	}
	return &RevocationCache{
		store:   store,
		ttl:     ttl,
		now:     time.Now,
		jtis:    make(map[string]struct{}),
		blanket: make(map[int64]time.Time),
	}
}

// IsRevoked reports whether jti is individually denylisted, or telegramID
// carries a blanket revocation recorded at or after issuedAt. Refreshes the
// cache first when it is stale (or has never populated).
//
// Fail-closed per the codebase's "no panics, wrap and return" posture: if the
// cache has never successfully populated and this refresh also fails, the
// error is returned so the caller (Provider.Authenticate) rejects the
// request instead of treating an unreachable revocation store as "nothing is
// revoked". Once the cache has populated at least once, a later refresh
// failure is swallowed here and the last-known-good snapshot is used instead
// — otherwise a single transient DB blip would turn every worker-token
// request into a 401 rather than merely risk staleness within the TTL bound.
func (c *RevocationCache) IsRevoked(ctx context.Context, jti string, telegramID int64, issuedAt time.Time) (bool, error) {
	c.mu.Lock()
	stale := !c.populated || c.now().Sub(c.lastRefresh) >= c.ttl
	wasPopulated := c.populated
	c.mu.Unlock()

	if stale {
		if err := c.refresh(ctx); err != nil && !wasPopulated {
			return false, fmt.Errorf("revocation cache cold-start refresh: %w", err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.populated {
		return false, errors.New("revocation cache never populated")
	}
	if _, ok := c.jtis[jti]; ok {
		return true, nil
	}
	if revokedAt, ok := c.blanket[telegramID]; ok && !issuedAt.After(revokedAt) {
		return true, nil
	}
	return false, nil
}

// Refresh forces an immediate reload of the denylist, ignoring the TTL.
//
// Callers that have just recorded a revocation use this to close the window
// the TTL would otherwise leave open. The concrete case is Local Bridge: the
// revoke path evicts a connected daemon, the daemon reconnects within
// seconds, and that reconnect is authenticated against this cache — against a
// snapshot that predates the revocation, if nothing forced it forward. The
// evicted credential would then simply reconnect with itself.
func (c *RevocationCache) Refresh(ctx context.Context) error {
	return c.refresh(ctx)
}

// refresh reloads the denylist from the store. Safe for concurrent callers:
// a race between two callers both observing a stale cache just issues the
// same idempotent read twice, which is harmless for a single-digit-row
// table and simpler than adding a singleflight for it.
func (c *RevocationCache) refresh(ctx context.Context) error {
	// Stamped before the read, not after: a snapshot's freshness is decided
	// by when it looked at the database, not by when its query happened to
	// return.
	readStartedAt := c.now()
	rows, err := c.store.ListWorkerTokenRevocations(ctx)
	if err != nil {
		return fmt.Errorf("refresh worker token revocation cache: %w", err)
	}
	jtis := make(map[string]struct{}, len(rows))
	blanket := make(map[int64]time.Time)
	for _, row := range rows {
		if row.Jti != "" {
			jtis[row.Jti] = struct{}{}
			continue
		}
		if cur, ok := blanket[row.TelegramID]; !ok || row.RevokedAt.After(cur) {
			blanket[row.TelegramID] = row.RevokedAt
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Discard a snapshot that read the database no later than the applied
	// one did. Without this, a slow lazy refresh that started before a
	// revocation was recorded can land after the forced refresh that
	// followed it, overwrite the denylist with pre-revocation data, and
	// stamp lastRefresh so the cache looks current — handing a just-evicted
	// daemon a clean reconnect for a whole TTL window. That is precisely the
	// containment this cache exists to provide.
	//
	// The comparison is between read-start times. Comparing an arriving
	// snapshot's start against the applied one's completion would get this
	// backwards in the other direction: a read that began earlier but
	// finished later would look newer, and would discard the fresher one.
	if c.populated && !c.readStartedAt.Before(readStartedAt) {
		return nil
	}
	c.jtis = jtis
	c.blanket = blanket
	c.populated = true
	c.readStartedAt = readStartedAt
	c.lastRefresh = c.now()
	return nil
}
