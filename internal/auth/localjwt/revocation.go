package localjwt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

// MaxRevocationSnapshotAge bounds how old a served snapshot may be, measured
// from when its read began, whatever happened to later refreshes. A populated
// cache whose refreshes keep failing serves its last good snapshot only up to
// this age; past it every check returns an error, so callers refuse the token
// as unverifiable (#1346). Without the bound, an unreadable store would be
// read as "nothing newly revoked" for as long as the outage lasts, and a
// revocation recorded in that time would never take effect. It equals
// MaxRevocationCacheTTL so the documented propagation delay holds on the
// failure path too.
const MaxRevocationSnapshotAge = MaxRevocationCacheTTL

// RevocationRefreshTimeout bounds one read of worker_token_revocations.
// Without it a read waits for as long as the caller's request lives: a
// shared-pg that hangs instead of failing, or a connection pool held by slow
// queries, then ends every refresh with the client giving up (context
// Canceled), which is deliberately not counted as a refresh failure, so the
// outage refuses every worker token while the failure counter stays flat.
// With this deadline such a read ends as a counted failure, and a request
// that has to refresh inline waits at most this long. It does NOT keep a
// hung-store check inside the bound: an inline refresh starts only once the
// snapshot is at least one TTL old (10s by default), so a read that runs to
// this deadline returns with the snapshot at 15s or more and the check is
// refused. That is the fail-closed outcome #1346 asks for, not a stale
// answer. What keeps checks inside the bound is the background refresher
// (RevocationRefreshInterval): with RevocationRefreshInterval +
// RevocationRefreshTimeout <= DefaultRevocationCacheTTL, a healthy store,
// however slow up to this deadline, refreshes the snapshot before any
// request finds it stale. Long enough that a slow but healthy read of a
// single-digit-row table does not trip it.
const RevocationRefreshTimeout = 5 * time.Second

// RevocationRefreshInterval is how often RunRefresher reloads the denylist,
// independently of traffic. Two reasons, both from #1346's outage shape:
//
//   - Workers exit on their first 401 and come back only through
//     CrashLoopBackOff (up to 5 minutes apart), so request-driven refreshes
//     stop almost as soon as an outage starts. A store failure must still be
//     observed at a rate the server sets: one read per interval.
//   - A snapshot kept younger than the TTL means the request path almost
//     never refreshes inline, so a healthy but slow store adds no latency
//     to token checks.
//
// See RevocationRefreshTimeout for how the two combine with the TTL.
const RevocationRefreshInterval = 5 * time.Second

// errRefreshDeadline is the cause attached to the refresh read's own
// deadline. context.Cause on the read's context returns it only when that
// deadline, and not the caller's context, ended the read.
var errRefreshDeadline = errors.New("revocation refresh read exceeded RevocationRefreshTimeout")

// ErrRevocationSnapshotTooOld is returned when no snapshot younger than
// MaxRevocationSnapshotAge is available: the latest refresh failed, or the
// read that produced the newest snapshot took longer than the bound.
var ErrRevocationSnapshotTooOld = errors.New("revocation cache snapshot is older than its bound")

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
	// refreshTimeout is RevocationRefreshTimeout; a field only so tests can
	// shorten it.
	refreshTimeout time.Duration
	// createdAt stands in for the read start while the cache has never
	// populated: no snapshot is younger than the process's cache, so that
	// is the age SnapshotAge reports rather than zero or "unknown".
	createdAt time.Time

	// onRefreshError, when set, is called once per failed refresh (the
	// server wires it to mctl_worker_token_revocation_refresh_failures_total).
	onRefreshError func()

	mu        sync.Mutex
	populated bool
	// readStartedAt is when the applied snapshot's read BEGAN. It decides
	// whether an arriving snapshot is newer than the applied one (see
	// refresh), when the next refresh is due (TTL) and how old the served
	// snapshot is (MaxRevocationSnapshotAge). A snapshot's freshness is when
	// it looked at the database, not when its query happened to return.
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
		store:          store,
		ttl:            ttl,
		now:            time.Now,
		refreshTimeout: RevocationRefreshTimeout,
		createdAt:      time.Now(),
		jtis:           make(map[string]struct{}),
		blanket:        make(map[int64]time.Time),
	}
}

// SetRefreshErrorHook registers f to be called once per failed refresh. Call
// it before the cache is shared; it is not synchronised with checks.
func (c *RevocationCache) SetRefreshErrorHook(f func()) {
	c.onRefreshError = f
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
// failure is tolerated and the last good snapshot is served, so a short DB
// blip does not turn every worker-token request into a 401 — but only while
// that snapshot is younger than MaxRevocationSnapshotAge. An older snapshot
// is an error, never "not revoked" (#1346).
func (c *RevocationCache) IsRevoked(ctx context.Context, jti string, telegramID int64, issuedAt time.Time) (bool, error) {
	return c.check(ctx, jti, true, telegramID, issuedAt)
}

// IsBlanketRevoked is the blanket half of IsRevoked: it reports whether
// telegramID carries a blanket revocation recorded at or after issuedAt,
// without any jti lookup. Same refresh and fail-closed rules as IsRevoked.
func (c *RevocationCache) IsBlanketRevoked(ctx context.Context, telegramID int64, issuedAt time.Time) (bool, error) {
	return c.check(ctx, "", false, telegramID, issuedAt)
}

func (c *RevocationCache) check(ctx context.Context, jti string, checkJti bool, telegramID int64, issuedAt time.Time) (bool, error) {
	c.mu.Lock()
	// Staleness and the age bound both count from when the applied
	// snapshot's read began. Counting staleness from when the read finished
	// would leave a window, as long as the read took, in which no refresh
	// is attempted yet the snapshot is already past the bound: a spurious
	// refusal with no refresh failure behind it.
	stale := !c.populated || c.now().Sub(c.readStartedAt) >= c.ttl
	wasPopulated := c.populated
	c.mu.Unlock()

	if stale {
		if err := c.refresh(ctx); err != nil && !wasPopulated {
			return false, fmt.Errorf("revocation cache cold-start refresh: %w", err)
		}
	}

	// A check that was not stale a moment ago can find the snapshot past
	// the bound when it reads it: with the TTL at MaxRevocationCacheTTL the
	// two are the same instant, and any delay carries a check across. Such
	// a check refreshes once and looks again, with the age taken under the
	// same lock as the lookup it guards. Only a snapshot still past the
	// bound after this call's own refresh attempt is refused.
	refreshed := stale
	for {
		revoked, tooOld, err := c.lookup(jti, checkJti, telegramID, issuedAt)
		if !tooOld || refreshed {
			return revoked, err
		}
		refreshed = true
		_ = c.refresh(ctx)
	}
}

// callerCanceled reports whether a failed read ended because the caller
// canceled its context, rather than because the store failed or the read's
// own deadline expired. Only that case goes uncounted: a request the client
// abandoned is not a store failure, and counting it would make the metric
// follow traffic rather than outages. The read's own deadline is told apart
// by its cause, not by the error text: when it fires first, context.Cause
// of readCtx is errRefreshDeadline even if the caller cancels afterwards.
func callerCanceled(ctx, readCtx context.Context) bool {
	if errors.Is(context.Cause(readCtx), errRefreshDeadline) {
		return false
	}
	return errors.Is(ctx.Err(), context.Canceled)
}

// lookup answers from the applied snapshot. tooOld reports a snapshot past
// MaxRevocationSnapshotAge, which is refused with ErrRevocationSnapshotTooOld.
func (c *RevocationCache) lookup(jti string, checkJti bool, telegramID int64, issuedAt time.Time) (revoked, tooOld bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.populated {
		return false, false, errors.New("revocation cache never populated")
	}
	if age := c.now().Sub(c.readStartedAt); age > MaxRevocationSnapshotAge {
		return false, true, fmt.Errorf("%w: %s old, bound %s", ErrRevocationSnapshotTooOld, age.Round(time.Millisecond), MaxRevocationSnapshotAge)
	}
	if checkJti {
		if _, ok := c.jtis[jti]; ok {
			return true, false, nil
		}
	}
	if revokedAt, ok := c.blanket[telegramID]; ok && !issuedAt.After(revokedAt) {
		return true, false, nil
	}
	return false, false, nil
}

// SnapshotAge is how old the served snapshot is, measured from when its read
// began: the age MaxRevocationSnapshotAge bounds. Past that bound every
// check is refused, so this is the direct signal of #1346's outage whatever
// the traffic. A cache that has never populated reports the time since it
// was created, never zero: could not load is not fresh.
func (c *RevocationCache) SnapshotAge() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.populated {
		return c.now().Sub(c.createdAt)
	}
	return c.now().Sub(c.readStartedAt)
}

// RunRefresher reloads the denylist every RevocationRefreshInterval until
// ctx ends, starting with one load at once. Run it once per cache, on the
// server's lifetime context. Failures go through the same counted path as
// request-driven refreshes, so while the store is unreadable the failure
// counter moves at least once per interval with no traffic at all.
//
// Reads run one at a time on this goroutine, each bounded by
// RevocationRefreshTimeout, so a hung store cannot pile up refresher reads:
// a tick that arrives while a read is running waits (time.Ticker keeps at
// most one) and the rest are dropped. A request-path refresh is a separate
// read with its own context and is counted separately: the counter is
// failed reads, not failed checks. ctx ending stops the loop and aborts a
// read in flight; that abort is a caller cancel and is not counted.
func (c *RevocationCache) RunRefresher(ctx context.Context) {
	t := time.NewTicker(RevocationRefreshInterval)
	defer t.Stop()
	c.RunRefresherOn(ctx, t.C)
}

// RunRefresherOn is RunRefresher driven by tick instead of its own ticker:
// one load at once, then one per value received, until ctx ends. Tests use
// it with a manual channel; a send on an unbuffered one completes only when
// the previous refresh has finished.
func (c *RevocationCache) RunRefresherOn(ctx context.Context, tick <-chan time.Time) {
	failing := false
	refreshOnce := func() {
		err := c.refresh(ctx)
		switch {
		case err != nil && ctx.Err() == nil && !failing:
			failing = true
			slog.Warn("worker token revocation refresher: refresh failing", "err", err)
		case err == nil && failing:
			failing = false
			slog.Info("worker token revocation refresher: refresh recovered")
		}
	}
	refreshOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			refreshOnce()
		}
	}
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
// table and simpler than adding a singleflight for it. There is no shared
// in-flight read, so one caller's cancel aborts only its own read, and each
// read is bounded by refreshTimeout: a hung store holds a request for at
// most that long, never indefinitely.
func (c *RevocationCache) refresh(ctx context.Context) error {
	// Derived from the caller's context, so a caller that goes away still
	// aborts its read at once; the deadline only adds an upper bound.
	readCtx, cancel := context.WithTimeoutCause(ctx, c.refreshTimeout, errRefreshDeadline)
	defer cancel()
	// Stamped before the read, not after: a snapshot's freshness is decided
	// by when it looked at the database, not by when its query happened to
	// return.
	readStartedAt := c.now()
	rows, err := c.store.ListWorkerTokenRevocations(readCtx)
	if err != nil {
		if c.onRefreshError != nil && !callerCanceled(ctx, readCtx) {
			c.onRefreshError()
		}
		// The driver reports only "context deadline exceeded"; name our
		// own deadline so the log says the store hung, not the client.
		if errors.Is(context.Cause(readCtx), errRefreshDeadline) {
			err = fmt.Errorf("%w: %w", errRefreshDeadline, err)
		}
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
	// mark the cache current — handing a just-evicted
	// daemon a clean reconnect for a whole TTL window. That is precisely the
	// containment this cache exists to provide.
	//
	// The comparison is between read-start times. Comparing an arriving
	// snapshot's start against the applied one's completion would get this
	// backwards in the other direction: a read that began earlier but
	// finished later would look newer, and would discard the fresher one.
	//
	// Ties apply rather than discard. Two reads that began in the same clock
	// tick are indistinguishable by timestamp, so the tie has to break one
	// way by fiat; it breaks towards the later arrival because the caller
	// that forces a refresh does so immediately after writing a revocation,
	// and dropping that snapshot is the one outcome with a security cost.
	if c.populated && c.readStartedAt.After(readStartedAt) {
		return nil
	}
	c.jtis = jtis
	c.blanket = blanket
	c.populated = true
	c.readStartedAt = readStartedAt
	return nil
}
