package localjwt

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// holdOnlyConnection reserves the store's single connection (SQLite opens
// exactly one), so every query waits for a free connection until its
// context ends. That is the hung-store shape #1346's alert could not see:
// an exhausted pool or a shared-pg that never answers, where nothing fails
// and the read simply waits.
func holdOnlyConnection(t *testing.T, store *db.Store) {
	t.Helper()
	conn, err := store.DB.Conn(context.Background())
	if err != nil {
		t.Fatalf("reserve connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	// Prove the hold works: a query with a short deadline must wait out
	// that deadline instead of running.
	probeCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	var one int
	if err := store.DB.QueryRowContext(probeCtx, "SELECT 1").Scan(&one); err == nil {
		t.Fatal("a second connection was available; the store is not held")
	}
}

// refreshWithin runs fn in a goroutine and fails the test if it has not
// returned within limit. Without the read's own deadline a held store blocks
// forever, and that must be a test failure, not a hung test binary.
func refreshWithin(t *testing.T, limit time.Duration, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(limit):
		t.Fatalf("refresh did not return within %s: the read has no deadline of its own", limit)
		return nil
	}
}

func TestRevocationRefreshTimeout_InsideSnapshotBound(t *testing.T) {
	if RevocationRefreshTimeout <= 0 {
		t.Fatalf("RevocationRefreshTimeout = %s, want > 0", RevocationRefreshTimeout)
	}
	// A check that has to refresh must still answer inside the age bound:
	// a read allowed to run past it would make every refusal wait it out.
	if RevocationRefreshTimeout >= MaxRevocationSnapshotAge {
		t.Fatalf("RevocationRefreshTimeout = %s, want below MaxRevocationSnapshotAge (%s)",
			RevocationRefreshTimeout, MaxRevocationSnapshotAge)
	}
	if c := NewRevocationCache(newTestLocaljwtStore(t), 0); c.refreshTimeout != RevocationRefreshTimeout {
		t.Fatalf("NewRevocationCache refreshTimeout = %s, want RevocationRefreshTimeout (%s)",
			c.refreshTimeout, RevocationRefreshTimeout)
	}
}

// A read that waits on a held store ends at the cache's own deadline and is
// counted exactly once, though the caller's context never ends.
func TestRevocationCache_HungStoreCountsOneFailureAtDeadline(t *testing.T) {
	store := newTestLocaljwtStore(t)
	cache := NewRevocationCache(store, DefaultRevocationCacheTTL)
	cache.refreshTimeout = 100 * time.Millisecond
	var failures atomic.Int32
	cache.SetRefreshErrorHook(func() { failures.Add(1) })
	holdOnlyConnection(t, store)

	start := time.Now()
	err := refreshWithin(t, 3*time.Second, func() error { return cache.Refresh(context.Background()) })
	if !errors.Is(err, errRefreshDeadline) {
		t.Fatalf("refresh against a held store: want an error naming the read deadline, got %v", err)
	}
	if elapsed := time.Since(start); elapsed < cache.refreshTimeout {
		t.Fatalf("refresh returned after %s, before its %s deadline: it did not wait on the store", elapsed, cache.refreshTimeout)
	}
	if got := failures.Load(); got != 1 {
		t.Fatalf("refresh failures = %d, want 1: our own deadline expiring is a store failure", got)
	}
}

// A caller that goes away before the deadline aborts the read at once (the
// deadline is derived from its context, not detached from it) and is not
// counted: an abandoned request is not a store failure.
func TestRevocationCache_CallerCancelBeforeDeadlineNotCounted(t *testing.T) {
	store := newTestLocaljwtStore(t)
	cache := NewRevocationCache(store, DefaultRevocationCacheTTL)
	cache.refreshTimeout = time.Minute
	var failures atomic.Int32
	cache.SetRefreshErrorHook(func() { failures.Add(1) })
	holdOnlyConnection(t, store)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	err := refreshWithin(t, 3*time.Second, func() error { return cache.Refresh(ctx) })
	if err == nil {
		t.Fatal("refresh with a canceled caller succeeded")
	}
	if got := failures.Load(); got != 0 {
		t.Fatalf("refresh failures = %d, want 0: a caller cancel is not a store failure", got)
	}
}

// The deadline is told apart by its cause, never by the error text: once it
// has fired, a caller cancel that follows does not turn the failure into an
// uncounted one, and a caller cancel alone never reads as our deadline.
func TestCallerCanceled_DistinguishesOwnDeadline(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	readCtx, cancelRead := context.WithTimeoutCause(parent, time.Millisecond, errRefreshDeadline)
	defer cancelRead()
	<-readCtx.Done()
	cancelParent()
	if callerCanceled(parent, readCtx) {
		t.Fatal("own deadline fired first, then the caller canceled: must count as a failure")
	}

	parent2, cancelParent2 := context.WithCancel(context.Background())
	readCtx2, cancelRead2 := context.WithTimeoutCause(parent2, time.Minute, errRefreshDeadline)
	defer cancelRead2()
	cancelParent2()
	if !callerCanceled(parent2, readCtx2) {
		t.Fatal("caller canceled before the deadline: must not count")
	}

	// A caller deadline is not a cancel; it was counted before the read had
	// a deadline of its own and still is.
	parent3, cancelParent3 := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancelParent3()
	readCtx3, cancelRead3 := context.WithTimeoutCause(parent3, time.Minute, errRefreshDeadline)
	defer cancelRead3()
	<-readCtx3.Done()
	if callerCanceled(parent3, readCtx3) {
		t.Fatal("caller deadline exceeded: must count, as before")
	}
}

// The #1346 behaviour holds when the store hangs rather than fails: within
// the bound the last good snapshot is served, past it the check is refused,
// and each check costs one bounded, counted read.
func TestRevocationCache_HungStoreStillFailsClosedPastBound(t *testing.T) {
	store := newTestLocaljwtStore(t)
	ctx := context.Background()
	base := time.Now()
	cache := NewRevocationCache(store, DefaultRevocationCacheTTL)
	cache.refreshTimeout = 50 * time.Millisecond
	var failures atomic.Int32
	cache.SetRefreshErrorHook(func() { failures.Add(1) })
	cache.now = func() time.Time { return base }
	if revoked, err := cache.IsRevoked(ctx, "jti-hung", 1, base); err != nil || revoked {
		t.Fatalf("initial populate: revoked=%v err=%v", revoked, err)
	}
	holdOnlyConnection(t, store)

	cache.now = func() time.Time { return base.Add(MaxRevocationSnapshotAge - time.Second) }
	if err := refreshWithin(t, 3*time.Second, func() error {
		_, err := cache.IsRevoked(ctx, "jti-hung", 1, base)
		return err
	}); err != nil {
		t.Fatalf("within the bound a hung refresh must serve the last good snapshot, got %v", err)
	}
	if got := failures.Load(); got != 1 {
		t.Fatalf("refresh failures within the bound = %d, want 1", got)
	}

	cache.now = func() time.Time { return base.Add(MaxRevocationSnapshotAge + time.Millisecond) }
	err := refreshWithin(t, 3*time.Second, func() error {
		_, err := cache.IsRevoked(ctx, "jti-hung", 1, base)
		return err
	})
	if !errors.Is(err, ErrRevocationSnapshotTooOld) {
		t.Fatalf("past the bound with the store hung: want ErrRevocationSnapshotTooOld, got %v", err)
	}
	if got := failures.Load(); got != 2 {
		t.Fatalf("refresh failures after the refused check = %d, want 2", got)
	}
}

// The relations the refresher depends on. With interval + timeout within
// the default TTL, a healthy store (even one slow up to the read deadline)
// refreshes the snapshot before a request finds it stale, so the request
// path does not refresh inline; and a refresher tick always lands inside
// the age bound.
func TestRevocationRefreshInterval_KeepsSnapshotWarm(t *testing.T) {
	if RevocationRefreshInterval <= 0 {
		t.Fatalf("RevocationRefreshInterval = %s, want > 0", RevocationRefreshInterval)
	}
	if got := RevocationRefreshInterval + RevocationRefreshTimeout; got > DefaultRevocationCacheTTL {
		t.Fatalf("interval + timeout = %s, want <= DefaultRevocationCacheTTL (%s)", got, DefaultRevocationCacheTTL)
	}
	if RevocationRefreshInterval >= MaxRevocationSnapshotAge {
		t.Fatalf("RevocationRefreshInterval = %s, want below MaxRevocationSnapshotAge (%s)",
			RevocationRefreshInterval, MaxRevocationSnapshotAge)
	}
}

// startRefresher runs the refresher on a manual, unbuffered tick channel.
// An unbuffered send completes only when the loop is back in its select, so
// a second send proves the refresh started by the first one has finished:
// no sleeps, no wall-clock polling.
func startRefresher(t *testing.T, cache *RevocationCache) (tick chan time.Time, stop func()) {
	t.Helper()
	tick = make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		cache.RunRefresherOn(ctx, tick)
		close(done)
	}()
	var once bool
	stop = func() {
		if once {
			return
		}
		once = true
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("refresher did not stop after its context was canceled")
		}
	}
	t.Cleanup(stop)
	return tick, stop
}

func sendTick(t *testing.T, tick chan time.Time) {
	t.Helper()
	select {
	case tick <- time.Time{}:
	case <-time.After(3 * time.Second):
		t.Fatal("refresher did not take a tick: a refresh is stuck past its deadline")
	}
}

// The refresher loads at once and reloads on every tick, with no request in
// sight: a revocation recorded later reaches the snapshot through a tick
// alone. The clock is frozen, so no check here is ever stale and no inline
// refresh can be what picked it up.
func TestRevocationCache_RefresherReloadsOnTick(t *testing.T) {
	store := newTestLocaljwtStore(t)
	ctx := context.Background()
	base := time.Now()
	cache := NewRevocationCache(store, DefaultRevocationCacheTTL)
	cache.now = func() time.Time { return base }
	tick, stop := startRefresher(t, cache)

	sendTick(t, tick) // returns once the initial load is done
	if got := cache.SnapshotAge(); got != 0 {
		t.Fatalf("snapshot age after the initial load = %s, want 0 on a frozen clock", got)
	}
	if err := store.RevokeWorkerToken(ctx, "jti-tick", 1, "", 0); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	// The tick above already started a refresh that may predate the
	// revocation; two more sends guarantee one full refresh after it.
	sendTick(t, tick)
	sendTick(t, tick)
	stop()
	revoked, err := cache.IsRevoked(ctx, "jti-tick", 1, base)
	if err != nil || !revoked {
		t.Fatalf("revocation recorded after start not picked up by the refresher: revoked=%v err=%v", revoked, err)
	}
}

// A failing store is counted once per tick (plus the initial load), whatever
// the traffic: the rate is the server's, not the clients'.
func TestRevocationCache_RefresherCountsFailuresAtTickRate(t *testing.T) {
	store := newBrokenLocaljwtStore(t, "refresher_failing")
	cache := NewRevocationCache(store, DefaultRevocationCacheTTL)
	var failures atomic.Int32
	cache.SetRefreshErrorHook(func() { failures.Add(1) })
	tick, stop := startRefresher(t, cache)
	const ticks = 5
	for range ticks {
		sendTick(t, tick)
	}
	sendTick(t, tick) // lands once the last of the 5 tick refreshes has finished
	stop()
	// Finished for sure: the initial load and the 5 ticks. The sync tick's
	// own refresh races with stop(): it is counted if it failed before the
	// cancel and not counted if the cancel aborted it.
	if got := failures.Load(); got < ticks+1 || got > ticks+2 {
		t.Fatalf("failures = %d, want %d or %d (initial load + %d ticks, plus maybe the sync tick)", got, ticks+1, ticks+2, ticks)
	}
}

// A hung store: each refresher read runs to its deadline and is counted, and
// reads never overlap, so ticks are taken one deadline apart rather than
// piling up concurrent reads.
func TestRevocationCache_RefresherHungStoreOneReadAtATime(t *testing.T) {
	store := newTestLocaljwtStore(t)
	cache := NewRevocationCache(store, DefaultRevocationCacheTTL)
	cache.refreshTimeout = 50 * time.Millisecond
	var failures atomic.Int32
	cache.SetRefreshErrorHook(func() { failures.Add(1) })
	holdOnlyConnection(t, store)

	start := time.Now()
	tick, stop := startRefresher(t, cache)
	for range 3 {
		sendTick(t, tick)
	}
	// Three sends: the first waits out the initial read, each later one the
	// read the previous tick started. Concurrent reads would take them at once.
	if elapsed, min := time.Since(start), 3*cache.refreshTimeout; elapsed < min {
		t.Fatalf("3 ticks taken in %s, want >= %s: refresher reads overlapped", elapsed, min)
	}
	stop()
	// The initial read and the first two ticks' reads ran to their deadline;
	// the third tick's read is normally aborted by stop() (not counted).
	if got := failures.Load(); got < 3 || got > 4 {
		t.Fatalf("failures = %d, want 3 (or 4 if the last read beat stop): one per read, each to its deadline", got)
	}
}

// Canceling the server context stops the loop promptly even while a read is
// hung (the read's deadline derives from that context), and that abort is
// not counted as a store failure.
func TestRevocationCache_RefresherStopsOnCancelDuringHungRead(t *testing.T) {
	store := newTestLocaljwtStore(t)
	cache := NewRevocationCache(store, DefaultRevocationCacheTTL)
	cache.refreshTimeout = time.Minute
	var failures atomic.Int32
	cache.SetRefreshErrorHook(func() { failures.Add(1) })
	holdOnlyConnection(t, store)

	_, stop := startRefresher(t, cache) // initial read is now hung
	time.Sleep(20 * time.Millisecond)   // let it reach the store; not a sync point
	start := time.Now()
	stop() // fails the test if the loop is not gone within 3s
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("refresher took %s to stop with a hung read", elapsed)
	}
	if got := failures.Load(); got != 0 {
		t.Fatalf("failures = %d, want 0: a shutdown abort is not a store failure", got)
	}
}

// SnapshotAge is the bound's own measure: from the applied snapshot's read
// start, unchanged by failing refreshes, and never zero for a cache that has
// never loaded.
func TestRevocationCache_SnapshotAge(t *testing.T) {
	store := newTestLocaljwtStore(t)
	ctx := context.Background()
	base := time.Now()
	cache := NewRevocationCache(store, DefaultRevocationCacheTTL)
	cache.createdAt = base
	cache.now = func() time.Time { return base.Add(7 * time.Second) }
	if got := cache.SnapshotAge(); got != 7*time.Second {
		t.Fatalf("never-populated age = %s, want 7s since creation", got)
	}
	cache.now = func() time.Time { return base.Add(10 * time.Second) }
	if err := cache.Refresh(ctx); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	cache.now = func() time.Time { return base.Add(13 * time.Second) }
	if got := cache.SnapshotAge(); got != 3*time.Second {
		t.Fatalf("age after a load at +10s, read at +13s = %s, want 3s", got)
	}
	if err := store.DB.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	cache.now = func() time.Time { return base.Add(30 * time.Second) }
	if err := cache.Refresh(ctx); err == nil {
		t.Fatal("refresh against a closed store succeeded")
	}
	if got := cache.SnapshotAge(); got != 20*time.Second {
		t.Fatalf("age after a failed refresh = %s, want 20s: a failure must not make the snapshot look fresh", got)
	}
}
