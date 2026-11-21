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
