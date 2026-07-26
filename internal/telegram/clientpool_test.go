package telegram

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tgerr"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	_ "modernc.org/sqlite"
)

// TestSessionErrorFor checks that MTProto auth-failure codes map to the right
// session sentinel — unfinished setup vs server-side revocation — and that
// ordinary errors map to nil.
func TestSessionErrorFor(t *testing.T) {
	for _, code := range unfinishedSessionCodes {
		if got := sessionErrorFor(tgerr.New(401, code)); !errors.Is(got, db.ErrSessionUnauthorized) {
			t.Errorf("sessionErrorFor(%s) = %v, want ErrSessionUnauthorized", code, got)
		}
		// Still recognised when wrapped.
		if got := sessionErrorFor(fmt.Errorf("borrow: %w", tgerr.New(401, code))); !errors.Is(got, db.ErrSessionUnauthorized) {
			t.Errorf("sessionErrorFor(wrapped %s) = %v, want ErrSessionUnauthorized", code, got)
		}
	}
	for _, code := range revokedSessionCodes {
		if got := sessionErrorFor(tgerr.New(401, code)); !errors.Is(got, db.ErrSessionRevoked) {
			t.Errorf("sessionErrorFor(%s) = %v, want ErrSessionRevoked", code, got)
		}
	}
	for _, err := range []error{
		nil,
		errors.New("connection refused"),
		tgerr.New(400, "PEER_ID_INVALID"),
		tgerr.New(420, "FLOOD_WAIT_30"),
	} {
		if got := sessionErrorFor(err); got != nil {
			t.Errorf("sessionErrorFor(%v) = %v, want nil", err, got)
		}
	}
}

func TestFinishRun_RevokesAsyncTerminalSession(t *testing.T) {
	ctx := context.Background()
	store := newBorrowTestStore(t)
	uid, err := store.EnsureUser(ctx, "async-revoke-user", "", "test")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at)
		 VALUES($1, $2, $3, $4, $5)`,
		uid, 555, []byte("blob"), now, now.Add(60*24*time.Hour),
	); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	p := NewClientPool(1, "hash", time.Minute, store)
	e := &entry{lastUsed: time.Now(), cancel: func() {}, ready: make(chan struct{})}
	p.entries[uid] = e

	p.finishRun(uid, e, tgerr.New(406, "AUTH_KEY_DUPLICATED"))

	if _, ok := p.entries[uid]; ok {
		t.Fatal("terminal entry remained in pool")
	}
	if _, err := store.CheckSessionValid(ctx, uid); !errors.Is(err, db.ErrNoActiveSession) {
		t.Fatalf("session was not revoked: %v", err)
	}
}

func TestFinishRun_DoesNotDeleteReplacementEntry(t *testing.T) {
	p := NewClientPool(1, "hash", time.Minute, nil)
	oldEntry := &entry{lastUsed: time.Now(), cancel: func() {}, ready: make(chan struct{})}
	replacement := &entry{lastUsed: time.Now(), cancel: func() {}, ready: make(chan struct{})}
	p.entries[7] = replacement

	p.finishRun(7, oldEntry, context.Canceled)

	if got := p.entries[7]; got != replacement {
		t.Fatalf("replacement entry was removed: got %p, want %p", got, replacement)
	}
}

// TestClose_RemovesEntryUnderLock verifies the fix for the race condition
// flagged by codex on PR #2: Close() must remove the entry from p.entries
// while still holding the mutex, otherwise a concurrent acquire() can
// observe the doomed entry with stopped=false and reuse the client.
func TestClose_RemovesEntryUnderLock(t *testing.T) {
	p := NewClientPool(1, "h", time.Minute, nil)

	canceled := make(chan struct{})
	_, cancel := context.WithCancel(context.Background())
	wrapped := func() {
		cancel()
		close(canceled)
	}

	// Hand-inject an entry as if a previous Borrow had populated it.
	// We deliberately leave stopped=false to model the race window.
	e := &entry{
		lastUsed: time.Now(),
		cancel:   wrapped,
		ready:    make(chan struct{}),
	}
	close(e.ready)
	p.mu.Lock()
	p.entries[42] = e
	p.mu.Unlock()

	if !p.Close(42) {
		t.Fatal("Close should report eviction when entry exists")
	}

	// After Close, the entry must be gone from the map and marked stopped.
	p.mu.Lock()
	_, present := p.entries[42]
	p.mu.Unlock()
	if present {
		t.Fatal("entry must be removed from map under the lock")
	}
	if !e.stopped {
		t.Fatal("entry must be marked stopped under the lock")
	}

	// And the cancel function must have been invoked.
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("Close did not invoke cancel within timeout")
	}
}

func TestClose_NoEntryReturnsFalse(t *testing.T) {
	p := NewClientPool(1, "h", time.Minute, nil)
	if p.Close(999) {
		t.Fatal("Close on missing entry must return false")
	}
}

// TestRemoveAtomic_HoldsLockAcrossFn verifies the second-pass codex fix
// for PR #2: pool eviction + DB revoke must commit under the same mutex
// so a concurrent acquire() observes both effects atomically.
//
// Rather than driving an actual acquire() — which spins up a gotd client
// and dials Telegram — we probe the shared mutex directly: a goroutine
// races to grab p.mu while RemoveAtomic's fn is mid-flight. If RemoveAtomic
// truly holds the lock for the duration of fn, the goroutine cannot
// acquire it until fn returns.
func TestRemoveAtomic_HoldsLockAcrossFn(t *testing.T) {
	p := NewClientPool(1, "h", time.Minute, nil)

	canceled := make(chan struct{})
	e := &entry{
		lastUsed: time.Now(),
		cancel:   func() { close(canceled) },
		ready:    make(chan struct{}),
	}
	close(e.ready)
	p.mu.Lock()
	p.entries[42] = e
	p.mu.Unlock()

	startProbe := make(chan struct{})
	probeAcquired := make(chan struct{})
	go func() {
		<-startProbe
		p.mu.Lock()
		close(probeAcquired)
		p.mu.Unlock()
	}()

	err := p.RemoveAtomic(42, func() error {
		close(startProbe)
		// Give the probe goroutine a chance to attempt p.mu.Lock().
		time.Sleep(50 * time.Millisecond)
		select {
		case <-probeAcquired:
			t.Error("probe acquired p.mu while RemoveAtomic's fn was running — lock not held")
		default:
		}
		return nil
	})
	if err != nil {
		t.Fatalf("RemoveAtomic: %v", err)
	}

	// After RemoveAtomic returns, the probe must be able to acquire.
	select {
	case <-probeAcquired:
	case <-time.After(time.Second):
		t.Fatal("probe could not acquire p.mu after RemoveAtomic released it")
	}

	// The original entry is gone and its cancel was invoked.
	p.mu.Lock()
	_, present := p.entries[42]
	p.mu.Unlock()
	if present {
		t.Fatal("entry 42 should be evicted")
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("cancel was not invoked after RemoveAtomic returned")
	}
}

func TestRemoveAtomic_ReturnsFnError(t *testing.T) {
	p := NewClientPool(1, "h", time.Minute, nil)
	sentinel := errSentinel("boom")
	err := p.RemoveAtomic(7, func() error { return sentinel })
	if err == nil || err.Error() != "boom" {
		t.Fatalf("expected sentinel error, got %v", err)
	}
}

type errSentinel string

func (e errSentinel) Error() string { return string(e) }

// newBorrowTestStore opens an in-memory SQLite DB, applies the schema
// migration, and registers a t.Cleanup to close the connection.
func newBorrowTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}
	return &db.Store{DB: conn}
}

// TestBorrow_SessionsBorrowCounter verifies that Pool.Borrow increments
// mctl_sessions_borrow_total with the correct result label on each early-exit
// path that can be exercised without a live Telegram connection.
func TestBorrow_SessionsBorrowCounter(t *testing.T) {
	ctx := context.Background()

	t.Run("error/no_credentials", func(t *testing.T) {
		met := metrics.New()
		p := NewClientPool(0, "", time.Minute, nil)
		p.WithMetrics(met)
		_ = p.Borrow(ctx, 1, nil)
		if got := testutil.ToFloat64(met.SessionsBorrowTotal.WithLabelValues("error")); got != 1 {
			t.Errorf("expected error counter=1, got %v", got)
		}
		for _, r := range []string{"ok", "expired_idle", "expired_absolute"} {
			if got := testutil.ToFloat64(met.SessionsBorrowTotal.WithLabelValues(r)); got != 0 {
				t.Errorf("expected %s counter=0, got %v", r, got)
			}
		}
	})

	t.Run("expired_idle", func(t *testing.T) {
		store := newBorrowTestStore(t)
		uid, err := store.EnsureUser(ctx, "idle-user", "", "test")
		if err != nil {
			t.Fatalf("EnsureUser: %v", err)
		}
		now := time.Now().UTC()
		stale := now.Add(-31 * 24 * time.Hour)
		if _, err := store.DB.ExecContext(ctx,
			`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at) VALUES($1, $2, $3, $4, $5)`,
			uid, 555, []byte("blob"), stale, now.Add(60*24*time.Hour),
		); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		met := metrics.New()
		p := NewClientPool(1, "hash", time.Minute, store)
		p.WithMetrics(met)
		borErr := p.Borrow(ctx, uid, nil)
		if !errors.Is(borErr, db.ErrSessionExpired) {
			t.Fatalf("expected ErrSessionExpired, got %v", borErr)
		}
		if got := testutil.ToFloat64(met.SessionsBorrowTotal.WithLabelValues("expired_idle")); got != 1 {
			t.Errorf("expected expired_idle counter=1, got %v", got)
		}
		for _, r := range []string{"ok", "expired_absolute", "error"} {
			if got := testutil.ToFloat64(met.SessionsBorrowTotal.WithLabelValues(r)); got != 0 {
				t.Errorf("expected %s counter=0, got %v", r, got)
			}
		}
	})

	t.Run("expired_absolute", func(t *testing.T) {
		store := newBorrowTestStore(t)
		uid, err := store.EnsureUser(ctx, "abs-user", "", "test")
		if err != nil {
			t.Fatalf("EnsureUser: %v", err)
		}
		now := time.Now().UTC()
		past := now.Add(-1 * time.Hour)
		if _, err := store.DB.ExecContext(ctx,
			`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at) VALUES($1, $2, $3, $4, $5)`,
			uid, 555, []byte("blob"), now, past,
		); err != nil {
			t.Fatalf("seed session: %v", err)
		}
		met := metrics.New()
		p := NewClientPool(1, "hash", time.Minute, store)
		p.WithMetrics(met)
		borErr := p.Borrow(ctx, uid, nil)
		if !errors.Is(borErr, db.ErrSessionExpired) {
			t.Fatalf("expected ErrSessionExpired, got %v", borErr)
		}
		if got := testutil.ToFloat64(met.SessionsBorrowTotal.WithLabelValues("expired_absolute")); got != 1 {
			t.Errorf("expected expired_absolute counter=1, got %v", got)
		}
		for _, r := range []string{"ok", "expired_idle", "error"} {
			if got := testutil.ToFloat64(met.SessionsBorrowTotal.WithLabelValues(r)); got != 0 {
				t.Errorf("expected %s counter=0, got %v", r, got)
			}
		}
	})

	t.Run("error/pool_full", func(t *testing.T) {
		met := metrics.New()
		p := NewClientPool(1, "hash", time.Minute, nil)
		p.WithMetrics(met).WithMaxSessions(1)
		// Inject one live entry so the pool is at capacity.
		e := &entry{lastUsed: time.Now(), cancel: func() {}, ready: make(chan struct{})}
		close(e.ready)
		p.mu.Lock()
		p.entries[10] = e
		p.mu.Unlock()

		borErr := p.Borrow(ctx, 99, func(_ context.Context, _ *telegram.Client) error { return nil })
		if !errors.Is(borErr, ErrPoolFull) {
			t.Fatalf("expected ErrPoolFull, got %v", borErr)
		}
		if got := testutil.ToFloat64(met.SessionsBorrowTotal.WithLabelValues("error")); got != 1 {
			t.Errorf("expected error counter=1, got %v", got)
		}
		for _, r := range []string{"ok", "expired_idle", "expired_absolute"} {
			if got := testutil.ToFloat64(met.SessionsBorrowTotal.WithLabelValues(r)); got != 0 {
				t.Errorf("expected %s counter=0, got %v", r, got)
			}
		}
	})
}

// TestBorrow_RevokePersistFailureMarksSystemicNotSentinel locks in the fix
// for a Codex P2 ("Keep failed revocations out of session sentinels"): when
// Telegram rejects the session inside fn AND persisting that revoke to the
// DB then fails, the returned error must
//  1. satisfy errors.Is against telegram.ErrSessionRevokePersistFailed, so
//     callers that need to know "is this call-wide, should I abort" (e.g.
//     isSystemicPoolErr) can still recognize it, but
//  2. NOT satisfy errors.Is against the user-facing session sentinel
//     (db.ErrSessionRevoked) — the DB write never completed, so telling the
//     user "reconnect and you're set" (sessionErrText's message) would be
//     misleading; the dead row may still be loadable.
//
// An earlier fix wrapped the sentinel directly to solve (1), which satisfied
// isSystemicPoolErr but broke (2) — Codex caught the regression on the very
// next review round.
func TestBorrow_RevokePersistFailureMarksSystemicNotSentinel(t *testing.T) {
	ctx := context.Background()
	store := newBorrowTestStore(t)
	uid, err := store.EnsureUser(ctx, "revoke-fail-user", "", "test")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at) VALUES($1, $2, $3, $4, $5)`,
		uid, 555, []byte("blob"), now, now.Add(60*24*time.Hour),
	); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	p := NewClientPool(1, "hash", time.Minute, store)
	// Inject a synthetic ready entry so acquire() returns it without dialing
	// Telegram — mirrors TestPoolFull / the error/pool_full subtest above.
	e := &entry{lastUsed: time.Now(), cancel: func() {}, ready: make(chan struct{})}
	close(e.ready)
	p.mu.Lock()
	p.entries[uid] = e
	p.mu.Unlock()

	borErr := p.Borrow(ctx, uid, func(context.Context, *telegram.Client) error {
		// Close the DB now, inside fn — CheckSessionValid already ran (it
		// happens before acquire()/fn), so this only breaks the *later*
		// revokeRejected -> RevokeActiveSession write, simulating a DB that
		// goes unavailable mid-call.
		_ = store.DB.Close()
		return tgerr.New(401, "SESSION_REVOKED")
	})
	if borErr == nil {
		t.Fatal("expected a non-nil error")
	}
	if !errors.Is(borErr, ErrSessionRevokePersistFailed) {
		t.Errorf("Borrow() error = %v, want errors.Is(_, ErrSessionRevokePersistFailed)", borErr)
	}
	if errors.Is(borErr, db.ErrSessionRevoked) {
		t.Errorf("Borrow() error = %v, must NOT satisfy errors.Is(_, db.ErrSessionRevoked) — the revoke never persisted, so sessionErrText must not render the misleading \"reconnect and you're set\" message", borErr)
	}
}

// TestPoolFull verifies that a pool with MaxSessions=2 returns ErrPoolFull on
// the third acquire when two entries are already live. It does NOT attempt to
// dial Telegram — the pool is seeded with hand-injected entries so no actual
// client goroutine is started.
func TestPoolFull(t *testing.T) {
	p := NewClientPool(1, "h", time.Minute, nil)
	p.WithMaxSessions(2)

	// Inject two synthetic live entries (stopped=false, ready channel closed).
	for _, uid := range []int64{1, 2} {
		e := &entry{
			lastUsed: time.Now(),
			cancel:   func() {},
			ready:    make(chan struct{}),
		}
		close(e.ready)
		p.mu.Lock()
		p.entries[uid] = e
		p.mu.Unlock()
	}

	// A third acquire for a new user id must return ErrPoolFull.
	_, err := p.acquire(99)
	if !errors.Is(err, ErrPoolFull) {
		t.Fatalf("expected ErrPoolFull when pool is at cap, got: %v", err)
	}

	// Acquiring for an existing uid must succeed (live entry reuse).
	e, err := p.acquire(1)
	if err != nil {
		t.Fatalf("expected acquire(1) to succeed (live entry reuse), got: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil entry for existing uid 1")
	}
}

// TestWithMaxSessions_ZeroMeansNoCap confirms that MaxSessions=0 (default)
// imposes no cap: the pool does not return ErrPoolFull even when many entries
// are present.
func TestWithMaxSessions_ZeroMeansNoCap(t *testing.T) {
	p := NewClientPool(1, "h", time.Minute, nil)
	// MaxSessions defaults to 0 — no cap.

	// Inject 5 synthetic entries to simulate a full pool.
	for i := int64(1); i <= 5; i++ {
		uid := i
		e := &entry{
			lastUsed: time.Now(),
			cancel:   func() {},
			ready:    make(chan struct{}),
		}
		close(e.ready)
		p.mu.Lock()
		p.entries[uid] = e
		p.mu.Unlock()
	}

	// Call acquire for a new uid (not in the 5 synthetic entries) and confirm
	// that ErrPoolFull is not returned. This exercises the runtime path directly
	// rather than asserting a boolean derived from the implementation details.
	e, err := p.acquire(99)
	if err != nil {
		t.Fatalf("MaxSessions=0 must not cap the pool: acquire returned %v", err)
	}
	// Stop the goroutines spawned by acquire so they do not outlive the test.
	if e != nil {
		e.cancel()
	}
}
