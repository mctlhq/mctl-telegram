package telegram

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tgerr"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// unfinishedSessionCodes are MTProto errors meaning the stored session never
// completed authorization — typically an enable_access flow abandoned at the
// 2FA step. The fix is for the user to finish the in-browser setup.
var unfinishedSessionCodes = []string{
	"SESSION_PASSWORD_NEEDED",
}

// revokedSessionCodes are MTProto errors meaning a once-good session was
// killed server-side: signed out from another device, or the account was
// expired/deactivated/banned. These are NOT half-finished setups — the
// user-facing message must not mention 2FA.
var revokedSessionCodes = []string{
	"AUTH_KEY_UNREGISTERED",
	"AUTH_KEY_INVALID",
	"SESSION_REVOKED",
	"SESSION_EXPIRED",
	"USER_DEACTIVATED",
	"USER_DEACTIVATED_BAN",
}

// sessionErrorFor classifies an MTProto error into the matching session
// sentinel — db.ErrSessionUnauthorized for an unfinished login,
// db.ErrSessionRevoked for a server-side kill — or nil when err is not a
// session-auth failure at all.
func sessionErrorFor(err error) error {
	switch {
	case tgerr.Is(err, unfinishedSessionCodes...):
		return db.ErrSessionUnauthorized
	case tgerr.Is(err, revokedSessionCodes...):
		return db.ErrSessionRevoked
	default:
		return nil
	}
}

// ClientPool keeps one running gotd telegram.Client per user_id. Each entry has
// its own goroutine running client.Run(ctx, ...); the pool tears the entry down
// after IdleTimeout of inactivity. Tool handlers call Borrow() to either
// resurrect an idle entry or piggyback on a running one.
type ClientPool struct {
	APIID       int
	APIHash     string
	IdleTimeout time.Duration
	Store       *db.Store

	mu      sync.Mutex
	entries map[int64]*entry
}

type entry struct {
	client   *telegram.Client
	lastUsed time.Time
	cancel   context.CancelFunc
	ready    chan struct{}
	runErr   error
	stopped  bool
}

func NewClientPool(apiID int, apiHash string, idle time.Duration, store *db.Store) *ClientPool {
	return &ClientPool{
		APIID:       apiID,
		APIHash:     apiHash,
		IdleTimeout: idle,
		Store:       store,
		entries:     make(map[int64]*entry),
	}
}

// Borrow returns a connected *telegram.Client for the user. The caller MUST
// only use it until fn returns; the pool refreshes the lastUsed marker.
//
// Pre-flight: the session's idle and absolute TTLs are checked against the
// DB *before* acquire(). An expired session is revoked in-place and the
// caller receives db.ErrSessionExpired so the user sees a clean error
// instead of an opaque MTProto failure later. After fn returns, the
// session's last_used_at is bumped so the idle-TTL clock resets while
// the user is active.
func (p *ClientPool) Borrow(ctx context.Context, userID int64, fn func(ctx context.Context, c *telegram.Client) error) error {
	if p.APIID == 0 || p.APIHash == "" {
		return fmt.Errorf("telegram api credentials not configured (TG_API_ID / TG_API_HASH)")
	}

	if p.Store != nil {
		if _, err := p.Store.CheckSessionValid(ctx, userID); err != nil {
			return err
		}
	}

	e, err := p.acquire(userID)
	if err != nil {
		return err
	}

	select {
	case <-e.ready:
		if e.runErr != nil {
			return fmt.Errorf("telegram client failed: %w", e.runErr)
		}
	case <-ctx.Done():
		return ctx.Err()
	}

	p.touch(userID)
	if p.Store != nil {
		p.Store.MarkLastUsed(ctx, userID)
	}
	callErr := fn(ctx, e.client)
	if sentinel := sessionErrorFor(callErr); sentinel != nil && p.Store != nil {
		// Telegram rejected the stored session — it was an unfinished
		// enable_access session, or the session was revoked / the account
		// deactivated server-side. Evict the pool entry and revoke the DB
		// row under the same mutex acquire() takes, so a reconnect re-runs
		// enable_access instead of reloading a dead session.
		// context.WithoutCancel keeps the revoke alive even if the request
		// context is already done.
		revokeCtx := context.WithoutCancel(ctx)
		_ = p.RemoveAtomic(userID, func() error {
			_, rErr := p.Store.RevokeActiveSession(revokeCtx, userID)
			return rErr
		})
		slog.Warn("telegram session rejected, revoked", "user_id", userID, "err", callErr)
		return fmt.Errorf("%w: %v", sentinel, callErr)
	}
	return callErr
}

func (p *ClientPool) acquire(userID int64) (*entry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if e, ok := p.entries[userID]; ok && !e.stopped {
		return e, nil
	}

	store := &SessionStore{UserID: userID, Store: p.Store}
	client := telegram.NewClient(p.APIID, p.APIHash, telegram.Options{
		SessionStorage: store,
	})
	ctx, cancel := context.WithCancel(context.Background())
	e := &entry{
		client:   client,
		lastUsed: time.Now(),
		cancel:   cancel,
		ready:    make(chan struct{}),
	}
	p.entries[userID] = e

	go p.run(ctx, userID, e)
	go p.gc(userID, e)
	return e, nil
}

func (p *ClientPool) run(ctx context.Context, userID int64, e *entry) {
	err := e.client.Run(ctx, func(ctx context.Context) error {
		close(e.ready)
		<-ctx.Done()
		return ctx.Err()
	})
	p.mu.Lock()
	defer p.mu.Unlock()
	e.stopped = true
	if err != nil && err != context.Canceled {
		e.runErr = err
		// Ready channel may not have been closed if client.Run errored before fn.
		select {
		case <-e.ready:
		default:
			close(e.ready)
		}
		slog.Warn("telegram client exited", "user_id", userID, "err", err)
	}
	delete(p.entries, userID)
}

func (p *ClientPool) gc(userID int64, e *entry) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for range tick.C {
		p.mu.Lock()
		stopped := e.stopped
		idle := time.Since(e.lastUsed)
		p.mu.Unlock()
		if stopped {
			return
		}
		if idle >= p.IdleTimeout {
			slog.Info("idle telegram client, closing", "user_id", userID, "idle", idle)
			e.cancel()
			return
		}
	}
}

func (p *ClientPool) touch(userID int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.entries[userID]; ok {
		e.lastUsed = time.Now()
	}
}

// Close evicts the pool entry for a single user, cancelling the running
// client. Returns true if there was an entry to evict. Safe to call when
// no entry exists.
//
// NOTE: Close alone is NOT race-free against a concurrent Borrow that
// arrives during the gap between Close and any subsequent DB-side
// revocation: acquire() may build a fresh entry and the new entry's
// SessionStorage may load the not-yet-revoked session. Self-service
// disconnect/delete must use RemoveAtomic instead, which holds the pool
// mutex across the DB call so acquire() blocks until both the eviction
// and the DB revoke are committed.
func (p *ClientPool) Close(userID int64) bool {
	p.mu.Lock()
	e, ok := p.entries[userID]
	if ok {
		e.stopped = true
		delete(p.entries, userID)
	}
	p.mu.Unlock()
	if !ok {
		return false
	}
	e.cancel()
	return true
}

// RemoveAtomic evicts the pool entry for the user AND runs fn() while
// holding the same mutex acquire() takes. Returns fn()'s error (or nil
// if fn was nil). Used to make self-service disconnect/delete atomic
// against concurrent Borrow:
//
//  1. acquire() blocks on p.mu until RemoveAtomic releases it
//  2. inside RemoveAtomic the entry is marked stopped + removed from the
//     map *and* the DB-side revocation runs to completion
//  3. by the time acquire() resumes, the entry is gone AND the DB row no
//     longer has an active session, so the fresh entry's SessionStorage
//     load returns nil and gotd refuses to start
//
// fn is expected to be short-lived (single DB UPDATE/DELETE). It runs
// under the pool mutex, so it must not call any other pool method or
// it would deadlock. cancel() on the evicted entry runs after the lock
// is released to avoid blocking on run()'s cleanup goroutine.
func (p *ClientPool) RemoveAtomic(userID int64, fn func() error) error {
	p.mu.Lock()
	e, hadEntry := p.entries[userID]
	if hadEntry {
		e.stopped = true
		delete(p.entries, userID)
	}
	var err error
	if fn != nil {
		err = fn()
	}
	p.mu.Unlock()
	if hadEntry {
		e.cancel()
	}
	return err
}

func (p *ClientPool) Shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries {
		e.cancel()
	}
}
