package telegram

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tgerr"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
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

// ErrPoolFull is returned by Borrow when the pool has reached its
// TELEGRAM_MAX_SESSIONS limit and cannot allocate a new client entry.
var ErrPoolFull = errors.New("telegram: session pool at capacity")

// ClientPool keeps one running gotd telegram.Client per user_id. Each entry has
// its own goroutine running client.Run(ctx, ...); the pool tears the entry down
// after IdleTimeout of inactivity. Tool handlers call Borrow() to either
// resurrect an idle entry or piggyback on a running one.
type ClientPool struct {
	APIID       int
	APIHash     string
	IdleTimeout time.Duration
	MaxSessions int // 0 = no cap; set via WithMaxSessions
	Store       *db.Store
	// metrics is optional; when non-nil, pool size and error counters are
	// maintained.
	metrics *metrics.Registry

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

// WithMetrics wires a *metrics.Registry so pool size and MTProto client errors
// are recorded. Returns the receiver for chaining.
func (p *ClientPool) WithMetrics(m *metrics.Registry) *ClientPool {
	p.metrics = m
	return p
}

// WithMaxSessions sets an upper bound on the number of concurrently live client
// pool entries. When n > 0 and the pool already holds n entries, Borrow returns
// ErrPoolFull instead of allocating a new entry. n = 0 disables the cap
// (default, preserving previous behaviour). Returns the receiver for chaining.
func (p *ClientPool) WithMaxSessions(n int) *ClientPool {
	p.MaxSessions = n
	return p
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
		if p.metrics != nil {
			p.metrics.SessionsBorrowTotal.WithLabelValues("error").Inc()
		}
		return fmt.Errorf("telegram api credentials not configured (TG_API_ID / TG_API_HASH)")
	}

	if p.Store != nil {
		if reason, err := p.Store.CheckSessionValid(ctx, userID); err != nil {
			if errors.Is(err, db.ErrSessionExpired) {
				switch reason {
				case db.ReasonIdle:
					if p.metrics != nil {
						p.metrics.SessionsBorrowTotal.WithLabelValues("expired_idle").Inc()
					}
				case db.ReasonAbsolute:
					if p.metrics != nil {
						p.metrics.SessionsBorrowTotal.WithLabelValues("expired_absolute").Inc()
					}
				default:
					if p.metrics != nil {
						p.metrics.SessionsBorrowTotal.WithLabelValues("error").Inc()
					}
				}
			} else {
				if p.metrics != nil {
					p.metrics.SessionsBorrowTotal.WithLabelValues("error").Inc()
				}
			}
			return err
		}
	}

	e, err := p.acquire(userID)
	if err != nil {
		if p.metrics != nil {
			p.metrics.SessionsBorrowTotal.WithLabelValues("error").Inc()
		}
		return err
	}

	select {
	case <-e.ready:
		if e.runErr != nil {
			// client.Run can fail before the ready callback ever fires —
			// a startup-time AUTH_KEY_UNREGISTERED / SESSION_REVOKED never
			// reaches the post-fn classifier below, so classify it here too.
			if sentinel := sessionErrorFor(e.runErr); sentinel != nil && p.Store != nil {
				if rErr := p.revokeRejected(ctx, userID); rErr != nil {
					slog.Error("telegram session rejected at startup, revoke failed", "user_id", userID, "err", rErr)
					if p.metrics != nil {
						p.metrics.SessionsBorrowTotal.WithLabelValues("error").Inc()
					}
					return fmt.Errorf("revoke rejected session: %w", rErr)
				}
				slog.Warn("telegram session rejected at startup, revoked", "user_id", userID, "err", e.runErr)
				if p.metrics != nil {
					p.metrics.SessionsBorrowTotal.WithLabelValues("error").Inc()
				}
				return fmt.Errorf("%w: %v", sentinel, e.runErr)
			}
			if p.metrics != nil {
				p.metrics.SessionsBorrowTotal.WithLabelValues("error").Inc()
			}
			return fmt.Errorf("telegram client failed: %w", e.runErr)
		}
	case <-ctx.Done():
		if p.metrics != nil {
			p.metrics.SessionsBorrowTotal.WithLabelValues("error").Inc()
		}
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
		// deactivated server-side. Revoke the DB row so a reconnect re-runs
		// enable_access instead of reloading a dead session. If the revoke
		// fails the row is still loadable, so do NOT report recovery — the
		// caller must not loop the user through reauth against a dead row.
		if rErr := p.revokeRejected(ctx, userID); rErr != nil {
			slog.Error("telegram session rejected, revoke failed", "user_id", userID, "err", rErr)
			if p.metrics != nil {
				p.metrics.SessionsBorrowTotal.WithLabelValues("error").Inc()
			}
			return fmt.Errorf("revoke rejected session: %w", rErr)
		}
		slog.Warn("telegram session rejected, revoked", "user_id", userID, "err", callErr)
		if p.metrics != nil {
			p.metrics.SessionsBorrowTotal.WithLabelValues("error").Inc()
		}
		return fmt.Errorf("%w: %v", sentinel, callErr)
	}
	if callErr != nil {
		if p.metrics != nil {
			p.metrics.SessionsBorrowTotal.WithLabelValues("error").Inc()
		}
		return callErr
	}
	if p.metrics != nil {
		p.metrics.SessionsBorrowTotal.WithLabelValues("ok").Inc()
	}
	return nil
}

// revokeRejected evicts the pool entry and revokes the DB session for a user
// whose stored session Telegram rejected. The eviction and the DB revoke run
// under the same mutex acquire() takes, so a concurrent reconnect cannot
// reload the dead session. context.WithoutCancel keeps the revoke alive even
// if the request context is already done. Returns nil when the row was
// revoked; a non-nil error means the revoke failed and the row may still be
// loadable.
func (p *ClientPool) revokeRejected(ctx context.Context, userID int64) error {
	revokeCtx := context.WithoutCancel(ctx)
	return p.RemoveAtomic(userID, func() error {
		_, rErr := p.Store.RevokeActiveSession(revokeCtx, userID, "unauthorized")
		return rErr
	})
}

func (p *ClientPool) acquire(userID int64) (*entry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if e, ok := p.entries[userID]; ok && !e.stopped {
		return e, nil
	}

	// Enforce TELEGRAM_MAX_SESSIONS cap. Only applies when allocating a new
	// entry (the early-return above lets existing live entries through).
	if p.MaxSessions > 0 && len(p.entries) >= p.MaxSessions {
		return nil, ErrPoolFull
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
	if p.metrics != nil {
		p.metrics.TelegramClientPoolSize.Inc()
	}

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
		if p.metrics != nil {
			p.metrics.TelegramClientErrorsTotal.Inc()
		}
	}
	delete(p.entries, userID)
	if p.metrics != nil {
		p.metrics.TelegramClientPoolSize.Dec()
	}
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
