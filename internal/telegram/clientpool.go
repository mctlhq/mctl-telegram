package telegram

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

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
func (p *ClientPool) Borrow(ctx context.Context, userID int64, fn func(ctx context.Context, c *telegram.Client) error) error {
	if p.APIID == 0 || p.APIHash == "" {
		return fmt.Errorf("telegram api credentials not configured (TG_API_ID / TG_API_HASH)")
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
	return fn(ctx, e.client)
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
// no entry exists. Used by self-service disconnect/delete so a Borrow()
// issued immediately afterwards does not piggyback on the doomed client.
//
// The entry is marked stopped and removed from the map under the same
// mutex that protects acquire(), so a concurrent Borrow() cannot observe
// the doomed entry in any reusable state — it will allocate a fresh one.
// run()'s deferred cleanup will see the entry already gone and its
// delete() becomes a no-op, which is intentional.
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

func (p *ClientPool) Shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries {
		e.cancel()
	}
}
