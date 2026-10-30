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
	"AUTH_KEY_DUPLICATED",
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

// IsSessionAuthError reports whether err means Telegram no longer accepts
// the session's auth key, so retrying with the same session cannot succeed.
func IsSessionAuthError(err error) bool {
	return sessionErrorFor(err) != nil
}

// sessionErrorDetail is the Telegram error type behind a session-auth
// failure (AUTH_KEY_UNREGISTERED, SESSION_REVOKED, ...), recorded in
// telegram_accounts.revoked_detail. Empty when err is not an MTProto error.
func sessionErrorDetail(err error) string {
	var te *tgerr.Error
	if errors.As(err, &te) {
		return te.Type
	}
	return ""
}

// ErrPoolFull is returned by Borrow when the pool has reached its
// TELEGRAM_MAX_SESSIONS limit and cannot allocate a new client entry.
var ErrPoolFull = errors.New("telegram: session pool at capacity")

// ErrSessionRetiring is returned during the bounded interval in which an
// asynchronously rejected auth key is being revoked. It prevents acquire
// from rebuilding a client from the same still-active database row.
var ErrSessionRetiring = errors.New("telegram: session is being retired")

// ErrSessionRevokePersistFailed marks a call-wide Borrow failure where
// Telegram rejected the session AND persisting that revoke to the DB itself
// failed. It deliberately does NOT wrap one of the user-facing session
// sentinels (db.ErrSessionRevoked etc.): those tell the caller "reconnect
// and you're set", which would be misleading here — the DB write never
// completed, so the dead row may still be loadable and we cannot promise a
// clean recovery. Callers that only need to know "is this call-wide, should
// I abort/stop retrying" (e.g. fetchMediaInline's isSystemicPoolErr) should
// check this alongside the session sentinels; callers rendering a
// user-facing message (sessionErrText) must NOT treat it the same as a
// clean revoke.
var ErrSessionRevokePersistFailed = errors.New("telegram: session rejected but revoke could not be persisted")

// ErrStaleSession is returned by Borrow when Telegram rejected the auth key of
// a pooled client whose row was no longer active: a newer sign-in had already
// replaced it (and may have logged its key out, #913), or the user
// disconnected. Nothing is revoked, the stale client is evicted, and a retry
// loads whatever row is active now.
var ErrStaleSession = errors.New("telegram: the connection used a session that is no longer active; retry the call")

// errLoadedRowUnknown: Telegram rejected a pooled client's key, but which row
// that client loaded is unknown, so no row may be revoked for it.
var errLoadedRowUnknown = errors.New("loaded session row unknown")

const asyncSessionRevokeTimeout = 5 * time.Second

// ClientPool keeps one running gotd telegram.Client per user_id. Each entry has
// its own goroutine running client.Run(ctx, ...); the pool tears the entry down
// after IdleTimeout of inactivity. Tool handlers call Borrow() to either
// resurrect an idle entry or piggyback on a running one.
type ClientPool struct {
	APIID       int
	APIHash     string
	IdleTimeout time.Duration
	MaxSessions int // 0 = no cap; set via WithMaxSessions
	// globalMW, when non-nil, is attached to every pooled client so all live
	// sessions share one api_id-wide MTProto rate budget. Set via
	// WithGlobalMiddleware. The login client (telegram.Login) receives the same
	// instance so the whole process throttles against one shared TG_API_ID.
	globalMW telegram.Middleware
	// testDC points every pooled client at Telegram's test datacenters
	// (WithTestDC, issue #854).
	testDC bool
	// onPeerFlood, when set, is told the user id whenever a borrowed call
	// fails with PEER_FLOOD (WithPeerFloodHook).
	onPeerFlood func(userID int64)
	Store       *db.Store
	// metrics is optional; when non-nil, pool size and error counters are
	// maintained.
	metrics *metrics.Registry
	// agentRT is optional; when non-nil, acquire() asks it for a per-user
	// UpdateHandler and run callback (communication-agent listener). See
	// agentruntime.go.
	agentRT AgentRuntime

	mu      sync.Mutex
	entries map[int64]*entry
	// pinned holds user ids whose entries are exempt from idle GC (listener
	// clients that must stay connected without Borrow traffic).
	pinned map[int64]struct{}
	// retiring is a per-user tombstone held while finishRun persists an
	// asynchronous terminal-session revoke outside the global pool mutex.
	retiring map[int64]struct{}
}

type entry struct {
	client       *telegram.Client
	sessionStore *SessionStore
	lastUsed     time.Time
	cancel       context.CancelFunc
	ready        chan struct{}
	runErr       error
	stopped      bool
	// runFn, when non-nil, replaces the default block-until-cancelled run
	// callback (agent listener entries run updates.Manager here).
	runFn func(ctx context.Context) error
}

func NewClientPool(apiID int, apiHash string, idle time.Duration, store *db.Store) *ClientPool {
	return &ClientPool{
		APIID:       apiID,
		APIHash:     apiHash,
		IdleTimeout: idle,
		Store:       store,
		entries:     make(map[int64]*entry),
		pinned:      make(map[int64]struct{}),
		retiring:    make(map[int64]struct{}),
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

// WithGlobalMiddleware attaches mw to every client the pool constructs, sharing
// one api_id-wide rate limit across all live sessions. Pass the same instance
// to telegram.Login (via LoginConfig.GlobalMiddleware) so the login client is
// bound by the same budget. nil is a no-op. Returns the receiver for chaining.
func (p *ClientPool) WithGlobalMiddleware(mw telegram.Middleware) *ClientPool {
	p.globalMW = mw
	return p
}

// WithTestDC points every client the pool constructs at Telegram's test
// datacenters instead of production. Pass the same value to telegram.Login
// (via LoginConfig.TestDC), and check the store's DC stamp
// (db.Store.EnsureDCMode) before serving: a session from the other side is
// rejected by Telegram, and the pool revokes rejected sessions. Returns the
// receiver for chaining.
func (p *ClientPool) WithTestDC(on bool) *ClientPool {
	p.testDC = on
	return p
}

// deviceConfig is how every client describes itself to Telegram in
// initConnection, and so what the user sees for the session under Active
// Sessions. The login and pooled clients must send the same values: a pooled
// client that set nothing fell back to gotd's defaults (go version, "linux",
// gotd version), so after each reconnect the session the user had just
// approved as "MCTL Assistant" looked like an unknown server script.
var deviceConfig = telegram.DeviceConfig{
	DeviceModel:    "MCTL Assistant",
	SystemVersion:  "Linux",
	AppVersion:     "1.0",
	SystemLangCode: "en",
	LangCode:       "en",
}

// clientOptions is the gotd configuration every pooled client starts from.
func (p *ClientPool) clientOptions(store *SessionStore) telegram.Options {
	opts := telegram.Options{SessionStorage: store, DCList: dcList(p.testDC), Device: deviceConfig}
	if p.globalMW != nil {
		opts.Middlewares = []telegram.Middleware{p.globalMW}
	}
	return opts
}

// WithPeerFloodHook registers fn to be called with the user id each time a
// call made through Borrow fails with PEER_FLOOD, whoever made it: an MCP
// tool, the background executor or the agent listener. The server uses it
// to pause the account's writes (#849). Returns the receiver for chaining.
func (p *ClientPool) WithPeerFloodHook(fn func(userID int64)) *ClientPool {
	p.onPeerFlood = fn
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
		p.countBorrow(ctx, "error")
		return fmt.Errorf("telegram api credentials not configured (TG_API_ID / TG_API_HASH)")
	}

	if p.Store != nil {
		if reason, err := p.Store.CheckSessionValid(ctx, userID); err != nil {
			if errors.Is(err, db.ErrSessionExpired) {
				switch reason {
				case db.ReasonIdle:
					p.countBorrow(ctx, "expired_idle")
				case db.ReasonAbsolute:
					p.countBorrow(ctx, "expired_absolute")
				default:
					p.countBorrow(ctx, "error")
				}
			} else if errors.Is(err, db.ErrNoActiveSession) {
				// No connected account: the user never connected or has
				// disconnected. Telegram is never called, so this says
				// nothing about the service (mctl-telegram#974).
				p.countBorrow(ctx, "no_session")
			} else {
				p.countBorrow(ctx, "error")
			}
			return err
		}
	}

	e, err := p.acquire(userID)
	if err != nil {
		p.countBorrow(ctx, "error")
		return err
	}

	select {
	case <-e.ready:
		if e.runErr != nil {
			// client.Run can fail before the ready callback ever fires —
			// a startup-time AUTH_KEY_UNREGISTERED / SESSION_REVOKED never
			// reaches the post-fn classifier below, so classify it here too.
			if sentinel := sessionErrorFor(e.runErr); sentinel != nil && p.Store != nil {
				revoked, rErr := p.revokeRejected(ctx, userID, e, e.runErr)
				if rErr != nil {
					slog.Error("telegram session rejected at startup, revoke failed", "user_id", userID, "err", rErr)
					p.countBorrow(ctx, "error")
					// Wrap ErrSessionRevokePersistFailed, NOT sentinel: the
					// revoke never completed, so the caller must not be told
					// "reconnect and you're set" (sessionErrText's message
					// for db.ErrSessionRevoked etc.) — the dead row may still
					// be loadable. This still marks the failure as call-wide
					// for isSystemicPoolErr without claiming a clean revoke.
					return fmt.Errorf("revoke rejected session: %w: %w", ErrSessionRevokePersistFailed, rErr)
				}
				if !revoked {
					slog.Warn("telegram session rejected at startup on a row no longer active", "user_id", userID, "err", e.runErr)
					p.countBorrow(ctx, "error")
					return fmt.Errorf("%w: %v", ErrStaleSession, e.runErr)
				}
				slog.Warn("telegram session rejected at startup, revoked", "user_id", userID, "err", e.runErr)
				p.countBorrow(ctx, "error")
				return fmt.Errorf("%w: %v", sentinel, e.runErr)
			}
			if errors.Is(e.runErr, db.ErrNoActiveSession) {
				// The row was revoked between CheckSessionValid and the
				// client's LoadSession (a disconnect racing this call). The
				// session load fails before any connection to Telegram, so
				// it is the same user-side state as the pre-flight branch.
				p.countBorrow(ctx, "no_session")
			} else {
				p.countBorrow(ctx, "error")
			}
			return fmt.Errorf("telegram client failed: %w", e.runErr)
		}
	case <-ctx.Done():
		p.countBorrow(ctx, "error")
		return ctx.Err()
	}

	p.touch(userID)
	if p.Store != nil {
		p.Store.MarkLastUsed(ctx, userID)
	}
	callErr := fn(ctx, e.client)
	if p.onPeerFlood != nil && IsPeerFlood(callErr) {
		p.onPeerFlood(userID)
	}
	if sentinel := sessionErrorFor(callErr); sentinel != nil && p.Store != nil {
		// Telegram rejected the stored session — it was an unfinished
		// enable_access session, or the session was revoked / the account
		// deactivated server-side. Revoke the DB row so a reconnect re-runs
		// enable_access instead of reloading a dead session. If the revoke
		// fails the row is still loadable, so do NOT report recovery — the
		// caller must not loop the user through reauth against a dead row.
		revoked, rErr := p.revokeRejected(ctx, userID, e, callErr)
		if rErr != nil {
			slog.Error("telegram session rejected, revoke failed", "user_id", userID, "err", rErr)
			p.countBorrow(ctx, "error")
			// Wrap ErrSessionRevokePersistFailed, NOT sentinel — see the
			// matching comment in the startup-path branch above. This still
			// marks the failure as call-wide (isSystemicPoolErr) — a
			// fetch_media call whose download callback already ran
			// (attempted=true) must abort rather than fold this into
			// Skipped — without claiming a clean revoke to the user.
			return fmt.Errorf("revoke rejected session: %w: %w", ErrSessionRevokePersistFailed, rErr)
		}
		if !revoked {
			slog.Warn("telegram session rejected on a row no longer active", "user_id", userID, "err", callErr)
			p.countBorrow(ctx, "error")
			return fmt.Errorf("%w: %v", ErrStaleSession, callErr)
		}
		slog.Warn("telegram session rejected, revoked", "user_id", userID, "err", callErr)
		p.countBorrow(ctx, "error")
		return fmt.Errorf("%w: %v", sentinel, callErr)
	}
	if callErr != nil {
		p.countBorrow(ctx, borrowCallResult(callErr))
		return callErr
	}
	p.countBorrow(ctx, "ok")
	return nil
}

// countBorrow records one Pool.Borrow() exit in mctl_sessions_borrow_total,
// with the traffic class ctx carries (metrics.TrafficFrom: user unless the
// MCP layer marked the call as the monitoring canary's).
func (p *ClientPool) countBorrow(ctx context.Context, result string) {
	if p.metrics == nil {
		return
	}
	p.metrics.SessionsBorrowTotal.WithLabelValues(result, metrics.TrafficFrom(ctx)).Inc()
}

// borrowCallResult picks the mctl_sessions_borrow_total result label for an
// error returned by the caller's fn, i.e. after the pool had already handed
// out a connected client.
//
// The counter feeds the session-borrow availability SLI, which is meant to
// say whether the pool could give a caller a working session. Until this
// classifier existed every fn error landed in "error", so the SLI also
// counted two things that say nothing about the session:
//
//   - flood_wait: Telegram asked the caller to slow down (code 420, or
//     PEER_FLOOD). borrowWithRetry sleeps on FLOOD_WAIT_X and calls Borrow
//     again (never on PEER_FLOOD, see IsPeerFlood), so one tool
//     call that the user sees succeed left one "error" per retried attempt.
//     On 2026-10-06 that was 41 of the 47 errors in 24 hours and fired
//     MctlTelegramSessionBorrowSlowBurn while 99% of tool calls were ok.
//   - call_error: Telegram answered the request and refused it as the
//     caller's mistake (400 or 403: an unknown peer, a missing permission).
//     A reply of that kind is proof the session works. IsCallerRefusal is
//     the shared definition; the tool-availability SLI uses it too.
//
// Everything else stays "error", on purpose: a session-auth rejection, a
// Telegram 5xx, a transport failure, a cancelled or timed-out context, and
// any error that is not an MTProto reply at all. When the session cannot be
// shown to be healthy, the SLI keeps counting the call against it.
func borrowCallResult(err error) string {
	if sessionErrorFor(err) != nil {
		return "error"
	}
	// Checked before the 420 test: FROZEN_METHOD_INVALID is a 420 but a
	// refusal, not a flood wait.
	if IsFrozenAccount(err) {
		return "call_error"
	}
	var te *tgerr.Error
	if (errors.As(err, &te) && te.Code == 420) || IsPeerFlood(err) {
		return "flood_wait"
	}
	if IsCallerRefusal(err) {
		return "call_error"
	}
	return "error"
}

// revokeRejected evicts e and revokes the row e loaded, after Telegram
// rejected that row's auth key. Only that row: a newer sign-in may already
// have saved a replacement row, and once it logs the superseded key out
// (#913) the stale client's next call fails exactly like this, so revoking
// every active row of the user would end the session the user just created.
// finishRun does the same for exits after Borrow returned.
//
// The eviction and the revoke run under the mutex acquire() takes, so a
// concurrent reconnect cannot reload the dead row; a replacement entry already
// installed for the user is left alone. context.WithoutCancel keeps the revoke
// alive even if the request context is already done.
//
// revoked reports whether the row was still active and is now revoked; false
// with a nil error means it was no longer active (replaced or disconnected).
// A non-nil error means the revoke failed, or the row is unknown, and the
// dead row may still be loadable.
func (p *ClientPool) revokeRejected(ctx context.Context, userID int64, e *entry, cause error) (revoked bool, err error) {
	revokeCtx := context.WithoutCancel(ctx)
	rowID := int64(0)
	if e.sessionStore != nil {
		rowID = e.sessionStore.LoadedRowID()
	}
	p.mu.Lock()
	if current, ok := p.entries[userID]; ok && current == e {
		delete(p.entries, userID)
	}
	e.stopped = true
	if rowID == 0 {
		err = errLoadedRowUnknown
	} else {
		revoked, err = p.Store.RevokeSessionByID(revokeCtx, userID, rowID, "unauthorized", sessionErrorDetail(cause))
	}
	p.mu.Unlock()
	if e.cancel != nil {
		e.cancel()
	}
	return revoked, err
}

func (p *ClientPool) acquire(userID int64) (*entry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.retiring[userID]; ok {
		return nil, ErrSessionRetiring
	}
	if e, ok := p.entries[userID]; ok && !e.stopped {
		return e, nil
	}

	// Enforce TELEGRAM_MAX_SESSIONS cap. Only applies when allocating a new
	// entry (the early-return above lets existing live entries through).
	if p.MaxSessions > 0 && len(p.entries) >= p.MaxSessions {
		return nil, ErrPoolFull
	}

	store := &SessionStore{UserID: userID, Store: p.Store, Pooled: true}
	opts := p.clientOptions(store)
	// Agent-enabled users get an UpdateHandler and a custom run callback so
	// incoming updates flow through the listener instead of being dropped.
	var handler telegram.UpdateHandler
	if p.agentRT != nil {
		handler = p.agentRT.HandlerFor(userID)
	}
	if handler != nil {
		opts.UpdateHandler = handler
	}
	client := telegram.NewClient(p.APIID, p.APIHash, opts)
	var runFn func(ctx context.Context) error
	if handler != nil {
		rt := p.agentRT
		runFn = func(ctx context.Context) error {
			return rt.RunFor(ctx, userID, client)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &entry{
		client:       client,
		sessionStore: store,
		lastUsed:     time.Now(),
		cancel:       cancel,
		ready:        make(chan struct{}),
		runFn:        runFn,
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
		if e.runFn != nil {
			return e.runFn(ctx)
		}
		<-ctx.Done()
		return ctx.Err()
	})
	p.finishRun(userID, e, err)
}

// finishRun records a client exit and removes only the entry that actually
// exited. A replacement entry may already have been installed after Close or
// RemoveAtomic; deleting by user id alone would accidentally evict that newer
// client when the old goroutine eventually returned.
//
// Terminal MTProto authentication errors can arrive after Borrow has already
// returned successfully (notably from a pinned listener's updates.Manager).
// Revoke the exact DB row this entry loaded so a concurrent OAuth reconnect is
// never invalidated. Database I/O runs outside the pool mutex and with a
// deadline so one stalled tenant cannot block every pool operation.
func (p *ClientPool) finishRun(userID int64, e *entry, err error) {
	sentinel := sessionErrorFor(err)
	p.mu.Lock()
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
	current, ownsEntry := p.entries[userID]
	if ownsEntry && current == e {
		delete(p.entries, userID)
		if sentinel != nil && p.Store != nil {
			p.retiring[userID] = struct{}{}
		}
	}
	if p.metrics != nil {
		p.metrics.TelegramClientPoolSize.Dec()
	}
	p.mu.Unlock()

	if !ownsEntry || current != e || sentinel == nil || p.Store == nil {
		return
	}
	defer func() {
		p.mu.Lock()
		delete(p.retiring, userID)
		p.mu.Unlock()
	}()
	sessionID := int64(0)
	if e.sessionStore != nil {
		sessionID = e.sessionStore.LoadedRowID()
	}
	if sessionID == 0 {
		slog.Error("telegram session rejected after client exit, loaded row unknown", "user_id", userID, "err", err)
		return
	}
	revokeCtx, cancel := context.WithTimeout(context.Background(), asyncSessionRevokeTimeout)
	defer cancel()
	revoked, revokeErr := p.Store.RevokeSessionByID(revokeCtx, userID, sessionID, "unauthorized", sessionErrorDetail(err))
	if revokeErr != nil {
		slog.Error("telegram session rejected after client exit, revoke failed", "user_id", userID, "session_id", sessionID, "err", revokeErr)
		return
	}
	if revoked {
		slog.Warn("telegram session rejected after client exit, revoked", "user_id", userID, "session_id", sessionID, "err", err)
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
		if p.isPinned(userID) {
			// Listener clients stay connected regardless of Borrow traffic;
			// their lifecycle is owned by the agent supervisor.
			//
			// A pinned listener only consumes updates, so it never calls
			// Borrow and nothing else refreshes telegram_accounts.last_used_at.
			// sweeper.Sessions would then revoke a perfectly healthy listener's
			// session once the idle TTL elapsed. Heartbeat the row here so the
			// idle clock tracks the client actually being alive.
			if p.Store != nil {
				p.Store.MarkLastUsed(context.Background(), userID)
			}
			continue
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
