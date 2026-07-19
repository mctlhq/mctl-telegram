package telegram

import (
	"context"
	"log/slog"

	"github.com/gotd/td/telegram"
)

// AgentRuntime supplies per-user update handling for pool entries that serve
// the communication agent. The pool consults it in acquire(): a non-nil
// HandlerFor(userID) means the user's client is constructed with an
// UpdateHandler and its run callback delegates to RunFor (which typically
// runs gotd's updates.Manager for gap recovery) instead of the default
// block-until-cancelled wait.
//
// The runtime lives outside the pool (internal/agent/listener) so the pool
// stays a connection manager; nil (the default) preserves existing behavior
// for every user.
type AgentRuntime interface {
	// HandlerFor returns the update handler for the user, or nil when the
	// user is not agent-enabled (no behavior change).
	HandlerFor(userID int64) telegram.UpdateHandler
	// RunFor runs inside client.Run for agent-enabled users, after the entry
	// is marked ready. Returning an error tears the entry down (surfaced as
	// runErr); returning ctx.Err() on cancellation matches the default path.
	RunFor(ctx context.Context, userID int64, c *telegram.Client) error
}

// WithAgentRuntime wires an AgentRuntime into the pool. Must be called before
// the first Borrow (wiring happens in main.go, ahead of any traffic).
// Returns the receiver for chaining.
func (p *ClientPool) WithAgentRuntime(rt AgentRuntime) *ClientPool {
	p.agentRT = rt
	return p
}

// Pin exempts the user's pool entry from idle GC so a listener client stays
// connected without traffic. The entry itself is (re)created by the next
// Borrow. Pinned entries still die on run errors — the listener supervisor is
// responsible for re-Borrowing.
//
// If the user already has a LIVE entry that was built before the agent runtime
// was wired (runFn == nil, i.e. no UpdateHandler), it is evicted here so the
// next Borrow reconstructs it with the handler attached. Without this, enabling
// the agent for a user who happens to have an active pooled client would leave
// that unwired client alive indefinitely (GC now skips pinned ids) and the
// listener would receive nothing until a restart. Pinning an already-wired
// entry is a no-op, so the supervisor's periodic Pin does not churn the client.
func (p *ClientPool) Pin(userID int64) {
	p.mu.Lock()
	p.pinned[userID] = struct{}{}
	e, ok := p.entries[userID]
	unwired := ok && !e.stopped && e.runFn == nil
	p.mu.Unlock()
	if unwired {
		slog.Info("evicting unwired client for pinned listener", "user_id", userID)
		p.Close(userID)
	}
}

// Unpin restores normal idle GC for the user's entry and immediately tears down
// a running listener. Dropping only the GC exemption would leave a client with
// the UpdateHandler installed processing incoming updates until IdleTimeout
// elapsed — a listener that has been disabled must stop consuming updates now,
// not minutes later.
func (p *ClientPool) Unpin(userID int64) {
	p.mu.Lock()
	delete(p.pinned, userID)
	e, ok := p.entries[userID]
	listening := ok && !e.stopped && e.runFn != nil
	p.mu.Unlock()
	if listening {
		slog.Info("stopping listener client on unpin", "user_id", userID)
		p.Close(userID)
	}
}

// isPinned reports whether the user is exempt from idle GC.
func (p *ClientPool) isPinned(userID int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.pinned[userID]
	return ok
}
