package bot

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
)

// Delivery is what a handler receives: the routing facts of one accepted
// update, and nothing else.
//
// There is no text or payload field, by construction. This package never
// decodes message content or callback data, so a handler cannot log, store or
// forward it by accident. A handler that genuinely needs content must widen
// both Update and this struct in a change that argues for itself.
type Delivery struct {
	UpdateID int64
	Kind     string
	// ChatID is invalid when the update carried no chat.
	ChatID sql.NullInt64
}

// Handler processes one inbound update.
//
// The transaction is the whole contract. A handler's database writes MUST go
// through tx: the receiver marks the update processed in that same transaction,
// so a crash rolls the handler's work and the "done" mark back together and the
// update is redelivered from the pending sweep. A handler that writes outside
// tx, or performs an external side effect such as sending a message, is
// at-least-once and must be idempotent -- see Store.DispatchOnce.
//
// Handlers receive routing facts only: no message text and no callback payload
// are decoded by this package. A handler needing content has to widen Update
// deliberately.
type Handler interface {
	// HandleUpdate returns the outcome to record on the row, or "" for the
	// default "handled". Returning an error rolls the claim back and the
	// update is retried.
	HandleUpdate(ctx context.Context, tx *sql.Tx, d Delivery) (string, error)
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, tx *sql.Tx, d Delivery) (string, error)

// HandleUpdate implements Handler.
func (f HandlerFunc) HandleUpdate(ctx context.Context, tx *sql.Tx, d Delivery) (string, error) {
	return f(ctx, tx, d)
}

// Registry maps an update kind to the handler for it.
//
// Small on purpose: this is the seam #438's commands, #439's delivery results
// and #571's callbacks plug into, and it should stay a lookup rather than grow
// routing rules of its own. It is safe for concurrent reads after registration;
// Register is expected during startup, before the poller runs, and is
// nonetheless mutex-guarded so a late registration cannot race a poll.
type Registry struct {
	mu       sync.RWMutex
	handlers map[string]Handler
	// knownChat reports whether a chat is one the platform recognises. An
	// update from an unknown chat is dropped and counted rather than
	// dispatched -- the bot must not act on a chat that never signed in.
	// A nil knownChat admits every chat, which is only appropriate in tests.
	knownChat func(ctx context.Context, chatID int64) (bool, error)
}

// NewRegistry returns an empty registry. knownChat may be nil, in which case
// every chat is treated as known.
func NewRegistry(knownChat func(ctx context.Context, chatID int64) (bool, error)) *Registry {
	return &Registry{handlers: map[string]Handler{}, knownChat: knownChat}
}

// Register installs the handler for a kind. Registering a second handler for
// the same kind is a programming error and panics at startup rather than
// silently replacing the first -- two owners for one kind means one of them is
// never going to run, and finding that at runtime is much worse.
func (r *Registry) Register(kind string, h Handler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.handlers[kind]; exists {
		panic(fmt.Sprintf("bot: handler already registered for kind %q", kind))
	}
	r.handlers[kind] = h
}

// lookup returns the handler for a kind, if any.
func (r *Registry) lookup(kind string) (Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[kind]
	return h, ok
}

// isKnownChat reports whether the chat is recognised.
func (r *Registry) isKnownChat(ctx context.Context, chatID sql.NullInt64) (bool, error) {
	if r.knownChat == nil {
		return true, nil
	}
	if !chatID.Valid {
		return false, nil
	}
	return r.knownChat(ctx, chatID.Int64)
}
