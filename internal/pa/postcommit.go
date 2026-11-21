package pa

import (
	"context"
	"errors"
)

// postcommit.go carries what an update's handler decided inside its
// transaction but must not do there: the account-linking commands and
// buttons (#1318 slice C2). Manager.Begin, Disconnect and the confirm
// button take the principal lock in their own transactions, and
// HandleUpdate already holds it in the update's transaction, so running
// them inside it would wait on itself. The handler only records the
// action; the webhook's AfterCommit runs it once the commit succeeded.
//
// A crash between the commit and AfterCommit loses the action: the update
// is already deduplicated, so Telegram does not redeliver it, and the user
// sends the command (or presses the button) again. That fails closed:
// nothing was linked, disconnected or confirmed half-way.

// LinkAction is one action for the linking flow, decided in an update's
// transaction and run after its commit.
type LinkAction struct {
	// Command is CommandConnect, CommandDisconnect or CommandConnections;
	// empty for a linking button.
	Command string
	// Arg is the command's first argument, lower case ("tg"), or "".
	Arg string
	// Button is a linking confirm or cancel button (LinkButton). Its
	// callback data is the update's; it is not consumed from pa_callbacks.
	Button bool
}

// ErrNoPostCommit: the handler ran outside a webhook delivery that can run
// an action after its commit. The update fails rather than lose the action
// silently.
var ErrNoPostCommit = errors.New("pa: no post-commit slot for this update")

type postCommitKey struct{}

// postCommitSlot holds at most one action per update delivery.
type postCommitSlot struct {
	action *LinkAction
}

// WithPostCommit returns ctx with an empty slot for one update's action.
// The webhook calls it once per delivery, before the transaction.
func WithPostCommit(ctx context.Context) context.Context {
	return context.WithValue(ctx, postCommitKey{}, &postCommitSlot{})
}

// setPostCommit records a for after the commit. It replaces an earlier
// action of the same delivery: an update carries one command or button.
func setPostCommit(ctx context.Context, a LinkAction) error {
	s, ok := ctx.Value(postCommitKey{}).(*postCommitSlot)
	if !ok || s == nil {
		return ErrNoPostCommit
	}
	s.action = &a
	return nil
}

// PostCommitAction returns the action the update's handler recorded, if
// any. Only AfterCommit calls it, after the transaction committed.
func PostCommitAction(ctx context.Context) (LinkAction, bool) {
	s, ok := ctx.Value(postCommitKey{}).(*postCommitSlot)
	if !ok || s == nil || s.action == nil {
		return LinkAction{}, false
	}
	return *s.action, true
}
