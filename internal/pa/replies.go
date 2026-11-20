package pa

// replies.go is the production ReplyQueue (#1348): the conversation
// layer's own answers -- the consent prompt with its button, and the
// answers to /new, /forget, /consent and to a refused message or button --
// go to the outbox as conversation-level rows, in the update's transaction,
// and are delivered with the outbox's send-once rules.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// replyKinds maps every Reply to its conversation-level outbox kind.
var replyKinds = map[Reply]jobs.OutboxKind{
	ReplyConsentPrompt:    jobs.OutboxConsentPrompt,
	ReplyConsentAccepted:  jobs.OutboxConsentAccepted,
	ReplyConsentWithdrawn: jobs.OutboxConsentWithdrawn,
	ReplyConsentStale:     jobs.OutboxConsentStale,
	ReplyNewConversation:  jobs.OutboxNewConversation,
	ReplyForgotten:        jobs.OutboxForgotten,
	ReplyUnknownButton:    jobs.OutboxUnknownButton,
	ReplyRateLimited:      jobs.OutboxRateLimited,
	ReplyMessageTooLong:   jobs.OutboxMessageTooLong,
}

// ErrUnknownReply is a Reply with no outbox kind: a programming error. It
// rolls the update back rather than dropping the answer.
var ErrUnknownReply = errors.New("pa: reply has no outbox kind")

// ReplyOutbox is what OutboxReplies writes to (*db.Store).
type ReplyOutbox interface {
	EnqueuePAOutbox(ctx context.Context, tx *sql.Tx, item jobs.OutboxItem, now time.Time) error
}

// OutboxReplies queues replies as conversation-level outbox rows. The row
// stores the reply's kind and, for the consent prompt, the opaque callback
// id of its button; never text. The deliverer renders the kind's server
// template when it sends the row.
type OutboxReplies struct {
	Store ReplyOutbox
	// Now defaults to time.Now.
	Now func() time.Time
}

var _ ReplyQueue = (*OutboxReplies)(nil)

// QueueReply implements ReplyQueue.
func (q *OutboxReplies) QueueReply(ctx context.Context, tx *sql.Tx, p Principal, updateID int64, r Reply, button string) error {
	kind, ok := replyKinds[r]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownReply, string(r))
	}
	now := time.Now
	if q.Now != nil {
		now = q.Now
	}
	return q.Store.EnqueuePAOutbox(ctx, tx, jobs.OutboxItem{
		Principal: p.TelegramID(), UpdateID: updateID, Kind: kind, Button: button,
	}, now())
}
