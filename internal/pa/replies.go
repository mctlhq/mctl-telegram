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
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// replyKinds maps every Reply to its conversation-level outbox kind.
var replyKinds = map[Reply]jobs.OutboxKind{
	ReplyConsentPrompt:      jobs.OutboxConsentPrompt,
	ReplyConsentPromptRU:    jobs.OutboxConsentPromptRU,
	ReplyConsentAccepted:    jobs.OutboxConsentAccepted,
	ReplyConsentWithdrawn:   jobs.OutboxConsentWithdrawn,
	ReplyConsentStale:       jobs.OutboxConsentStale,
	ReplyNewConversation:    jobs.OutboxNewConversation,
	ReplyForgotten:          jobs.OutboxForgotten,
	ReplyUnknownButton:      jobs.OutboxUnknownButton,
	ReplyRateLimited:        jobs.OutboxRateLimited,
	ReplyMessageTooLong:     jobs.OutboxMessageTooLong,
	ReplyLinkingUnavailable: jobs.OutboxLinkingUnavailable,
	ReplyPrincipalDisabled:  jobs.OutboxPrincipalDisabled,

	ReplyApprovalCancelled:   jobs.OutboxApprovalCancelled,
	ReplyApprovalAlreadyDone: jobs.OutboxApprovalAlreadyDone,
	ReplyApprovalExpired:     jobs.OutboxApprovalExpired,

	ReplyPermissionsUnavailable: jobs.OutboxPermissionsUnavailable,
	ReplyPermissionGranted:      jobs.OutboxPermissionGranted,
	ReplyPermissionRevoked:      jobs.OutboxPermissionRevoked,
	ReplyPermissionRefused:      jobs.OutboxPermissionRefused,
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
	// Metrics counts a reply lost to a reused update id
	// (OutboxOutcomeUpdateReused). Optional.
	Metrics OutboxCounter
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
	err := q.Store.EnqueuePAOutbox(ctx, tx, jobs.OutboxItem{
		Principal: p.TelegramID(), UpdateID: updateID, Kind: kind, Button: button,
	}, now())
	if errors.Is(err, jobs.ErrOutboxUpdateReused) {
		// The update dedup let an update through whose id already has this
		// reply: Telegram reused the id, or one update queued a kind twice.
		// The update itself stands (failing it would make Telegram
		// redeliver it forever); the reply is not sent, and that is
		// counted rather than silent.
		slog.Warn("pa reply not queued: update id already has this reply", "update_id", updateID, "kind", string(kind))
		if q.Metrics != nil {
			q.Metrics.CountPAOutbox(OutboxOutcomeUpdateReused)
		}
		return nil
	}
	return err
}
