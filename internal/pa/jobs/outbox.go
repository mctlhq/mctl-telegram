package jobs

// The PA outbox (issue #1313 slice d2, deferral F4 of slice d1). Every bot
// message the run loop owes a principal -- the reply, the budget hold
// notice, and the run-failed and request-dropped notices -- is written to
// pa_outbox in the same transaction as the state change that owes it, and
// sent after the commit. A failed send therefore leaves the row due again
// instead of losing the message.
//
// A row stores no message text. A server notice is a kind, mapped to an
// output template when it is sent; a reply names the external-marked
// assistant fragment that holds the model's answer, and is rendered from it
// through output.Render when it is sent. A reply whose conversation was
// closed, forgotten or withdrawn before delivery is dropped with it.
//
// Send-once: a row is claimed (pending -> sending) before it is sent and
// completed after. A row is sent again only after a send that failed. A
// row left in sending past its lease (the process died between the claim
// and the completion, so whether Telegram got the message is not known) is
// marked unknown and never sent again: an unknown outcome is not a failure.

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// OutboxKind says what a pa_outbox row sends.
type OutboxKind string

const (
	// OutboxReply is the model's answer, rendered from its fragment.
	OutboxReply OutboxKind = "reply"
	// OutboxReplyTooLong replaces an answer too long to send.
	OutboxReplyTooLong OutboxKind = "reply_too_long"
	// OutboxBudgetHold is the once-per-job budget hold notice (S1-R3).
	OutboxBudgetHold OutboxKind = "budget_hold"
	// OutboxRunFailed is NoticeRunFailed.
	OutboxRunFailed OutboxKind = "run_failed"
	// OutboxRequestDropped is NoticeDropped.
	OutboxRequestDropped OutboxKind = "request_dropped"
)

// OutboxKinds lists every kind this build writes.
func OutboxKinds() []OutboxKind {
	return []OutboxKind{OutboxReply, OutboxReplyTooLong, OutboxBudgetHold, OutboxRunFailed, OutboxRequestDropped}
}

// Valid reports whether k is a kind this build knows.
func (k OutboxKind) Valid() bool {
	for _, v := range OutboxKinds() {
		if v == k {
			return true
		}
	}
	return false
}

// OutboxKindOf maps a Notice to its outbox kind.
func OutboxKindOf(k NoticeKind) OutboxKind {
	if k == NoticeDropped {
		return OutboxRequestDropped
	}
	return OutboxRunFailed
}

// OutboxStatus is the state of a pa_outbox row.
type OutboxStatus string

const (
	// OutboxPending is due at NextAt.
	OutboxPending OutboxStatus = "pending"
	// OutboxSending is claimed by one deliverer until its lease ends.
	OutboxSending OutboxStatus = "sending"
	// OutboxSent was accepted by the Bot API.
	OutboxSent OutboxStatus = "sent"
	// OutboxFailed was refused permanently or ran out of attempts.
	OutboxFailed OutboxStatus = "failed"
	// OutboxDropped is a reply whose conversation went away first.
	OutboxDropped OutboxStatus = "dropped"
	// OutboxUnknown outlived its sending lease: it may or may not have been
	// delivered, and it is not sent again.
	OutboxUnknown OutboxStatus = "unknown"
)

// OutboxItem is one pa_outbox row.
type OutboxItem struct {
	ID        int64
	Principal int64
	JobID     int64
	Kind      OutboxKind
	// ConversationID and FragmentSeq name the assistant fragment of an
	// OutboxReply; both are empty for every other kind.
	ConversationID string
	FragmentSeq    int64
	// Attempts counts claims, including the current one.
	Attempts int
	Status   OutboxStatus
	NextAt   time.Time
}

// Valid reports whether the item can be enqueued.
func (o OutboxItem) Valid() bool {
	if o.Principal <= 0 || o.JobID <= 0 || !o.Kind.Valid() {
		return false
	}
	if o.Kind == OutboxReply {
		return o.ConversationID != "" && o.FragmentSeq > 0
	}
	return o.ConversationID == "" && o.FragmentSeq == 0
}

// Outbox limits.
const (
	// OutboxLease bounds one send. A row still sending after it becomes
	// OutboxUnknown.
	OutboxLease = 2 * time.Minute
	// OutboxMaxAttempts is how many failed sends of one row are retried
	// before it fails for good.
	OutboxMaxAttempts = 8
	// OutboxBatch bounds the rows one delivery pass claims.
	OutboxBatch = 32
)

// OutboxBackoff is the wait after the n-th (1-based) failed send: 15s
// doubling, at most 10m. Eight attempts span about half an hour.
func OutboxBackoff(n int) time.Duration {
	d := 15 * time.Second
	for i := 1; i < n && d < 10*time.Minute; i++ {
		d *= 2
	}
	return min(d, 10*time.Minute)
}

// OutboxClaimRequest configures one ClaimPAOutbox call.
type OutboxClaimRequest struct {
	Now   time.Time
	Lease time.Duration
	// Principal limits the pass to one principal; 0 means every principal.
	Principal int64
	Limit     int
}

// OutboxClaimResult is what ClaimPAOutbox did.
type OutboxClaimResult struct {
	// Items are claimed (OutboxSending), at most one per principal: the
	// oldest undelivered row, so a principal's messages go out in order.
	Items []OutboxItem
	// Unknown counts rows this call moved from sending to unknown.
	Unknown int
}

// OutboxCompletion is the outcome of sending one claimed row.
type OutboxCompletion struct {
	Now time.Time
	// Status is OutboxSent, OutboxFailed, OutboxDropped or OutboxPending
	// (a retry, due at RetryAt).
	Status  OutboxStatus
	RetryAt time.Time
}

// ErrOutboxStale: the row is no longer sending under this attempt (its
// lease ran out and it was marked unknown).
var ErrOutboxStale = errors.New("pa outbox: row is not sending under this attempt")

// OutboxStore is the persistence contract of the outbox (*db.Store).
type OutboxStore interface {
	// EnqueuePAOutbox records item in tx, once per (job, kind): a second
	// enqueue of the same pair is a no-op.
	EnqueuePAOutbox(ctx context.Context, tx *sql.Tx, item OutboxItem, now time.Time) error
	// ClaimPAOutbox marks expired sending rows unknown, then claims due
	// rows. Every failure is an error, never an empty result (I9).
	ClaimPAOutbox(ctx context.Context, req OutboxClaimRequest) (OutboxClaimResult, error)
	// CompletePAOutbox records the outcome of sending item. It returns
	// ErrOutboxStale when the row is not sending under item.Attempts.
	CompletePAOutbox(ctx context.Context, item OutboxItem, c OutboxCompletion) error
}
