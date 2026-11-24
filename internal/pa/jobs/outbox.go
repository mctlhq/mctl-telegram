package jobs

// The PA outbox (issue #1313 slice d2, deferral F4 of slice d1). Every bot
// message the run loop owes a principal -- the reply, the budget hold
// notice, and the run-failed and request-dropped notices -- is written to
// pa_outbox in the same transaction as the state change that owes it, and
// sent after the commit. A failed send therefore leaves the row due again
// instead of losing the message.
//
// A row stores no message text. A server notice is a kind, mapped to a
// safetext template when it is sent; a reply names the external-marked
// assistant fragment that holds the model's answer, and is rendered from it
// through safetext.Render when it is sent. A reply whose conversation was
// closed, forgotten or withdrawn before delivery is dropped with it.
//
// Send-once: a row is claimed (pending -> sending) right before it is sent,
// one row per claim, so its lease covers that one send only, and it is
// completed after. A row is sent again only after a send that is known to
// have failed: refused before the request was written, or answered with an
// explicit Bot API error. A send whose outcome is not known (the request
// was written and no answer was read) completes as unknown, and so does a
// row left in sending past its lease (the process died between the claim
// and the completion). An unknown row is never sent again: an unknown
// outcome is not a failure.
//
// A reply can be several messages. Each part the Bot API accepted is
// recorded (sent_parts) before the next is sent, and a retry resumes after
// the last recorded part, so a failure on part 3 never sends parts 1 and 2
// again.
//
// Conversation-level rows (#1348) carry the server answers of the
// conversation layer: the consent prompt with its button, and the answers
// to /new, /forget, /consent and to a refused message or button. They
// belong to no job: they are keyed by principal and the Telegram update
// that owed them, and are written in that update's transaction. They are
// delivered by the same claim, in the same per-principal order and with
// the same send-once rules as every other row.

import (
	"context"
	"database/sql"
	"errors"
	"slices"
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
	// OutboxPrincipalStopped is NoticePrincipalDisabled.
	OutboxPrincipalStopped OutboxKind = "principal_stopped"
	// OutboxDisclosureTooLong tells the principal, once per job, that a
	// text for a speaker was over the cap and was not sent, and offers to
	// send it in parts (#1322 slice P2-S6, S2-D3). No card was made.
	OutboxDisclosureTooLong OutboxKind = "disclosure_too_long"
)

// Conversation-level kinds (#1348), one per pa.Reply, with the same names.
// Only the consent prompts carry a button (CarriesButton).
const (
	OutboxConsentPrompt OutboxKind = "consent_prompt"
	// OutboxConsentPromptRU is the consent prompt in Russian
	// (convo.ConsentTextRU), its button bound to that text's hash.
	OutboxConsentPromptRU  OutboxKind = "consent_prompt_ru"
	OutboxConsentAccepted  OutboxKind = "consent_accepted"
	OutboxConsentWithdrawn OutboxKind = "consent_withdrawn"
	OutboxConsentStale     OutboxKind = "consent_stale"
	OutboxNewConversation  OutboxKind = "new_conversation"
	OutboxForgotten        OutboxKind = "forgotten"
	OutboxUnknownButton    OutboxKind = "unknown_button"
	OutboxRateLimited      OutboxKind = "rate_limited"
	OutboxMessageTooLong   OutboxKind = "message_too_long"
	// OutboxLinkingUnavailable answers a linking command while no PA
	// server is enabled (#1318 slice C2).
	OutboxLinkingUnavailable OutboxKind = "linking_unavailable"
	// OutboxPrincipalDisabled refuses an update of a disabled principal or
	// one not on the allowlist (T11, #1318).
	OutboxPrincipalDisabled OutboxKind = "principal_disabled"
	// The answers to an approval card's buttons (#1320 slice P2-S5):
	// Cancel pressed, and a button of a card that already ended.
	OutboxApprovalCancelled   OutboxKind = "approval_cancelled"
	OutboxApprovalAlreadyDone OutboxKind = "approval_already_done"
	OutboxApprovalExpired     OutboxKind = "approval_expired"
	// The fixed answers of /permissions (#1320 slice P2-S10): the command
	// where standing permissions are not offered, and the outcome of a
	// grant or revoke button. The screens themselves are not outbox rows.
	OutboxPermissionsUnavailable OutboxKind = "permissions_unavailable"
	OutboxPermissionGranted      OutboxKind = "permission_granted"
	OutboxPermissionRevoked      OutboxKind = "permission_revoked"
	OutboxPermissionRefused      OutboxKind = "permission_refused"
	// The consent to actions (#1320 slice P2-S14c): its prompt in English
	// and in Russian, each with a button bound to the text it shows
	// (convo.ActionConsentText, convo.ActionConsentTextRU), and the answer
	// to that button. Queued only while PA_WRITES_ENABLED is on.
	OutboxActionConsentPrompt   OutboxKind = "action_consent_prompt"
	OutboxActionConsentPromptRU OutboxKind = "action_consent_prompt_ru"
	OutboxActionConsentAccepted OutboxKind = "action_consent_accepted"
)

// Connection-level kinds (#1318 slice C2b). A row belongs to one
// connection, not to a job or an update, and is written in the transaction
// of the state change that owes it, once per connection and kind: a
// connection leaves active for expired at most once, so the row is keyed
// on that transition durably, across restarts and replicas.
const (
	// OutboxConnectionExpired asks the principal to link a connection the
	// service stopped accepting again (active -> expired).
	OutboxConnectionExpired OutboxKind = "connection_expired"
	// OutboxActionConsentNeeded tells the principal that an action on
	// this connection waits for the consent to actions, and
	// OutboxWriteScopeNeeded that the connection only allows reading and
	// the service must be connected again before the assistant can act
	// through it (#1320 slice P2-S14c). Once per connection each, by the
	// same key as every connection-level row: the principal is told once,
	// not on every request.
	OutboxActionConsentNeeded OutboxKind = "action_consent_needed"
	OutboxWriteScopeNeeded    OutboxKind = "write_scope_needed"
)

// ConnectionOutboxKinds lists the connection-level kinds.
func ConnectionOutboxKinds() []OutboxKind {
	return []OutboxKind{OutboxConnectionExpired, OutboxActionConsentNeeded, OutboxWriteScopeNeeded}
}

// ConnectionLevel reports whether k is a connection-level kind, whose rows
// have a connection id and neither a job nor an update.
func (k OutboxKind) ConnectionLevel() bool {
	return slices.Contains(ConnectionOutboxKinds(), k)
}

// Approval-level kinds (#1320 slice P2-S3): what became of a call the
// principal approved, or was asked to approve. A row belongs to one
// approval, not to a job, an update or a connection, and is written in the
// transaction that ends the approval or its dispatch. An approval gets at
// most one such row, whatever its kind: the executor and the stale-dispatch
// sweep cannot both report one call.
const (
	// OutboxWriteDone: the server answered the call without an error.
	OutboxWriteDone OutboxKind = "write_done"
	// OutboxWriteFailed: the server ran the call and answered with a tool
	// error.
	OutboxWriteFailed OutboxKind = "write_failed"
	// OutboxWriteNotSent: the call was not carried out: refused before
	// anything was sent, or the server refused the token.
	OutboxWriteNotSent OutboxKind = "write_not_sent"
	// OutboxWriteFenced: the call was sent and its result discarded,
	// because the connection, consent or conversation changed meanwhile.
	OutboxWriteFenced OutboxKind = "write_fenced"
	// OutboxWriteUnknown: the call was sent and no usable answer came
	// back (timeout, transport error, 5xx, a crash before the result).
	OutboxWriteUnknown OutboxKind = "write_outcome_unknown"
	// OutboxActionsCancelled: approvals that were waiting (pending, or
	// approved and not yet sent) were cancelled because their connection
	// ended, consent was withdrawn, the principal asked to forget, or an
	// admin disabled the principal (#1320 slice P2-S12, S2-C9). One row
	// answers for every approval one such change cancelled; it is keyed on
	// one of them, so none of them gets a second report.
	OutboxActionsCancelled OutboxKind = "actions_cancelled"
)

// ApprovalOutboxKinds lists the approval-level kinds.
func ApprovalOutboxKinds() []OutboxKind {
	return []OutboxKind{OutboxWriteDone, OutboxWriteFailed, OutboxWriteNotSent, OutboxWriteFenced, OutboxWriteUnknown,
		OutboxActionsCancelled}
}

// ApprovalLevel reports whether k is an approval-level kind, whose rows
// have an approval id and nothing else.
func (k OutboxKind) ApprovalLevel() bool {
	return slices.Contains(ApprovalOutboxKinds(), k)
}

// Card-level kinds (#1320 slice P2-S5). A row is the approval card of one
// pending approval: it has no job, update, connection or approval id, only
// the opaque id of the card's Approve callback in Button. The deliverer
// reads the approval through that id, under the principal, and builds the
// card and both of its buttons from the approval row, so nothing of the
// card is stored here. It is not an approval-level row: an approval gets
// one of those, the report of what became of it.
const (
	// OutboxApprovalCard asks the principal to approve or cancel one call.
	OutboxApprovalCard OutboxKind = "approval_card"
)

// CardOutboxKinds lists the card-level kinds.
func CardOutboxKinds() []OutboxKind {
	return []OutboxKind{OutboxApprovalCard}
}

// CardLevel reports whether k is a card-level kind, whose rows have the
// card's Approve callback id and nothing else.
func (k OutboxKind) CardLevel() bool {
	return slices.Contains(CardOutboxKinds(), k)
}

// CarriesButton reports whether a row of kind k is sent with one button,
// a consent prompt's: such a row needs its callback id, any other row
// must not have one.
func (k OutboxKind) CarriesButton() bool {
	return k == OutboxConsentPrompt || k == OutboxConsentPromptRU ||
		k == OutboxActionConsentPrompt || k == OutboxActionConsentPromptRU
}

// OutboxKinds lists every kind this build writes.
func OutboxKinds() []OutboxKind {
	return slices.Concat(jobOutboxKinds(), ConversationOutboxKinds(), ConnectionOutboxKinds(), ApprovalOutboxKinds(), CardOutboxKinds())
}

func jobOutboxKinds() []OutboxKind {
	return []OutboxKind{OutboxReply, OutboxReplyTooLong, OutboxBudgetHold, OutboxRunFailed, OutboxRequestDropped, OutboxPrincipalStopped,
		OutboxDisclosureTooLong}
}

// ConversationOutboxKinds lists the conversation-level kinds.
func ConversationOutboxKinds() []OutboxKind {
	return []OutboxKind{OutboxConsentPrompt, OutboxConsentPromptRU, OutboxConsentAccepted, OutboxConsentWithdrawn, OutboxConsentStale,
		OutboxNewConversation, OutboxForgotten, OutboxUnknownButton, OutboxRateLimited, OutboxMessageTooLong,
		OutboxLinkingUnavailable,
		OutboxPrincipalDisabled,
		OutboxApprovalCancelled, OutboxApprovalAlreadyDone, OutboxApprovalExpired,
		OutboxPermissionsUnavailable, OutboxPermissionGranted, OutboxPermissionRevoked, OutboxPermissionRefused,
		OutboxActionConsentPrompt, OutboxActionConsentPromptRU, OutboxActionConsentAccepted}
}

// ConversationLevel reports whether k is a conversation-level kind, whose
// rows have an update and no job.
func (k OutboxKind) ConversationLevel() bool {
	for _, v := range ConversationOutboxKinds() {
		if v == k {
			return true
		}
	}
	return false
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
	switch k {
	case NoticeDropped:
		return OutboxRequestDropped
	case NoticePrincipalDisabled:
		return OutboxPrincipalStopped
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
	// OutboxUnknown may or may not have been delivered: its send was cut
	// off after the request was written, or it outlived its sending lease.
	// It is not sent again.
	OutboxUnknown OutboxStatus = "unknown"
)

// OutboxItem is one pa_outbox row.
type OutboxItem struct {
	ID        int64
	Principal int64
	// JobID is the job that owes a job-level row; 0 for a
	// conversation-level row.
	JobID int64
	// UpdateID is the Telegram update that owed a conversation-level row;
	// 0 for a job-level row.
	UpdateID int64
	Kind     OutboxKind
	// Button is the opaque callback id of an OutboxConsentPrompt's single
	// button, or of an OutboxApprovalCard's Approve button; empty for
	// every other kind.
	Button string
	// ConversationID and FragmentSeq name the assistant fragment of an
	// OutboxReply; both are empty for every other kind.
	ConversationID string
	FragmentSeq    int64
	// ConnectionID is the connection a connection-level row is about;
	// empty for every other kind.
	ConnectionID string
	// ApprovalID is the approval an approval-level row is about; empty
	// for every other kind.
	ApprovalID string
	// Attempts counts claims, including the current one.
	Attempts int
	// SentParts counts the messages of this row the Bot API accepted, over
	// every attempt; a retry resumes after them.
	SentParts int
	Status    OutboxStatus
	NextAt    time.Time
}

// Valid reports whether the item can be enqueued.
func (o OutboxItem) Valid() bool {
	if o.Principal <= 0 || !o.Kind.Valid() {
		return false
	}
	if o.Kind.ApprovalLevel() {
		return o.ApprovalID != "" && len(o.ApprovalID) <= MaxOutboxApprovalID && o.ConnectionID == "" && o.JobID == 0 &&
			o.UpdateID == 0 && o.Button == "" && o.ConversationID == "" && o.FragmentSeq == 0
	}
	if o.ApprovalID != "" {
		return false
	}
	if o.Kind.ConnectionLevel() {
		return o.ConnectionID != "" && len(o.ConnectionID) <= MaxOutboxConnectionID && o.JobID == 0 && o.UpdateID == 0 &&
			o.Button == "" && o.ConversationID == "" && o.FragmentSeq == 0
	}
	if o.ConnectionID != "" {
		return false
	}
	if o.Kind.CardLevel() {
		return o.Button != "" && len(o.Button) <= MaxOutboxButton && o.JobID == 0 && o.UpdateID == 0 &&
			o.ConversationID == "" && o.FragmentSeq == 0
	}
	if o.Kind.ConversationLevel() {
		if o.JobID != 0 || o.UpdateID <= 0 || o.ConversationID != "" || o.FragmentSeq != 0 {
			return false
		}
		if len(o.Button) > MaxOutboxButton {
			return false
		}
		return o.Kind.CarriesButton() == (o.Button != "")
	}
	if o.JobID <= 0 || o.UpdateID != 0 || o.Button != "" {
		return false
	}
	if o.Kind == OutboxReply {
		return o.ConversationID != "" && o.FragmentSeq > 0
	}
	return o.ConversationID == "" && o.FragmentSeq == 0
}

// Outbox limits.
const (
	// MaxOutboxButton is the Bot API's callback_data limit, in bytes.
	MaxOutboxButton = 64
	// MaxOutboxConnectionID bounds a connection-level row's connection id.
	MaxOutboxConnectionID = 128
	// MaxOutboxApprovalID bounds an approval-level row's approval id.
	MaxOutboxApprovalID = 64
	// OutboxLease bounds one row's send. A row still sending after it
	// becomes OutboxUnknown. A row is claimed right before its own send,
	// which is bounded well inside the lease (pa.outboxSendTimeout).
	OutboxLease = 2 * time.Minute
	// OutboxMaxAttempts is how many failed sends of one row are retried
	// before it fails for good.
	OutboxMaxAttempts = 8
	// OutboxBatch bounds the rows one delivery pass sends (one claim each).
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
	// Status is OutboxSent, OutboxFailed, OutboxDropped, OutboxUnknown or
	// OutboxPending (a retry, due at RetryAt).
	Status  OutboxStatus
	RetryAt time.Time
}

// ErrOutboxStale: the row is no longer sending under this attempt (its
// lease ran out and it was marked unknown).
var ErrOutboxStale = errors.New("pa outbox: row is not sending under this attempt")

// ErrOutboxUpdateReused: a conversation-level row for the same principal,
// update id and kind already exists, so nothing was written. The
// transaction is still usable (the insert is ON CONFLICT DO NOTHING); the
// caller decides whether that is fatal. OutboxReplies counts and logs it.
var ErrOutboxUpdateReused = errors.New("pa outbox: a reply for this update id and kind already exists")

// OutboxStore is the persistence contract of the outbox (*db.Store).
type OutboxStore interface {
	// EnqueuePAOutbox records item in tx, once per (job, kind) for a
	// job-level row and once per (principal, update, kind) for a
	// conversation-level one. A second enqueue of a job-level key is a
	// no-op; one of a conversation-level key writes nothing and returns
	// ErrOutboxUpdateReused, so the lost reply can be counted.
	EnqueuePAOutbox(ctx context.Context, tx *sql.Tx, item OutboxItem, now time.Time) error
	// ClaimPAOutbox marks expired sending rows unknown, then claims due
	// rows. Every failure is an error, never an empty result (I9).
	ClaimPAOutbox(ctx context.Context, req OutboxClaimRequest) (OutboxClaimResult, error)
	// CompletePAOutbox records the outcome of sending item. It returns
	// ErrOutboxStale when the row is not sending under item.Attempts.
	CompletePAOutbox(ctx context.Context, item OutboxItem, c OutboxCompletion) error
	// RecordPAOutboxParts records that parts messages of item were
	// delivered, before the next part is sent. It returns ErrOutboxStale
	// when the row is not sending under item.Attempts.
	RecordPAOutboxParts(ctx context.Context, item OutboxItem, parts int, now time.Time) error
}
