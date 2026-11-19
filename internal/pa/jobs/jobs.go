// Package jobs holds the Personal Assistant run-loop types shared by the
// run loop (internal/pa) and its store (internal/db): the job row, the PA
// ledger, the limits and the errors (issue #1313 slice d1; threat model T4,
// T10, T13). It is a leaf package for the same reason as internal/pa/convo:
// internal/db implements Store without importing internal/pa, whose tests
// import internal/db.
//
// The rules it encodes:
//
//   - A job is enqueued in the webhook's dedup transaction and does nothing
//     else there; the work runs after the commit, through the claim route.
//   - Budget is reserved at claim, under the same lock and the same
//     global_day window as the managed runtime ledger (#1092), so PA spend
//     counts against the platform-wide daily cap. An exhausted budget holds
//     the job: no reservation, no token, no model call (S1-R3).
//   - Every decision after the claim (turn, tool call, reply) re-reads the
//     job row, the consent and the conversation in a transaction and
//     refuses on any failure to read them (I9): a read error is never
//     "allowed" and never "zero spent".
package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Status is the state of a pa_jobs row.
type Status string

const (
	// StatusPending waits for a claim.
	StatusPending Status = "pending"
	// StatusHeld waits for its budget window to reset (HeldUntil).
	StatusHeld Status = "held"
	// StatusClaimed is running under a pa-job token until LeaseUntil.
	StatusClaimed Status = "claimed"
	// StatusDone has replied.
	StatusDone Status = "done"
	// StatusCancelled was stopped by consent withdrawal, /forget, /new or
	// an expired conversation. It never runs again.
	StatusCancelled Status = "cancelled"
	// StatusExpired was claimed and its lease ran out without a reply.
	StatusExpired Status = "expired"
)

// Ledger statuses of pa_usage. They mean what the managed ledger's do
// (internal/db/agent_usage.go): reserved is in flight, held counts at the
// full reservation, settled counts at the reported cost.
const (
	UsageReserved = "reserved"
	UsageHeld     = "held"
	UsageSettled  = "settled"
)

// Budget scopes of a hold.
const (
	ScopeGlobalDay      = "global_day"
	ScopePrincipalDay   = "principal_day"
	ScopePrincipalMonth = "principal_month"
)

// Defaults (owner decisions, 2026-11-18). Config may override them.
const (
	DefaultRateMessages     = 20
	DefaultRateWindow       = time.Hour
	DefaultMaxToolCalls     = 8
	DefaultMaxContextTokens = 32000
	DefaultBudgetJobUSD     = 0.25
	DefaultBudgetDayUSD     = 2
	DefaultBudgetMonthUSD   = 20
	// DefaultLease is how long a claimed job and its pa-job token live.
	DefaultLease = 5 * time.Minute
	// MaxMessageChars is the Telegram maximum for one message, applied to
	// every text part of an incoming update (T10).
	MaxMessageChars = 4096
	// MaxToolOutputBytes caps one tool output (T10); the executor (#1315)
	// truncates with TruncateToolOutput.
	MaxToolOutputBytes = 64 << 10
)

// Limits are the per-principal and per-run caps (threat model T10).
type Limits struct {
	RateMessages     int
	RateWindow       time.Duration
	MaxToolCalls     int
	MaxContextTokens int
}

// DefaultLimits returns the owner-decided limits.
func DefaultLimits() Limits {
	return Limits{
		RateMessages:     DefaultRateMessages,
		RateWindow:       DefaultRateWindow,
		MaxToolCalls:     DefaultMaxToolCalls,
		MaxContextTokens: DefaultMaxContextTokens,
	}
}

// Valid reports whether every limit is set.
func (l Limits) Valid() bool {
	return l.RateMessages > 0 && l.RateWindow > 0 && l.MaxToolCalls > 0 && l.MaxContextTokens > 0
}

// Budget is the PA ledger's caps in USD. GlobalDayUSD is the platform-wide
// daily cap shared with the managed runtime (MANAGED_BUDGET_USD_GLOBAL_DAY).
type Budget struct {
	PerJobUSD         float64
	PrincipalDayUSD   float64
	PrincipalMonthUSD float64
	GlobalDayUSD      float64
}

// Valid reports whether every cap is positive. A budget with a zero cap is
// not "unlimited": the run loop refuses to start with it.
func (b Budget) Valid() bool {
	// A job dearer than any window could never be claimed: it would be
	// held at every reset, without end.
	return b.PerJobUSD > 0 && b.PerJobUSD <= b.PrincipalDayUSD && b.PrincipalDayUSD <= b.PrincipalMonthUSD &&
		b.PerJobUSD <= b.GlobalDayUSD
}

// Job is one pa_jobs row.
type Job struct {
	ID             int64
	Principal      int64
	ConversationID string
	UpdateID       int64
	ConsentVersion string
	Status         Status
	Attempts       int
	Turns          int
	ToolCalls      int
	// ExecutionContext is the canonical JSON of the run's context, set at
	// claim; ContextDigest is its SHA-256 (hex), also signed into the token.
	ExecutionContext []byte
	ContextDigest    string
	// ToolSet is the signed tool set of the current attempt.
	ToolSet    []string
	LeaseUntil time.Time
	HeldUntil  time.Time
	CreatedAt  time.Time
	// HoldNotified: the principal was told this job is held.
	HoldNotified bool
	// ClaimFailures counts failed claims of this job (ClaimBackoff).
	ClaimFailures int
}

// Ref names one attempt of one job, as a verified pa-job token does. Every
// lookup is by (Principal, JobID, Attempt) and the digest must match.
type Ref struct {
	Principal int64
	JobID     int64
	Attempt   int
	Digest    string
}

// Valid reports whether every field is set.
func (r Ref) Valid() bool {
	return r.Principal > 0 && r.JobID > 0 && r.Attempt > 0 && r.Digest != ""
}

// Errors. None carries text, ids or amounts.
var (
	// ErrNotFound: no such job for this principal and attempt.
	ErrNotFound = errors.New("pa jobs: not found")
	// ErrStale: the job is not running under this attempt any more (done,
	// cancelled, expired, re-claimed, lease over or digest mismatch).
	ErrStale = errors.New("pa jobs: job is not running under this token")
	// ErrGone: consent was withdrawn or changed, or the conversation was
	// closed or expired. The job is cancelled.
	ErrGone = errors.New("pa jobs: consent or conversation no longer valid")
	// ErrConversationGone is the ErrGone of a closed or expired
	// conversation while consent still stands: the principal is told that
	// the request was dropped. errors.Is(err, ErrGone) holds for it.
	ErrConversationGone = fmt.Errorf("%w: conversation", ErrGone)
	// ErrToolCap: the run reached its tool-call cap (S1-R2).
	ErrToolCap = errors.New("pa jobs: tool-call cap reached")
	// ErrToolNotInSet: the tool is not in the job's signed tool set (S1-I1).
	ErrToolNotInSet = errors.New("pa jobs: tool not in the job's tool set")
	// ErrBudget: the attempt has no live reservation.
	ErrBudget = errors.New("pa jobs: no live budget reservation")
	// ErrContextTooLarge: the declared context is over the cap (S1-R1).
	ErrContextTooLarge = errors.New("pa jobs: context over the token cap")
	// ErrUnreadable wraps every failure to read or interpret a row. It is
	// never treated as absence, as zero spent or as allowed (I9).
	ErrUnreadable = errors.New("pa jobs: state unreadable")
	// ErrInvalid is a call the store refuses before touching a row.
	ErrInvalid = errors.New("pa jobs: invalid request")
)

// Gate re-checks, inside the store's transaction, everything outside the
// job row that must still hold: consent (current version and text) and
// the conversation (open, unexpired). It returns nil, ErrGone, or any
// other error for a failed read, which aborts the transaction.
type Gate func(ctx context.Context, tx *sql.Tx, j Job, now time.Time) error

// Build fills a claimed job's execution context inside the claim's
// transaction: the reservation id is already known. It returns the
// canonical context JSON, its digest and the signed tool set.
type Build func(ctx context.Context, tx *sql.Tx, j Job, reservationID int64) (contextJSON []byte, digest string, toolSet []string, err error)

// RateDecision is the outcome of one message against the rate window.
type RateDecision struct {
	// Allowed: the message is within the limit.
	Allowed bool
	// Notify: this is the first refused message of the window, so the
	// principal is told once, not on every message.
	Notify bool
}

// EnqueueRequest is what the conversation layer hands the store.
type EnqueueRequest struct {
	Principal      int64
	ConversationID string
	UpdateID       int64
	ConsentVersion string
	Now            time.Time
}

// EnqueueOutcome says what EnqueuePAJob did.
type EnqueueOutcome int

const (
	// Enqueued: a new pending job.
	Enqueued EnqueueOutcome = iota + 1
	// Coalesced: the principal already has a queued (pending or held) job,
	// which will read this message from the conversation when it runs.
	Coalesced
)

// ClaimRequest configures one claim.
type ClaimRequest struct {
	Now    time.Time
	Lease  time.Duration
	Budget Budget
	Gate   Gate
	Build  Build
}

// ClaimOutcome says what ClaimPAJob did.
type ClaimOutcome int

const (
	// ClaimNone: nothing was due.
	ClaimNone ClaimOutcome = iota
	// ClaimClaimed: Job is claimed, with a reservation.
	ClaimClaimed
	// ClaimHeld: the budget is durably exhausted; Job is held until
	// HeldUntil. Notify is true the first time this job is held.
	ClaimHeld
	// ClaimDeferred: only in-flight reservations block the claim; the job
	// stays pending and nothing is said.
	ClaimDeferred
	// ClaimCancelled: the gate found consent or the conversation gone.
	ClaimCancelled
)

// ClaimResult is the outcome of ClaimPAJob.
type ClaimResult struct {
	Outcome       ClaimOutcome
	Job           Job
	ReservationID int64
	Notify        bool
	Scope         string
	// Notices are owed to principals whose jobs ended without an answer
	// during this claim (an expired lease, a job cancelled after repeated
	// failures, a request dropped with its conversation). They are set
	// even when the claim itself returns an error.
	Notices []Notice
}

// NoticeKind says why a job ended without an answer.
type NoticeKind int

const (
	// NoticeRunFailed: the job could not be run (repeated failures, an
	// expired lease, state that cannot be built).
	NoticeRunFailed NoticeKind = iota + 1
	// NoticeDropped: the conversation the job would answer closed or
	// expired before the job ran (for example during a budget hold).
	NoticeDropped
)

// Notice is a server message owed to Principal about JobID.
type Notice struct {
	Principal int64
	JobID     int64
	Kind      NoticeKind
}

// MaxClaimFailures is how many failed claims of one job (a per-job read or
// build error) are backed off before the job is cancelled with a notice.
const MaxClaimFailures = 5

// ClaimBackoff is the wait after the n-th (1-based) failed claim of a job:
// 30s doubling, at most 8m. A failing job must not stay the oldest due job
// and block every other principal's claim.
func ClaimBackoff(n int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < n && d < 8*time.Minute; i++ {
		d *= 2
	}
	return min(d, 8*time.Minute)
}

// TurnRequest is a model turn the worker is about to take.
type TurnRequest struct {
	Now              time.Time
	ContextTokens    int
	MaxContextTokens int
	// MaxTurns bounds model turns: one per tool call plus the answer.
	MaxTurns int
	Gate     Gate
}

// ToolCallRequest is a tool call the executor is about to dispatch.
type ToolCallRequest struct {
	Now          time.Time
	Tool         string
	MaxToolCalls int
	Gate         Gate
}

// FinishRequest settles the run.
type FinishRequest struct {
	Now time.Time
	// CostUSD is the reported cost; a negative value means "not reported"
	// and settles at the full reservation.
	CostUSD float64
	Gate    Gate
	// Record runs in the finish transaction after the gate, to store the
	// reply as conversation state.
	Record func(ctx context.Context, tx *sql.Tx, j Job) error
}

// Store is the persistence contract (implemented by *db.Store).
type Store interface {
	// AdmitPAMessage counts one message of principal in its fixed rate
	// window, in the webhook's transaction.
	AdmitPAMessage(ctx context.Context, tx *sql.Tx, principal int64, now time.Time, limit int, window time.Duration) (RateDecision, error)
	// EnqueuePAJob records a job in the webhook's transaction.
	EnqueuePAJob(ctx context.Context, tx *sql.Tx, req EnqueueRequest) (EnqueueOutcome, error)
	// ClaimPAJob claims the oldest due job of a principal with no running
	// job, reserving budget, in one transaction.
	ClaimPAJob(ctx context.Context, req ClaimRequest) (ClaimResult, error)
	// ReleasePAClaim undoes a claim whose token never left the server:
	// the reservation is deleted and the job returns to pending (requeue)
	// or is cancelled (a deterministic failure, which would recur).
	// With requeue the job is backed off like a failed claim (and
	// cancelled after MaxClaimFailures); the returned notice, if any, is
	// for the principal.
	ReleasePAClaim(ctx context.Context, ref Ref, requeue bool, now time.Time) (*Notice, error)
	// RunningPAJob reads the job of ref, refusing one that is not running
	// under exactly this attempt and context, and runs gate; like every
	// step it cancels the job when the gate reports ErrGone.
	RunningPAJob(ctx context.Context, ref Ref, now time.Time, gate Gate) (Job, error)
	// AdmitPATurn admits one model turn.
	AdmitPATurn(ctx context.Context, ref Ref, req TurnRequest) (Job, error)
	// AdmitPAToolCall admits one tool call (cap, tool set, budget, gate).
	AdmitPAToolCall(ctx context.Context, ref Ref, req ToolCallRequest) (Job, error)
	// FinishPAJob settles the reservation and marks the job done.
	FinishPAJob(ctx context.Context, ref Ref, req FinishRequest) (Job, error)
}

// EstimateTokens is the conservative context estimate the run loop uses:
// one token per four bytes, rounded up.
func EstimateTokens(s string) int { return (len(s) + 3) / 4 }

// TruncationMarker ends a tool output cut by TruncateToolOutput.
const TruncationMarker = "\n[truncated by mctl]"

// TruncateToolOutput caps a tool output at MaxToolOutputBytes, marker
// included, never cutting inside a UTF-8 sequence. The result stays
// external whatever it holds (T5).
func TruncateToolOutput(b []byte) ([]byte, bool) {
	if len(b) <= MaxToolOutputBytes {
		return b, false
	}
	cut := MaxToolOutputBytes - len(TruncationMarker)
	// Step back to a rune boundary: a continuation byte is 10xxxxxx.
	for cut > 0 && b[cut]&0xC0 == 0x80 {
		cut--
	}
	out := make([]byte, 0, cut+len(TruncationMarker))
	out = append(out, b[:cut]...)
	return append(out, TruncationMarker...), true
}
