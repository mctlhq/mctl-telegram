package pa

// runloop.go is the server side of the Personal Assistant run loop (issue
// #1313 slice d1; threat model T4, T5, T10, T11, T13, T14). A worker polls
// the claim route with its pool credential and drives the model; this side
// decides everything:
//
//   - claim: picks a due job, re-checks consent and the conversation,
//     reserves budget under the managed ledger's lock (or holds the job and
//     says so once, with no model call: S1-R3), and returns a pa-job token,
//     the signed tool set and the marked context;
//   - turn: called before every model call; re-checks the job, consent, the
//     conversation, the context size (S1-R1) and the turn cap;
//   - reply: re-checks, records the answer, settles the reservation, and
//     sends through safetext.Render and output.Sender only, after the commit.
//     A reply too long to send is replaced by a short server text, never
//     truncated.
//
// AdmitPAToolCall is the executor's gate (#1315): tool in the job's signed
// set (S1-I1), under the tool-call cap (S1-R2), reservation live, consent
// and conversation still valid. The worker never holds a provider token; it
// gets only the pa-job token, which the job row outranks at every step.
//
// Every read failure is a refusal (I9): a consent, status or ledger read
// that failed never reads as consent, as an open conversation or as zero
// spend.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// Run-loop routes. All three are POST.
const (
	RouteClaim = "/api/pa/v1/jobs/claim"
	RouteTurn  = "/api/pa/v1/jobs/turn"
	RouteReply = "/api/pa/v1/jobs/reply"
	// RouteDraft shows a partial answer as a Telegram draft (streaming.go).
	RouteDraft = "/api/pa/v1/jobs/draft"
)

// maxReplyBody bounds a reply request. It is sized from the Render limit
// so that any answer Render could accept fits even fully \uXXXX-escaped
// (6 bytes per UTF-16 unit), plus room for the rest of the JSON. A body
// over it is a too-long answer, handled like safetext.ErrTooLong.
const maxReplyBody = 6*safetext.MaxParts*4096 + 4<<10

// RunLoopStore is what the run loop persists through (*db.Store).
type RunLoopStore interface {
	jobs.Store
	jobs.OutboxStore
	convo.Store
	AdmitPAMessage(ctx context.Context, tx *sql.Tx, principal int64, now time.Time, limit int, window time.Duration) (jobs.RateDecision, error)
	PAConversationOpen(ctx context.Context, tx *sql.Tx, principal int64, conversationID string, now time.Time) error
	// PACallbackExpiry returns when a callback id stops resolving, or
	// convo.ErrNotFound when it does not resolve at all.
	PACallbackExpiry(ctx context.Context, principal int64, id string) (time.Time, error)
}

// BotSender sends a rendered message (*output.Sender). SendFrom resumes a
// message after the parts already delivered and reports each delivered
// part; it wraps output.ErrOutcomeUnknown around any failure that may have
// reached Telegram.
type BotSender interface {
	SendFrom(ctx context.Context, chatID int64, text safetext.Text, kb output.Keyboard, from int, sent func(delivered int) error) error
	// AnswerCallback answers a callback query (answerCallbackQuery), so the
	// client stops the spinner on the pressed button.
	AnswerCallback(ctx context.Context, callbackQueryID string, notice safetext.Template) error
}

// PoolAuthenticator authenticates the worker pool (*localjwt.PoolProvider).
type PoolAuthenticator interface {
	Authenticate(r *http.Request) (*auth.Identity, error)
}

// JobMinter mints pa-job tokens (*localjwt.Issuer).
type JobMinter interface {
	MintPAJob(j localjwt.PAJob, parentJti string, parentOrigIAT int64, ttl time.Duration) (string, error)
}

// JobVerifier verifies pa-job tokens (*localjwt.PAJobVerifier).
type JobVerifier interface {
	VerifyRequest(r *http.Request) (localjwt.PAJob, error)
}

// ToolResolver returns the connections a principal's run is bound to and
// the tool set ("server/tool") they expose, inside the claim transaction.
// Phase 1 ships NoTools until connections (#1314) are wired.
//
// Error contract: a failed read of the store (begin, query, rows, lock,
// timeout) must wrap jobs.ErrStoreFault; the claim then records nothing
// against the job. Any other error is taken as this job's own failure and
// backed off (counted toward jobs.MaxClaimFailures), and one wrapping
// jobs.ErrInvalid cancels the job.
type ToolResolver func(ctx context.Context, tx *sql.Tx, principal int64) ([]ConnectionRevision, []string, error)

// NoTools binds no connection and exposes no tool.
func NoTools(context.Context, *sql.Tx, int64) ([]ConnectionRevision, []string, error) {
	return nil, nil, nil
}

// RunLoopConfig configures NewRunLoop. Every field but Now and Lease is
// required.
type RunLoopConfig struct {
	Store    RunLoopStore
	Sealer   *convo.Sealer
	Pool     PoolAuthenticator
	Minter   JobMinter
	Verifier JobVerifier
	Sender   BotSender
	Tools    ToolResolver
	Limits   jobs.Limits
	Budget   jobs.Budget
	// Lease is how long a claim and its token live (jobs.DefaultLease).
	Lease time.Duration
	Now   func() time.Time
	// Metrics counts outbox outcomes. Optional.
	Metrics OutboxCounter
	// CallbackMetrics counts callback answers (AnswerCallbackAfter).
	// Optional.
	CallbackMetrics CallbackCounter
	// Allowed is the preview allowlist (PA_ALLOWED_PRINCIPALS), re-checked
	// at every step by gate. Required; an empty list allows nobody.
	Allowed PrincipalAllowlist
	// Typing shows "typing..." in the principal's chat while a run is in
	// progress (typing.go). Optional; nil shows nothing.
	Typing TypingSender
	// Phases records where a run's time goes (timing.go). Optional.
	Phases PhaseObserver
	// Cards builds an approval card when its outbox row is sent (card.go).
	// Optional: without it such a row cannot be built and fails.
	Cards CardRenderer
	// Drafts shows streamed partial answers and tool statuses as drafts
	// (streaming.go). Optional; nil disables streaming entirely. It needs
	// Typing, whose presence loop it extends.
	Drafts DraftSender
	// Getenv reads PA_STREAMING_ENABLED on every claim and draft. Optional;
	// defaults to os.Getenv.
	Getenv func(string) string
}

// RunLoop serves the run-loop routes and implements RunEnqueuer and
// Limiter for Conversations.
type RunLoop struct {
	store    RunLoopStore
	sealer   *convo.Sealer
	pool     PoolAuthenticator
	minter   JobMinter
	verifier JobVerifier
	sender   BotSender
	tools    ToolResolver
	limits   jobs.Limits
	budget   jobs.Budget
	lease    time.Duration
	now      func() time.Time
	metrics  OutboxCounter
	cbCount  CallbackCounter
	allowed  PrincipalAllowlist
	typing   *typingTracker
	timer    *runTimer
	cards    CardRenderer
	drafts   DraftSender
	getenv   func(string) string
	limiter  *draftLimiter
	// pending tracks the deliveries request paths started (deliverAfter).
	pending sync.WaitGroup
	// readTools is every tool the pin admits without approval, as
	// "server/tool". Phase 1 has no other kind (catalog.LoadPin), and a
	// resolver that offers anything else fails the claim.
	readTools map[string]bool
	// modelTools is the model's view of every readTools entry, built from
	// the pin (catalog description and pinned schema), keyed the same way.
	// The claim offers exactly the job's signed tool set from it.
	modelTools map[string]catalog.ModelTool
}

var (
	_ RunEnqueuer = (*RunLoop)(nil)
	_ Limiter     = (*RunLoop)(nil)
)

// ErrRunLoopConfig reports an unusable RunLoopConfig.
var ErrRunLoopConfig = errors.New("pa: run loop needs a store, sealer, pool, minter, verifier, sender, tool resolver, allowlist, limits and a budget")

// NewRunLoop builds the run loop. It is constructed only when PA_ENABLED.
func NewRunLoop(cfg RunLoopConfig) (*RunLoop, error) {
	if cfg.Store == nil || cfg.Sealer == nil || cfg.Pool == nil || cfg.Minter == nil || cfg.Verifier == nil ||
		cfg.Sender == nil || cfg.Tools == nil || cfg.Allowed == nil || !cfg.Limits.Valid() || !cfg.Budget.Valid() ||
		cfg.Budget.PerJobUSD > cfg.Budget.PrincipalDayUSD || cfg.Lease < 0 || cfg.Lease > localjwt.MaxPAJobTTL ||
		// The per-turn floor of a run at its turn cap must fit the
		// reservation, or the floor alone would settle above it.
		cfg.Budget.MinTurnUSD*float64(cfg.Limits.MaxToolCalls+1) > cfg.Budget.PerJobUSD+1e-9 {
		return nil, ErrRunLoopConfig
	}
	pin, err := catalog.LoadPin()
	if err != nil {
		return nil, fmt.Errorf("pa run loop: %w", err)
	}
	read := map[string]bool{}
	modelTools := map[string]catalog.ModelTool{}
	for server, sp := range pin.Servers {
		for name, t := range sp.Tools {
			if t.Tier == catalog.TierAuto && t.Class == catalog.ClassRead {
				mt, err := pin.ModelTool(server, name)
				if err != nil {
					return nil, fmt.Errorf("pa run loop: %w", err)
				}
				read[server+"/"+name] = true
				modelTools[server+"/"+name] = mt
			}
		}
	}
	lease := cfg.Lease
	if lease == 0 {
		lease = jobs.DefaultLease
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	getenv := cfg.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	loop := &RunLoop{
		store: cfg.Store, sealer: cfg.Sealer, pool: cfg.Pool, minter: cfg.Minter, verifier: cfg.Verifier,
		sender: cfg.Sender, tools: cfg.Tools, limits: cfg.Limits, budget: cfg.Budget, lease: lease, now: now,
		readTools: read, modelTools: modelTools, metrics: cfg.Metrics, cbCount: cfg.CallbackMetrics,
		allowed: cfg.Allowed, typing: newTypingTracker(cfg.Typing, now), timer: newRunTimer(cfg.Phases, now),
		cards: cfg.Cards, drafts: cfg.Drafts, getenv: getenv, limiter: newDraftLimiter(),
	}
	if loop.typing != nil && cfg.Drafts != nil {
		loop.typing.drafts = cfg.Drafts
		loop.typing.check = func(ctx context.Context, ref jobs.Ref) error {
			_, err := loop.store.RunningPAJob(ctx, ref, loop.now(), loop.gate)
			loop.droppedNotice(ctx, ref, err)
			return err
		}
	}
	return loop, nil
}

// streaming reports whether draft streaming is on right now. An unreadable
// flag is off.
func (l *RunLoop) streaming() bool {
	if l.drafts == nil || l.typing == nil {
		return false
	}
	on, err := streamingOn(l.getenv)
	return err == nil && on
}

// endPresence stops job's typing and draft presence and its draft cap.
func (l *RunLoop) endPresence(job int64) {
	l.typing.stop(job)
	l.limiter.drop(job)
}

// Mount registers the three routes.
func (l *RunLoop) Mount(mux interface{ Handle(string, http.Handler) }) {
	mux.Handle(RouteClaim, http.HandlerFunc(l.serveClaim))
	mux.Handle(RouteTurn, http.HandlerFunc(l.serveTurn))
	mux.Handle(RouteReply, http.HandlerFunc(l.serveReply))
	mux.Handle(RouteDraft, http.HandlerFunc(l.serveDraft))
}

// EnqueueRun implements RunEnqueuer, inside the update's transaction.
func (l *RunLoop) EnqueueRun(ctx context.Context, tx *sql.Tx, req RunRequest) error {
	if req.Principal.IsZero() {
		return ErrNoPrincipal
	}
	_, err := l.store.EnqueuePAJob(ctx, tx, jobs.EnqueueRequest{
		Principal:      req.Principal.TelegramID(),
		ConversationID: req.ConversationID,
		UpdateID:       req.UpdateID,
		ConsentVersion: req.ConsentVersion,
		Now:            l.now(),
	})
	if err == nil {
		markRunQueued(ctx)
	}
	return err
}

// AdmitMessage implements Limiter, inside the update's transaction.
func (l *RunLoop) AdmitMessage(ctx context.Context, tx *sql.Tx, p Principal) (jobs.RateDecision, error) {
	if p.IsZero() {
		return jobs.RateDecision{}, ErrNoPrincipal
	}
	return l.store.AdmitPAMessage(ctx, tx, p.TelegramID(), l.now(), l.limits.RateMessages, l.limits.RateWindow)
}

// gate re-checks the principal (the preview allowlist and the admin
// disable), consent (current version and text, and the version the job was
// admitted under) and the conversation, inside the store's transaction
// (T11, T13). Every step runs it: claim, turn, tool admission, the
// post-call StillRunning, reply and result recording. Absence or a change
// is jobs.ErrGone (jobs.ErrPrincipalNotAllowed, jobs.ErrPrincipalDisabled
// for the principal); a failed read is an error that aborts the step,
// never a pass.
func (l *RunLoop) gate(ctx context.Context, tx *sql.Tx, j jobs.Job, now time.Time) error {
	// The allowlist changes only on restart, but a job queued before a
	// restart that dropped its principal stops here too.
	if !l.allowed.Allowed(j.Principal) {
		return jobs.ErrPrincipalNotAllowed
	}
	disabled, err := l.store.PAPrincipalDisabled(ctx, tx, j.Principal)
	switch {
	case errors.Is(err, convo.ErrStoreFault):
		return fmt.Errorf("%w: %w: principal disable: %v", jobs.ErrUnreadable, jobs.ErrStoreFault, err)
	case err != nil:
		return fmt.Errorf("%w: principal disable: %v", jobs.ErrUnreadable, err)
	case disabled:
		return jobs.ErrPrincipalDisabled
	}
	rec, err := l.store.GetPAConsent(ctx, tx, j.Principal)
	switch {
	case errors.Is(err, convo.ErrNotFound):
		return jobs.ErrGone
	case errors.Is(err, convo.ErrStoreFault):
		return fmt.Errorf("%w: %w: consent: %v", jobs.ErrUnreadable, jobs.ErrStoreFault, err)
	case err != nil:
		return fmt.Errorf("%w: consent: %v", jobs.ErrUnreadable, err)
	case !convo.Satisfied(rec) || rec.Version != j.ConsentVersion || j.ConsentVersion != convo.ConsentVersion:
		return jobs.ErrGone
	}
	return l.store.PAConversationOpen(ctx, tx, j.Principal, j.ConversationID, now)
}

// runContext is the canonical execution context of one claimed attempt.
// Its SHA-256 is signed into the pa-job token and stored on the job row.
type runContext struct {
	V              int                  `json:"v"`
	Principal      int64                `json:"principal"`
	Trigger        Trigger              `json:"trigger"`
	ConversationID string               `json:"conversation_id"`
	JobID          int64                `json:"job_id"`
	Attempt        int                  `json:"attempt"`
	Connections    []ConnectionRevision `json:"connections"`
	Budget         string               `json:"budget"`
	ConsentVersion string               `json:"consent_version"`
	ConsentSHA256  string               `json:"consent_sha256"`
	ToolSet        []string             `json:"tool_set"`
}

func (l *RunLoop) build(ctx context.Context, tx *sql.Tx, j jobs.Job, reservationID int64) ([]byte, string, []string, error) {
	conns, tools, err := l.tools(ctx, tx, j.Principal)
	if err != nil {
		return nil, "", nil, err
	}
	for _, t := range tools {
		if !l.readTools[t] {
			// Only pinned reads exist in Phase 1 (I5): a resolver offering
			// anything else is a bug, and the run does not start.
			return nil, "", nil, fmt.Errorf("%w: tool set offers a tool that is not a pinned read", jobs.ErrInvalid)
		}
	}
	tools = slices.Clone(tools)
	sort.Strings(tools)
	tools = slices.Compact(tools)
	ec, err := restoreInteractive(j, conns, BudgetReservation{ID: "pa_usage:" + strconv.FormatInt(reservationID, 10)})
	if err != nil {
		// The job row and connections do not make a valid context: that
		// recurs on every attempt, so the claim cancels the job.
		return nil, "", nil, fmt.Errorf("%w: execution context: %v", jobs.ErrInvalid, err)
	}
	// The context names the text the principal accepted, English or
	// Russian: the record the claim check just found satisfied, read again
	// in the same transaction. A failed read fails the claim.
	rec, err := l.store.GetPAConsent(ctx, tx, j.Principal)
	switch {
	case errors.Is(err, convo.ErrNotFound):
		return nil, "", nil, jobs.ErrGone
	case err != nil:
		return nil, "", nil, fmt.Errorf("%w: consent: %v", jobs.ErrUnreadable, err)
	case !convo.Satisfied(rec):
		return nil, "", nil, jobs.ErrGone
	}
	rc := runContext{
		V: 1, Principal: ec.Principal().TelegramID(), Trigger: TriggerInteractive, ConversationID: ec.ConversationID(),
		JobID: j.ID, Attempt: j.Attempts, Connections: ec.Connections(), Budget: ec.Budget().ID,
		ConsentVersion: ec.ConsentVersion(), ConsentSHA256: rec.TextSHA256, ToolSet: tools,
	}
	if rc.Connections == nil {
		rc.Connections = []ConnectionRevision{}
	}
	if rc.ToolSet == nil {
		rc.ToolSet = []string{}
	}
	b, err := json.Marshal(rc)
	if err != nil {
		return nil, "", nil, err
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), rc.ToolSet, nil
}

// Wire types of the run-loop routes.
type (
	wireFragment struct {
		Kind       string `json:"kind"`
		Provenance string `json:"provenance"`
		Text       string `json:"text"`
	}
	wireLimits struct {
		MaxJobCostUSD      float64 `json:"max_job_cost_usd"`
		MaxToolCalls       int     `json:"max_tool_calls"`
		MaxContextTokens   int     `json:"max_context_tokens"`
		MaxToolOutputBytes int     `json:"max_tool_output_bytes"`
	}
	// wireTool is one tool the model may be offered. Name is the signed
	// "server/tool"; Description and InputSchema come from the pin, never
	// from the server's live listing (T8).
	wireTool struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"input_schema"`
	}
	claimResponse struct {
		JobID      int64          `json:"job_id"`
		Attempt    int            `json:"attempt"`
		Token      string         `json:"token"`
		LeaseUntil time.Time      `json:"lease_until"`
		ToolSet    []string       `json:"tool_set"`
		Tools      []wireTool     `json:"tools,omitempty"`
		Limits     wireLimits     `json:"limits"`
		Fragments  []wireFragment `json:"fragments"`
		// Streaming tells the worker it may post drafts (RouteDraft).
		Streaming bool `json:"streaming,omitempty"`
	}
	turnRequest struct {
		ContextTokens int `json:"context_tokens"`
	}
	replyRequest struct {
		Text string `json:"text"`
		// CostUSD is the run's reported cost; absent settles at the full
		// reservation.
		CostUSD *float64 `json:"cost_usd"`
	}
	stopResponse struct {
		Stop string `json:"stop"`
	}
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// stop answers a refused step. The reason is a fixed label, never an error
// text, which may carry ids.
func stop(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, jobs.ErrNotFound), errors.Is(err, jobs.ErrStale):
		writeJSON(w, http.StatusConflict, stopResponse{Stop: "stale"})
	case errors.Is(err, jobs.ErrPrincipalDisabled), errors.Is(err, jobs.ErrPrincipalNotAllowed):
		writeJSON(w, http.StatusConflict, stopResponse{Stop: "principal_disabled"})
	case errors.Is(err, jobs.ErrGone):
		writeJSON(w, http.StatusConflict, stopResponse{Stop: "gone"})
	case errors.Is(err, jobs.ErrToolCap):
		writeJSON(w, http.StatusConflict, stopResponse{Stop: "tool_cap"})
	case errors.Is(err, jobs.ErrToolNotInSet):
		writeJSON(w, http.StatusForbidden, stopResponse{Stop: "tool_not_in_set"})
	case errors.Is(err, jobs.ErrBudget):
		writeJSON(w, http.StatusConflict, stopResponse{Stop: "budget"})
	case errors.Is(err, jobs.ErrContextTooLarge):
		writeJSON(w, http.StatusConflict, stopResponse{Stop: "context_too_large"})
	case errors.Is(err, jobs.ErrInvalid):
		writeJSON(w, http.StatusBadRequest, stopResponse{Stop: "invalid"})
	default:
		// Unreadable state and everything unexpected: refuse, retryable.
		slog.Warn("pa run loop step refused", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, stopResponse{Stop: "unavailable"})
	}
}

func (l *RunLoop) serveClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id, err := l.pool.Authenticate(r)
	if err != nil || id == nil || id.Pool == "" || id.Jti == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	now := l.now()
	res, err := l.store.ClaimPAJob(ctx, jobs.ClaimRequest{
		Now: now, Lease: l.lease, Budget: l.budget, Gate: l.gate, Build: l.build,
	})
	// Committed to the outbox with the state change; owed whether or not
	// the claim succeeded.
	principals := make([]int64, 0, len(res.Notices)+1)
	for _, n := range res.Notices {
		principals = append(principals, n.Principal)
	}
	if err == nil && res.Outcome == jobs.ClaimHeld && res.Notify {
		principals = append(principals, res.Job.Principal)
	}
	// Sent after this response, never before it: the claim is committed,
	// and the token it carries must reach the worker whatever Telegram
	// does.
	defer l.deliverAfter(ctx, principals...)
	if err != nil {
		stop(w, err)
		return
	}
	switch res.Outcome {
	case jobs.ClaimClaimed:
	case jobs.ClaimHeld:
		// The hold notice, once per held job, was written to the outbox
		// with the hold and is delivered after this response; no model call was or will be
		// made for this job until the window resets (S1-R3).
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		w.WriteHeader(http.StatusNoContent)
		return
	}
	j := res.Job
	ref := jobs.Ref{Principal: j.Principal, JobID: j.ID, Attempt: j.Attempts, Digest: j.ContextDigest}
	frags, err := l.loadFragments(ctx, j.Principal, j.ConversationID)
	if err != nil {
		// Unmarked or unreadable state is never loaded (T5). A sealed row
		// that does not open will not open on the next attempt either, so
		// the job is cancelled; a store hiccup puts it back.
		// A failed read (store fault) says nothing about the job: it
		// counts no failure and is due again after ClaimBackoff(1).
		mode := jobs.ReleaseBackoff
		switch {
		case errors.Is(err, convo.ErrStoreFault):
			mode = jobs.ReleaseRetry
		case errors.Is(err, convo.ErrUnmarked) || errors.Is(err, convo.ErrUnreadable) || errors.Is(err, convo.ErrNotFound):
			mode = jobs.ReleaseCancel
		}
		l.release(ctx, ref, mode, now)
		stop(w, err)
		return
	}
	frags = trimContext(frags, l.limits.MaxContextTokens)
	tools, err := l.claimTools(j.ToolSet)
	if err != nil {
		// build admitted only pinned reads, so this is a server bug; it
		// recurs on every attempt.
		l.release(ctx, ref, jobs.ReleaseCancel, now)
		stop(w, err)
		return
	}
	ttl := j.LeaseUntil.Sub(now)
	tok, err := l.minter.MintPAJob(localjwt.PAJob{
		Principal: j.Principal, JobID: j.ID, Attempt: j.Attempts, ContextDigest: j.ContextDigest, Tools: j.ToolSet,
	}, id.Jti, id.OriginalIssuedAt, ttl)
	if err != nil {
		// A signer outage is the server's fault, not the job's: it counts
		// no failure (as the managed pool's ReleaseUnissued).
		l.release(ctx, ref, jobs.ReleaseRetry, now)
		stop(w, err)
		return
	}
	// Before the response: a fast worker's first turn must find the run.
	l.timer.claimed(j.ID, j.CreatedAt)
	writeJSON(w, http.StatusOK, claimResponse{
		JobID: j.ID, Attempt: j.Attempts, Token: tok, LeaseUntil: j.LeaseUntil, ToolSet: j.ToolSet, Tools: tools,
		Limits: wireLimits{
			MaxToolCalls: l.limits.MaxToolCalls, MaxContextTokens: l.limits.MaxContextTokens,
			MaxToolOutputBytes: jobs.MaxToolOutputBytes, MaxJobCostUSD: l.budget.PerJobUSD,
		},
		Fragments: frags, Streaming: l.streaming(),
	})
	l.typing.begin(ref, j.LeaseUntil)
}

// claimTools is the model's view of exactly the job's signed tool set, in
// its order. A tool with no pinned read entry fails the claim rather than
// being dropped: the worker must not be offered less, or other, than what
// its token names.
func (l *RunLoop) claimTools(set []string) ([]wireTool, error) {
	if len(set) == 0 {
		return nil, nil
	}
	out := make([]wireTool, 0, len(set))
	for _, name := range set {
		mt, ok := l.modelTools[name]
		if !ok {
			return nil, fmt.Errorf("%w: tool set names a tool with no pinned read entry", jobs.ErrInvalid)
		}
		out = append(out, wireTool{Name: name, Description: mt.Description, InputSchema: mt.InputSchema})
	}
	return out, nil
}

// loadFragments opens the conversation's marked fragments for principal.
// Any fragment that is unmarked or does not open fails the whole load.
func (l *RunLoop) loadFragments(ctx context.Context, principal int64, conversationID string) ([]wireFragment, error) {
	rows, err := l.store.LoadPAFragments(ctx, principal, conversationID, l.now())
	if err != nil {
		return nil, err
	}
	out := make([]wireFragment, 0, len(rows))
	for _, row := range rows {
		f, err := l.sealer.Open(principal, row)
		if err != nil {
			return nil, err
		}
		text, prov := f.Text()
		out = append(out, wireFragment{Kind: string(f.Kind()), Provenance: string(prov), Text: text})
	}
	return out, nil
}

// trimContext drops the oldest fragments until the estimate fits max
// tokens (S1-R1). The newest user fragment is never dropped: it is what
// the run answers. Fragments keep their order and marks.
func trimContext(frags []wireFragment, max int) []wireFragment {
	lastUser := -1
	for i, f := range frags {
		if f.Provenance == string(convo.ProvenanceUser) {
			lastUser = i
		}
	}
	total := 0
	for _, f := range frags {
		total += jobs.EstimateTokens(f.Text)
	}
	keep := make([]bool, len(frags))
	for i := range keep {
		keep[i] = true
	}
	for i := 0; i < len(frags) && total > max; i++ {
		if i == lastUser {
			continue
		}
		keep[i] = false
		total -= jobs.EstimateTokens(frags[i].Text)
	}
	out := make([]wireFragment, 0, len(frags))
	for i, f := range frags {
		if keep[i] {
			out = append(out, f)
		}
	}
	return out
}

func (l *RunLoop) verify(w http.ResponseWriter, r *http.Request) (jobs.Ref, localjwt.PAJob, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return jobs.Ref{}, localjwt.PAJob{}, false
	}
	pj, err := l.verifier.VerifyRequest(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return jobs.Ref{}, localjwt.PAJob{}, false
	}
	return jobs.Ref{Principal: pj.Principal, JobID: pj.JobID, Attempt: pj.Attempt, Digest: pj.ContextDigest}, pj, true
}

func (l *RunLoop) serveTurn(w http.ResponseWriter, r *http.Request) {
	ref, _, ok := l.verify(w, r)
	if !ok {
		return
	}
	var req turnRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil || req.ContextTokens < 0 {
		writeJSON(w, http.StatusBadRequest, stopResponse{Stop: "invalid"})
		return
	}
	j, err := l.store.AdmitPATurn(r.Context(), ref, jobs.TurnRequest{
		Now: l.now(), ContextTokens: req.ContextTokens, MaxContextTokens: l.limits.MaxContextTokens,
		MaxTurns: l.limits.MaxToolCalls + 1, Gate: l.gate,
	})
	if err != nil {
		l.stopRun(r.Context(), w, ref, err)
		return
	}
	l.typing.touch(ref.JobID)
	l.timer.turn(ref.JobID)
	writeJSON(w, http.StatusOK, map[string]int{"turns": j.Turns, "tool_calls": j.ToolCalls})
}

func (l *RunLoop) serveReply(w http.ResponseWriter, r *http.Request) {
	ref, _, ok := l.verify(w, r)
	if !ok {
		return
	}
	// The answer is here: the status stops before it is queued, so the
	// chat never shows "typing" under the answer.
	l.endPresence(ref.JobID)
	var req replyRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReplyBody))
	var tooBig *http.MaxBytesError
	overflow := errors.As(err, &tooBig)
	switch {
	case overflow:
		// Too long to have rendered: the same fail-closed path as
		// safetext.ErrTooLong, with the cost unreported.
		req = replyRequest{}
	case err == nil:
		err = json.Unmarshal(body, &req)
	}
	if !overflow && (err != nil || strings.TrimSpace(req.Text) == "" || (req.CostUSD != nil && !(*req.CostUSD >= 0))) {
		writeJSON(w, http.StatusBadRequest, stopResponse{Stop: "invalid"})
		return
	}
	ctx := r.Context()
	// The allow-list of URLs is what the principal typed in this
	// conversation (safetext.Render, T14). It is read before the finish
	// transaction (on SQLite the load needs the one connection); a failed
	// read is a refusal, never an empty allow-list that would still send.
	cur, err := l.store.RunningPAJob(ctx, ref, l.now(), l.gate)
	if err != nil {
		l.stopRun(ctx, w, ref, err)
		return
	}
	allow, err := l.typedAllowList(ctx, cur.Principal, cur.ConversationID)
	if err != nil {
		stop(w, err)
		return
	}
	// Rendered here only to refuse an answer too long to send; the outbox
	// renders the stored answer again when it sends it.
	_, err = safetext.Render(req.Text, allow)
	if overflow {
		err = safetext.ErrTooLong
	}
	record := true
	switch {
	case errors.Is(err, safetext.ErrTooLong):
		// Fail closed: a short server text, never a truncated answer. The
		// answer the principal never saw is not kept as conversation state.
		record = false
	case err != nil:
		writeJSON(w, http.StatusBadRequest, stopResponse{Stop: "invalid"})
		return
	}
	cost := -1.0
	if req.CostUSD != nil {
		cost = *req.CostUSD
		if cost > l.budget.PerJobUSD {
			// FinishPAJob settles at most jobs.SettleFactor x the
			// reservation and records the reported figure; the overrun is
			// worth a look.
			slog.Warn("pa reported cost above the reservation", "job_id", ref.JobID)
		}
	}
	j, err := l.store.FinishPAJob(ctx, ref, jobs.FinishRequest{
		Now: l.now(), CostUSD: cost, MinTurnUSD: l.budget.MinTurnUSD, Gate: l.gate,
		// The answer is stored as conversation state and queued in the
		// outbox in the finish transaction; the send happens after the
		// commit, through the outbox, which renders it again from the
		// stored fragment (T14).
		Record: func(ctx context.Context, tx *sql.Tx, j jobs.Job) error {
			item := jobs.OutboxItem{Principal: j.Principal, JobID: j.ID, Kind: jobs.OutboxReplyTooLong}
			if record {
				seq, err := l.appendAssistant(ctx, tx, j, req.Text)
				if err != nil {
					return err
				}
				item = jobs.OutboxItem{Principal: j.Principal, JobID: j.ID, Kind: jobs.OutboxReply,
					ConversationID: j.ConversationID, FragmentSeq: seq}
			}
			return l.store.EnqueuePAOutbox(ctx, tx, item, l.now())
		},
	})
	if err != nil {
		l.stopRun(ctx, w, ref, err)
		return
	}
	// After the commit and after this response: the send is never inside a
	// transaction and never holds up the worker. A failed send leaves the
	// row due again; the worker's part is done either way.
	writeJSON(w, http.StatusOK, map[string]bool{"queued": true})
	l.timer.replied(ref.JobID)
	l.deliverAfter(ctx, j.Principal)
}

// typedAllowList is the allow-list of URLs the principal typed in this
// conversation: user-provenance fragments only.
func (l *RunLoop) typedAllowList(ctx context.Context, principal int64, conversationID string) (safetext.UserText, error) {
	frags, err := l.loadFragments(ctx, principal, conversationID)
	if err != nil {
		return safetext.UserText{}, err
	}
	var typed []string
	for _, f := range frags {
		if f.Provenance == string(convo.ProvenanceUser) {
			typed = append(typed, f.Text)
		}
	}
	return safetext.AllowFromUserText(typed...), nil
}

// draftRequest is a streamed partial answer.
type draftRequest struct {
	Text string `json:"text"`
}

// serveDraft shows a partial answer as a draft. It is presentation only:
// nothing is stored or queued, every partial goes through
// safetext.RenderPartial with the reply's allow-list, and a refused or
// skipped draft changes no run. It answers like serveTurn when the job is
// no longer running, and sends nothing then.
func (l *RunLoop) serveDraft(w http.ResponseWriter, r *http.Request) {
	ref, _, ok := l.verify(w, r)
	if !ok {
		return
	}
	if !l.streaming() {
		writeJSON(w, http.StatusNotFound, stopResponse{Stop: "streaming_off"})
		return
	}
	var req draftRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDraftBody))
	if err != nil || json.Unmarshal(body, &req) != nil || strings.TrimSpace(req.Text) == "" {
		writeJSON(w, http.StatusOK, map[string]bool{"shown": false})
		return
	}
	if !l.limiter.allow(ref.JobID, l.now()) {
		writeJSON(w, http.StatusTooManyRequests, stopResponse{Stop: "rate"})
		return
	}
	ctx := r.Context()
	cur, err := l.store.RunningPAJob(ctx, ref, l.now(), l.gate)
	if err != nil {
		l.stopRun(ctx, w, ref, err)
		return
	}
	allow, cached := l.typing.cachedAllow(ref.JobID)
	if !cached {
		allow, err = l.typedAllowList(ctx, cur.Principal, cur.ConversationID)
		if err != nil {
			stop(w, err)
			return
		}
		l.typing.setAllow(ref.JobID, allow)
	}
	text, err := safetext.RenderPartial(req.Text, allow)
	if err != nil || text.Parts() != 1 || strings.TrimSpace(text.Part(0)) == "" {
		writeJSON(w, http.StatusOK, map[string]bool{"shown": false})
		return
	}
	shown := l.typing.showDraft(ctx, ref, text)
	writeJSON(w, http.StatusOK, map[string]bool{"shown": shown})
}

// release undoes a claim whose token was never handed out and sends the
// notice it may owe.
func (l *RunLoop) release(ctx context.Context, ref jobs.Ref, mode jobs.ReleaseMode, now time.Time) {
	l.endPresence(ref.JobID)
	l.timer.drop(ref.JobID)
	n, err := l.store.ReleasePAClaim(ctx, ref, mode, now)
	if err != nil {
		slog.Warn("pa claim not released", "job_id", ref.JobID, "err", err)
		return
	}
	if n != nil {
		l.deliverAfter(ctx, n.Principal)
	}
}

// appendAssistant stores the model's answer as an external-marked
// assistant fragment: model output is never user provenance (T5). The mark
// does not taint the conversation (convo.Taints): an answer only saw what
// the conversation already held.
func (l *RunLoop) appendAssistant(ctx context.Context, tx *sql.Tx, j jobs.Job, text string) (int64, error) {
	return l.appendFragment(ctx, tx, j, convo.NewFragment(convo.KindAssistant, convo.ProvenanceExternal, text))
}

// appendFragment stores f in the job's conversation, in tx.
// AppendPAFragment taints the conversation in the same transaction when f
// is external content.
func (l *RunLoop) appendFragment(ctx context.Context, tx *sql.Tx, j jobs.Job, f convo.Fragment) (int64, error) {
	seq, err := l.store.NextPAFragmentSeq(ctx, tx, j.Principal, j.ConversationID)
	if err != nil {
		return 0, err
	}
	sf, err := l.sealer.Seal(j.Principal, j.ConversationID, seq, f)
	if err != nil {
		return 0, err
	}
	sf.CreatedAt = l.now()
	return seq, l.store.AppendPAFragment(ctx, tx, sf)
}

// ConversationTainted reports whether the run's conversation is tainted,
// for the dispatcher's audit record and, once writes exist, its card gate
// (threat model T5, #1321). It reads the durable flag, never the fragments
// in the model's context: eviction and summaries do not lower it. Any
// error comes with true, and the caller acts on taint (S2-I10).
func (l *RunLoop) ConversationTainted(ctx context.Context, policy Policy) (bool, error) {
	pid, conv := policy.Principal().TelegramID(), policy.ConversationID()
	if pid <= 0 || conv == "" {
		return true, ErrInvalidContext
	}
	tainted, err := l.store.ReadPAConversationTaint(ctx, pid, conv)
	if err != nil {
		return true, err
	}
	return tainted, nil
}

// RecordToolResult stores a tool result the dispatcher is about to return
// to the worker as an external KindTool fragment of the job's
// conversation, which taints it, in one transaction with the job's gate
// (#1321). An error means nothing was stored and the result must be
// withheld: the worker never holds tool output its conversation does not
// record.
func (l *RunLoop) RecordToolResult(ctx context.Context, job PAJob, output []byte) error {
	if !job.ref.Valid() {
		return ErrNoJob
	}
	_, err := l.store.RecordPAToolResult(ctx, job.ref, jobs.ToolResultRequest{
		Now: l.now(), Gate: l.gate,
		Record: func(ctx context.Context, tx *sql.Tx, j jobs.Job) error {
			_, err := l.appendFragment(ctx, tx, j, convo.NewFragment(convo.KindTool, convo.ProvenanceExternal, string(output)))
			return err
		},
	})
	l.droppedNotice(ctx, job.ref, err)
	return err
}

// PAJob is a verified pa-job credential, for the tool executor (#1315).
type PAJob struct {
	ref   jobs.Ref
	tools []string
}

// Tools returns the job's signed tool set.
func (j PAJob) Tools() []string { return slices.Clone(j.tools) }

// ErrNoJob is returned by Authenticate for a missing or invalid token.
var ErrNoJob = errors.New("pa: no valid pa-job token")

// Authenticate verifies the request's pa-job token for the executor.
func (l *RunLoop) Authenticate(r *http.Request) (PAJob, error) {
	pj, err := l.verifier.VerifyRequest(r)
	if err != nil {
		return PAJob{}, ErrNoJob
	}
	return PAJob{
		ref:   jobs.Ref{Principal: pj.Principal, JobID: pj.JobID, Attempt: pj.Attempt, Digest: pj.ContextDigest},
		tools: pj.Tools,
	}, nil
}

// Principal returns the principal the job's token was minted for.
func (j PAJob) Principal() int64 { return j.ref.Principal }

// JobID returns the id of the job the token was minted for.
func (j PAJob) JobID() int64 { return j.ref.JobID }

// TokenRefusal says why a request's pa-job token was refused, for the
// executor's audit record (#1315).
type TokenRefusal struct {
	// Principal is the principal of a token this server minted and then
	// refused (expired, revoked), so the refusal can be audited in their
	// chain. 0 when the token cannot be attributed: a bad signature, a
	// malformed payload, another audience.
	Principal int64
	// Reason is a fixed label (localjwt.PAJobRefusal values).
	Reason string
}

// attributingVerifier is the optional part of JobVerifier that
// AuthenticateAttributed needs (*localjwt.PAJobVerifier implements it).
type attributingVerifier interface {
	VerifyRequestAttributed(r *http.Request) (localjwt.PAJob, int64, localjwt.PAJobRefusal, error)
}

// AuthenticateAttributed is Authenticate that also describes a refusal.
// A verifier without attribution refuses with Principal 0.
func (l *RunLoop) AuthenticateAttributed(r *http.Request) (PAJob, TokenRefusal, error) {
	av, ok := l.verifier.(attributingVerifier)
	if !ok {
		j, err := l.Authenticate(r)
		if err != nil {
			return PAJob{}, TokenRefusal{Reason: string(localjwt.PAJobRefusedInvalid)}, err
		}
		return j, TokenRefusal{}, nil
	}
	pj, principal, reason, err := av.VerifyRequestAttributed(r)
	if err != nil {
		return PAJob{}, TokenRefusal{Principal: principal, Reason: string(reason)}, ErrNoJob
	}
	return PAJob{
		ref:   jobs.Ref{Principal: pj.Principal, JobID: pj.JobID, Attempt: pj.Attempt, Digest: pj.ContextDigest},
		tools: pj.Tools,
	}, TokenRefusal{}, nil
}

// AdmitPAToolCall is the executor's gate before it dispatches server/tool
// for job (#1315): the tool must be in the signed tool set of the token AND
// of the job row (S1-I1), a pinned read, under the tool-call cap (S1-R2),
// with the reservation live and consent and the conversation still valid.
// It counts the call; a refused call is not counted.
func (l *RunLoop) AdmitPAToolCall(ctx context.Context, job PAJob, server, tool string) error {
	_, err := l.AdmitToolCall(ctx, job, server, tool)
	return err
}

// AdmitToolCall is AdmitPAToolCall returning the run's Policy, rebuilt from
// the job row the admission just read (threat model T4, I10: "principal,
// connection and authority revision come from the job row"). The row's
// execution context must hash to the digest the row and the token carry; a
// context that does not is unreadable state and refuses (I9).
//
// The call is counted by the admission, before the context is checked: a
// call refused for an unreadable or tampered context has used one of the
// run's tool-call slots. That fails closed (owner question (b) on #1341:
// an admitted-then-refused call counts toward the cap).
func (l *RunLoop) AdmitToolCall(ctx context.Context, job PAJob, server, tool string) (Policy, error) {
	if !job.ref.Valid() {
		return Policy{}, ErrNoJob
	}
	name := server + "/" + tool
	if server == "" || tool == "" || !slices.Contains(job.tools, name) || !l.readTools[name] {
		return Policy{}, jobs.ErrToolNotInSet
	}
	j, err := l.store.AdmitPAToolCall(ctx, job.ref, jobs.ToolCallRequest{
		Now: l.now(), Tool: name, MaxToolCalls: l.limits.MaxToolCalls, Gate: l.gate,
	})
	l.droppedNotice(ctx, job.ref, err)
	if err != nil {
		l.endPresence(job.ref.JobID)
		l.timer.drop(job.ref.JobID)
		return Policy{}, err
	}
	l.typing.touch(job.ref.JobID)
	if l.streaming() {
		l.typing.showStatus(job.ref, safetext.ServerText(toolStatus(name)))
	}
	l.timer.toolStart(job.ref.JobID)
	return policyFromJob(j, job.ref)
}

// StillRunning re-reads job's row after a tool call returned: the job must
// still be running under the same attempt and context, with consent and
// the conversation still valid (the same gate as the admission). A job
// cancelled, consent withdrawn or a conversation closed while the call was
// on the wire is an error, and the dispatcher discards the result. A read
// error is an error too (I9).
func (l *RunLoop) StillRunning(ctx context.Context, job PAJob) error {
	if !job.ref.Valid() {
		return ErrNoJob
	}
	_, err := l.store.RunningPAJob(ctx, job.ref, l.now(), l.gate)
	l.droppedNotice(ctx, job.ref, err)
	if err != nil {
		l.endPresence(job.ref.JobID)
		l.timer.drop(job.ref.JobID)
	} else {
		l.typing.touch(job.ref.JobID)
		l.timer.toolEnd(job.ref.JobID)
	}
	return err
}

// policyFromJob rebuilds the Policy of a running job from its row. The
// stored execution context is checked against the digest of the row and
// of the token, and against the row's own principal, job and attempt.
func policyFromJob(j jobs.Job, ref jobs.Ref) (Policy, error) {
	sum := sha256.Sum256(j.ExecutionContext)
	if len(j.ExecutionContext) == 0 || hex.EncodeToString(sum[:]) != j.ContextDigest || j.ContextDigest != ref.Digest ||
		j.Principal != ref.Principal || j.ID != ref.JobID || j.Attempts != ref.Attempt {
		return Policy{}, fmt.Errorf("%w: execution context does not match the job", jobs.ErrUnreadable)
	}
	dec := json.NewDecoder(strings.NewReader(string(j.ExecutionContext)))
	dec.DisallowUnknownFields()
	var rc runContext
	if err := dec.Decode(&rc); err != nil {
		return Policy{}, fmt.Errorf("%w: execution context: %v", jobs.ErrUnreadable, err)
	}
	// The trigger is not read here (TestNoTriggerCalls): the digest already
	// proves this is the context the claim built, and the claim builds
	// interactive runs only.
	if rc.V != 1 || rc.Principal != j.Principal || rc.JobID != j.ID || rc.Attempt != j.Attempts ||
		rc.ConversationID != j.ConversationID {
		return Policy{}, fmt.Errorf("%w: execution context names another run", jobs.ErrUnreadable)
	}
	ec, err := restoreInteractive(j, rc.Connections, BudgetReservation{ID: rc.Budget})
	if err != nil {
		return Policy{}, fmt.Errorf("%w: execution context: %v", jobs.ErrUnreadable, err)
	}
	return ec.Policy(), nil
}

// stopRun is stop for a step that ran the gate: a job cancelled because its
// conversation expired mid-run, or its principal was disabled or taken off
// the allowlist, owes the principal a notice.
func (l *RunLoop) stopRun(ctx context.Context, w http.ResponseWriter, ref jobs.Ref, err error) {
	l.endPresence(ref.JobID)
	l.timer.drop(ref.JobID)
	l.droppedNotice(ctx, ref, err)
	stop(w, err)
}

// droppedNotice sends the notice owed when err says this call cancelled the
// job because its conversation closed or expired, or its principal was
// disabled or left the allowlist (jobs.NoticeFor). The store returns those
// errors only to the call that cancelled, so it is sent once.
func (l *RunLoop) droppedNotice(ctx context.Context, ref jobs.Ref, err error) {
	if _, owed := jobs.NoticeFor(err); owed {
		// The store wrote the notice with the cancellation.
		l.deliverAfter(ctx, ref.Principal)
	}
}
