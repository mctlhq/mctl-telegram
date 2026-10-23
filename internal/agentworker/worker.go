package agentworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// eventPoller is the subset of *Client the worker loop needs — narrowed for
// testability, matching agentAPI's pattern in mcpserver.go.
type eventPoller interface {
	PollEvents(ctx context.Context, limit int) ([]JobEnvelope, error)
}

// Runner invokes one Claude turn for a single claimed job. Success means the
// process ran cleanly AND this exact attempt reached a terminal state through
// complete_agent_job. A worker crash or an unsuccessful turn still leaves
// the job claimed for the existing visibility-timeout sweeper to requeue;
// Runner makes that outcome observable immediately instead of logging it as
// a successful invocation.
type Runner interface {
	Run(ctx context.Context, job JobEnvelope) error
}

// backoff bounds how long the poll loop waits after a failed PollEvents call
// before retrying, growing from minBackoff to maxBackoff and resetting to
// minBackoff on the next success.
const (
	minPollBackoff = 2 * time.Second
	maxPollBackoff = 60 * time.Second
	// jobDeadlineFallback is used when a claimed job's Deadline field is
	// missing or unparsable — see JobEnvelope.ParsedDeadline.
	jobDeadlineFallback = 5 * time.Minute
)

// Worker runs the long-poll → invoke-claude loop. Construct with NewWorker.
type Worker struct {
	poller eventPoller
	runner Runner
	health *Health
	// concurrency is the number of jobs run at once; 1 (the default) is the
	// sequential behaviour.
	concurrency int
}

func NewWorker(poller eventPoller, runner Runner) *Worker {
	return &Worker{poller: poller, runner: runner, concurrency: 1}
}

// MaxConcurrency is the largest accepted worker concurrency: the server's
// ?limit= cap on one claim.
const MaxConcurrency = 10

// WithConcurrency sets how many jobs one worker runs at once (clamped to
// 1..MaxConcurrency). The server still never hands out two jobs of one
// conversation at once.
func (w *Worker) WithConcurrency(n int) *Worker {
	if n < 1 {
		n = 1
	}
	if n > MaxConcurrency {
		n = MaxConcurrency
	}
	w.concurrency = n
	return w
}

// convGate is defence in depth for the server's per-conversation
// serialization: it never lets two jobs of one conversation run together
// inside this process.
type convGate struct {
	mu      sync.Mutex
	running map[int64]chan struct{}
}

// enter blocks until no other job of conv runs here, then marks conv running.
// It reports whether it had to wait. Conversation 0 (none) is not gated.
func (g *convGate) enter(conv int64) (waited bool) {
	if conv == 0 {
		return false
	}
	for {
		g.mu.Lock()
		if g.running == nil {
			g.running = map[int64]chan struct{}{}
		}
		ch, busy := g.running[conv]
		if !busy {
			g.running[conv] = make(chan struct{})
			g.mu.Unlock()
			return waited
		}
		g.mu.Unlock()
		waited = true
		<-ch
	}
}

func (g *convGate) leave(conv int64) {
	if conv == 0 {
		return
	}
	g.mu.Lock()
	if ch, ok := g.running[conv]; ok {
		delete(g.running, conv)
		close(ch)
	}
	g.mu.Unlock()
}

// WithHealth attaches a Health reporter that Loop updates as it runs, for
// cmd/agent-worker's HTTP probes. Optional — Loop works identically without
// one (Health's methods are all nil-safe).
func (w *Worker) WithHealth(h *Health) *Worker {
	w.health = h
	return w
}

// ErrFatalAuth is returned by Loop when it stops because PollEvents reported
// a fatal (401/403) auth error, distinguishing that from an ordinary ctx
// cancellation — cmd/agent-worker's run() propagates it so a process
// supervisor sees a nonzero exit instead of what would otherwise look like
// an intentional, clean shutdown.
var ErrFatalAuth = errors.New("agent-worker: fatal auth error, poll loop stopped")

// Loop polls for jobs and runs them, up to the configured concurrency at once
// (WithConcurrency, default 1), until ctx is canceled. It polls for exactly as
// many jobs as it has free slots, so no claimed job waits for a slot while its
// visibility deadline runs. The server serializes each conversation, so two
// jobs of one conversation never run together; the worker also enforces that
// locally. On shutdown it stops polling and waits for in-flight jobs (each
// bounded by its own deadline) before returning.
//
// Returns nil on a normal ctx-cancel shutdown, ErrFatalAuth if it stopped
// because of an unrecoverable 401/403 (see isFatalAuthError).
func (w *Worker) Loop(ctx context.Context) error {
	defer w.health.SetStopped()
	n := w.concurrency
	if n < 1 {
		n = 1
	}
	slots := make(chan struct{}, n)
	var wg sync.WaitGroup
	defer wg.Wait()
	gate := &convGate{}
	backoff := minPollBackoff
	for {
		if ctx.Err() != nil {
			return nil
		}
		// Wait for one free slot, then take every other free slot too.
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return nil
		}
		held := 1
	more:
		for held < n {
			select {
			case slots <- struct{}{}:
				held++
			default:
				break more
			}
		}
		release := func(k int) {
			for ; k > 0; k-- {
				<-slots
			}
		}
		jobs, err := w.poller.PollEvents(ctx, held)
		if err != nil {
			release(held)
			if ctx.Err() != nil {
				return nil
			}
			if isFatalAuthError(err) {
				// AGENT_API_TOKEN is read once at process start (see
				// cmd/agent-worker) — there is no live credential-reload
				// path, so retrying an expired/revoked token can only ever
				// repeat the same 401/403 forever. Treating it like an
				// ordinary transient network blip would let the process
				// keep running (and looking "alive" in logs, just noisy
				// warnings) while jobs silently pile up unprocessed with no
				// operator signal that anything actually needs fixing.
				// Stopping the loop turns that into a visible process
				// exit — restart with a fresh token is the only real fix.
				w.health.SetFatal()
				slog.Error("agent-worker: auth failure is not recoverable by retrying, stopping poll loop", "err", err)
				return ErrFatalAuth
			}
			w.health.SetPollResult(false)
			slog.Warn("agent-worker: poll failed", "err", err, "retry_in", backoff)
			if !sleepCtx(ctx, backoff) {
				return nil
			}
			backoff = nextBackoff(backoff)
			continue
		}
		w.health.SetPollResult(true)
		backoff = minPollBackoff
		if len(jobs) < held {
			release(held - len(jobs))
		}
		for i, job := range jobs {
			// A job past held means the server returned more than asked for.
			// Honour the claim at once, outside the slots, rather than block
			// the loop (and shutdown) until a slot frees while its deadline
			// runs.
			slotted := i < held
			wg.Add(1)
			go func(job JobEnvelope) {
				defer wg.Done()
				if slotted {
					defer func() { <-slots }()
				}
				w.runJob(ctx, gate, job)
			}(job)
		}
	}
}

func (w *Worker) runJob(ctx context.Context, gate *convGate, job JobEnvelope) {
	jobCtx, cancel := context.WithDeadline(ctx, job.ParsedDeadline(jobDeadlineFallback))
	defer cancel()
	if gate.enter(job.ConversationID) {
		slog.Error("agent-worker: claimed a job of a conversation already running here; waited for it",
			"job_id", job.JobID)
	}
	defer gate.leave(job.ConversationID)
	err := w.runner.Run(jobCtx, job)
	// event_id (format evt:v1:<account>:<chat>:<message>) is
	// deliberately not logged here — it's not a redacted slog key,
	// and job_id already gives an operator everything needed to
	// correlate against the API for triage.
	if err != nil {
		outcome := "invocation_failed"
		if errors.Is(err, ErrAgentDidNotCompleteJob) {
			outcome = "model_exited_without_completion"
		}
		slog.Warn("agent-worker: job invocation failed",
			"job_id", job.JobID, "outcome", outcome, "err", err)
		return
	}
	slog.Info("agent-worker: job invocation finished",
		"job_id", job.JobID, "outcome", "completed")
}

// isFatalAuthError reports whether err is an APIError carrying a 401 or 403
// — the two statuses an expired, revoked, or otherwise invalid
// AGENT_API_TOKEN produces, none of which a same-token retry can ever
// resolve.
func isFatalAuthError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
}

func nextBackoff(cur time.Duration) time.Duration {
	next := cur * 2
	if next > maxPollBackoff {
		return maxPollBackoff
	}
	return next
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// ClaudeResult mirrors the subset of `claude -p --output-format json`'s
// final result object this package cares about. Field names/shape confirmed
// against a real `claude` CLI invocation's stdout (type=result,
// subtype=success|error_*, is_error, duration_ms, num_turns, total_cost_usd,
// result) — not guessed.
type ClaudeResult struct {
	Type       string `json:"type"`
	Subtype    string `json:"subtype"`
	IsError    bool   `json:"is_error"`
	DurationMS int64  `json:"duration_ms"`
	NumTurns   int    `json:"num_turns"`
	// TotalCostUSD is a pointer so a missing key or a JSON null (no spend
	// observed) is distinguishable from a genuinely free run (a real 0.0) —
	// json.Unmarshal leaves a pointer field nil in both of those absent
	// cases, whereas a plain float64 field cannot tell "absent" from "zero".
	// A false zero here would silently understate persisted spend.
	TotalCostUSD *float64 `json:"total_cost_usd"`
	Result       string   `json:"result"`
}

// ParseClaudeResult extracts the final JSON result object from `claude -p
// --output-format json` stdout. That mode prints exactly one JSON value, so
// this is a plain Unmarshal — no stream-json line-splitting needed.
func ParseClaudeResult(stdout []byte) (*ClaudeResult, error) {
	var res ClaudeResult
	if err := json.Unmarshal(stdout, &res); err != nil {
		return nil, fmt.Errorf("parse claude result: %w", err)
	}
	return &res, nil
}

// ErrClaudeReportedError is returned by a Runner when the process exited 0
// but its own result JSON carries is_error=true (e.g. it hit its
// --max-budget-usd cap, or an internal SDK error) — a distinct case from a
// nonzero exit or a malformed result, worth telling apart in logs/metrics.
var ErrClaudeReportedError = errors.New("claude reported is_error=true")

// ErrClaudeUsageLimit is the quota/usage-limit subclass of
// ErrClaudeReportedError. Declaring it by wrapping the general error means
// an error built on top of it satisfies errors.Is for BOTH, so no existing
// caller that tests the general case changes behaviour.
var ErrClaudeUsageLimit = fmt.Errorf("%w: usage limit or quota exhausted", ErrClaudeReportedError)

// usageLimitSubtypes are matched as lowercase substrings of res.Subtype. The
// exact subtype string the `claude` CLI emits on a usage-limit/quota stop is
// not evidenced anywhere in this codebase (only success, error_max_turns,
// and error_during_execution appear in fixtures) — this is a documented
// token set, not a captured value. res.Result is deliberately NOT inspected:
// it can carry model-derived Telegram content and is prompt-injectable,
// exactly as CheckResult's doc comment explains for the error string itself.
var usageLimitSubtypes = []string{"usage_limit", "rate_limit", "quota", "credit_balance", "insufficient_credits"}

// isUsageLimitSubtype reports whether subtype (case-insensitively) contains
// one of usageLimitSubtypes.
func isUsageLimitSubtype(subtype string) bool {
	lower := strings.ToLower(subtype)
	for _, s := range usageLimitSubtypes {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// CheckResult turns a parsed ClaudeResult into an error iff IsError is set,
// wrapping ErrClaudeReportedError with the CLI's own subtype for context.
//
// Deliberately excludes res.Result (the model's own result text) from the
// returned error: on this path (is_error=true after a successful get_event
// or get_conversation_context call), that text can carry content derived
// from the Telegram message the model was reasoning about, and Worker.Loop
// logs this error verbatim (slog.Warn). The redaction layer in
// internal/audit/redact.go operates on structured attribute keys, not
// free-form error string values, so embedding raw result text here would
// bypass it the same way claudeinvoker.go's Run keeps subprocess
// stdout/stderr out of its own returned errors. subtype is a small
// enum-like string (e.g. "error_max_turns") safe to log; result length is
// kept for triage without the content.
func CheckResult(res *ClaudeResult) error {
	if res == nil || !res.IsError {
		return nil
	}
	subtype := res.Subtype
	if subtype == "" {
		subtype = "unknown"
	}
	sentinel := ErrClaudeReportedError
	if isUsageLimitSubtype(res.Subtype) {
		sentinel = ErrClaudeUsageLimit
	}
	return fmt.Errorf("%w: subtype=%s (result: %d bytes, see run logs)", sentinel, subtype, len(res.Result))
}
