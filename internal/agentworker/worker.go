package agentworker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// eventPoller is the subset of *Client the worker loop needs — narrowed for
// testability, matching agentAPI's pattern in mcpserver.go.
type eventPoller interface {
	PollEvents(ctx context.Context, limit int) ([]JobEnvelope, error)
}

// Runner invokes one Claude turn for a single claimed job and reports
// whether the invocation itself succeeded (process ran and exited 0) —
// NOT whether the model actually completed the job. A worker crash or a
// model that never calls complete_agent_job both leave the job claimed;
// the existing visibility-timeout sweeper (internal/sweeper.AgentJobs,
// A-PR2) requeues it, and repeated failures eventually dead-letter it.
// This package deliberately does not duplicate that recovery logic — see
// mctlhq/mctl-telegram#298's "no special crash-recovery logic needed in the
// worker itself" note.
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
}

func NewWorker(poller eventPoller, runner Runner) *Worker {
	return &Worker{poller: poller, runner: runner}
}

// Loop polls for jobs and runs them one at a time until ctx is canceled.
// Sequential (not concurrent) processing is a deliberate simplification for
// the initial version: the account-scoped rate/turn limits the policy engine
// already enforces (internal/agent/policy) are per-conversation, not
// per-worker, so nothing here currently depends on concurrency — revisit if
// throughput becomes a real bottleneck.
func (w *Worker) Loop(ctx context.Context) {
	backoff := minPollBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		jobs, err := w.poller.PollEvents(ctx, 1)
		if err != nil {
			if ctx.Err() != nil {
				return
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
				slog.Error("agent-worker: auth failure is not recoverable by retrying, stopping poll loop", "err", err)
				return
			}
			slog.Warn("agent-worker: poll failed", "err", err, "retry_in", backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = minPollBackoff
		for _, job := range jobs {
			jobCtx, cancel := context.WithDeadline(ctx, job.ParsedDeadline(jobDeadlineFallback))
			err := w.runner.Run(jobCtx, job)
			cancel()
			if err != nil {
				slog.Warn("agent-worker: job invocation failed", "job_id", job.JobID, "event_id", job.EventID, "err", err)
			} else {
				slog.Info("agent-worker: job invocation finished", "job_id", job.JobID, "event_id", job.EventID)
			}
		}
	}
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
	Type         string  `json:"type"`
	Subtype      string  `json:"subtype"`
	IsError      bool    `json:"is_error"`
	DurationMS   int64   `json:"duration_ms"`
	NumTurns     int     `json:"num_turns"`
	TotalCostUSD float64 `json:"total_cost_usd"`
	Result       string  `json:"result"`
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

// CheckResult turns a parsed ClaudeResult into an error iff IsError is set,
// wrapping ErrClaudeReportedError with the CLI's own subtype/result text for
// context.
func CheckResult(res *ClaudeResult) error {
	if res == nil || !res.IsError {
		return nil
	}
	detail := strings.TrimSpace(res.Result)
	if detail == "" {
		detail = res.Subtype
	}
	return fmt.Errorf("%w: %s", ErrClaudeReportedError, detail)
}
