package agentworker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// finishRun is the tail both runners share: record cost (before the check),
// map the result to an error, then verify the durable terminal state.
func finishRun(ctx context.Context, client *Client, job JobEnvelope, res *ClaudeResult, m *metrics.Registry) error {
	// Recorded BEFORE CheckResult so a job that fails the check below still
	// reports what it spent — spend telemetry must not be gated on the run
	// having succeeded.
	recordRunCost(ctx, client, job, res, m)
	if err := CheckResult(res); err != nil {
		countRunResultError(m, err)
		return err
	}
	// The final model text is never evidence of a completed action: a model
	// with no tools can emit text that merely resembles a tool call and still
	// exit 0/is_error=false. Query the API's durable, user-scoped job record
	// instead. Requiring the same attempt preserves the claim fencing used by
	// complete_agent_job and prevents a stale invocation from taking credit
	// for a newer worker's completion.
	status, err := client.GetJobStatus(ctx, job.JobID)
	if err != nil {
		return fmt.Errorf("verify job %d completion: %w", job.JobID, err)
	}
	if status.JobID != job.JobID || status.Attempt != job.Attempt || !status.Terminal() {
		return fmt.Errorf("%w: job_id=%d returned_job_id=%d status=%s attempt=%d expected_attempt=%d",
			ErrAgentDidNotCompleteJob, job.JobID, status.JobID, status.Status, status.Attempt, job.Attempt)
	}
	return nil
}

// recordRunCost is a no-op when res.TotalCostUSD is nil — nothing was
// actually observed to report. Otherwise it best-effort reports the figure to
// the agent API so it lands on the job row's cost_usd column, and, when a
// registry is wired, also increments mctl_agent_job_cost_usd_total labeled by
// whether the result reported is_error. A failure to report is logged as a
// warning and never changes the run's return value — spend telemetry must not
// be able to fail a job.
//
// The nil-registry check deliberately guards ONLY the counter. cost_usd is a
// durable accounting record and must not depend on whether an optional
// telemetry field happens to be set: Metrics is documented as optional, and
// a future caller that leaves it nil would otherwise silently stop
// persisting spend (claude review P3 on PR #583).
func recordRunCost(ctx context.Context, client *Client, job JobEnvelope, res *ClaudeResult, m *metrics.Registry) {
	if res == nil || res.TotalCostUSD == nil {
		return
	}
	cost := *res.TotalCostUSD
	if cost < 0 {
		// prometheus.Counter.Add panics on a negative delta, and the value
		// comes straight from the provider/CLI's reported cost — nothing
		// upstream constrains its sign. Drop it rather than take the
		// poll-loop process down, and keep the DB write honest too.
		slog.Warn("agent-worker: ignoring negative reported job cost", "job_id", job.JobID)
		return
	}
	result := metrics.JobCostResultSuccess
	if res.IsError {
		result = metrics.JobCostResultError
	}
	if m != nil {
		m.AgentJobCostUSDTotal.WithLabelValues(result).Add(cost)
	}
	if err := client.ReportJobCost(ctx, job.JobID, job.Attempt, cost); err != nil {
		slog.Warn("agent-worker: report job cost failed", "job_id", job.JobID, "err", err)
	}
}

// countRunResultError increments mctl_agent_claude_result_errors_total for a
// CheckResult error, classifying it as usage_limit or other. No-op on a nil
// registry.
func countRunResultError(m *metrics.Registry, err error) {
	if m == nil || err == nil {
		return
	}
	class := metrics.ClaudeResultClassOther
	if errors.Is(err, ErrClaudeUsageLimit) {
		class = metrics.ClaudeResultClassUsageLimit
	}
	m.AgentClaudeResultErrorsTotal.WithLabelValues(class).Inc()
}
