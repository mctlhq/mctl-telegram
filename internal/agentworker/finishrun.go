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
	recordRunCost(ctx, client, job, res, m)
	if err := CheckResult(res); err != nil {
		countRunResultError(m, err)
		return err
	}
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

func recordRunCost(ctx context.Context, client *Client, job JobEnvelope, res *ClaudeResult, m *metrics.Registry) {
	if res == nil || res.TotalCostUSD == nil {
		return
	}
	cost := *res.TotalCostUSD
	if cost < 0 {
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
