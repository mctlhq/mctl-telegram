package agentapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func claimAttempt(t *testing.T, h *testHarness, jobID int64) int {
	t.Helper()
	claimed, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, db.RuntimeOwn, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
	}
	return claimed[0].Attempts
}

// A failed invocation reported by the worker returns the job to pending with
// a short delay, not the visibility timeout.
func TestHandleRetryJob_RequeuesWithShortDelay(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:retry", conv.ID)
	attempt := claimAttempt(t, h, jobID)

	rec := h.do("POST", "/jobs/"+itoaTest(jobID)+"/retry", retryJobRequest{
		Attempt: attempt, Outcome: "model_exited_without_completion",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	job, err := h.store.GetAgentJob(context.Background(), h.userID, jobID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if job.Status != db.JobPending {
		t.Fatalf("status = %q, want pending", job.Status)
	}
	if !job.NextRunAt.Before(time.Now().UTC().Add(15 * time.Second)) {
		t.Fatalf("next_run_at %v is not short", job.NextRunAt)
	}
	if job.LastError != "model_exited_without_completion" {
		t.Fatalf("last_error = %q", job.LastError)
	}
}

func TestHandleRetryJob_StaleAttemptReturnsConflict(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:retry-stale", conv.ID)
	attempt := claimAttempt(t, h, jobID)

	rec := h.do("POST", "/jobs/"+itoaTest(jobID)+"/retry", retryJobRequest{
		Attempt: attempt + 1, Outcome: "invocation_failed",
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
	job, _ := h.store.GetAgentJob(context.Background(), h.userID, jobID)
	if job.Status != db.JobProcessing {
		t.Fatalf("status = %q, want processing (untouched)", job.Status)
	}
}

func TestHandleRetryJob_RejectsBadInput(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:retry-bad", conv.ID)
	attempt := claimAttempt(t, h, jobID)
	path := "/jobs/" + itoaTest(jobID) + "/retry"

	for name, req := range map[string]retryJobRequest{
		"free text outcome": {Attempt: attempt, Outcome: "the model said something"},
		"empty outcome":     {Attempt: attempt},
		"zero attempt":      {Attempt: 0, Outcome: "invocation_failed"},
	} {
		if rec := h.do("POST", path, req); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400, body=%s", name, rec.Code, rec.Body.String())
		}
	}
	job, _ := h.store.GetAgentJob(context.Background(), h.userID, jobID)
	if job.Status != db.JobProcessing {
		t.Fatalf("status = %q, want processing after rejected requests", job.Status)
	}
}

func TestHandleRetryJob_UnknownJobReturnsNotFound(t *testing.T) {
	h := newHarness(t)
	rec := h.do("POST", "/jobs/999999/retry", retryJobRequest{Attempt: 1, Outcome: "invocation_failed"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func (h *testHarness) auditDetail(t *testing.T, tool string) string {
	t.Helper()
	var d string
	if err := h.store.DB.QueryRowContext(context.Background(),
		`SELECT COALESCE(error, '') FROM audit_logs WHERE tool_name = $1 ORDER BY id DESC LIMIT 1`, tool).Scan(&d); err != nil {
		t.Fatalf("audit row for %s: %v", tool, err)
	}
	return d
}

// The third failed attempt is left to the sweeper: 200 processing, nothing
// written, and the audit row says so rather than a bare "ok".
func TestHandleRetryJob_LeftToSweeperIsReportedAndAudited(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:retry-sweeper", conv.ID)
	if _, err := h.store.DB.ExecContext(context.Background(),
		`UPDATE agent_jobs SET max_attempts = 1 WHERE id = $1`, jobID); err != nil {
		t.Fatalf("max_attempts: %v", err)
	}
	attempt := claimAttempt(t, h, jobID)

	rec := h.do("POST", "/jobs/"+itoaTest(jobID)+"/retry", retryJobRequest{Attempt: attempt, Outcome: "invocation_failed"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"processing"`) {
		t.Fatalf("status = %d body=%s, want 200 processing", rec.Code, rec.Body.String())
	}
	job, _ := h.store.GetAgentJob(context.Background(), h.userID, jobID)
	if job.Status != db.JobProcessing {
		t.Fatalf("status = %q, want processing (untouched)", job.Status)
	}
	if d := h.auditDetail(t, "retry_agent_job"); !strings.Contains(d, "processing") {
		t.Fatalf("audit detail = %q, want the resulting status", d)
	}
}

func jobTokenIdentity(h *testHarness, convID, jobID int64, attempt int) *auth.Identity {
	return &auth.Identity{
		UserID: h.userID, Subject: "tg:1", TelegramID: 1,
		JobID: jobID, JobAttempt: attempt, ConversationID: convID,
	}
}

// With a job token the attempt comes from the token, so a body without one
// works; a body naming another attempt or another job is refused by binding.
func TestHandleRetryJob_JobTokenBinding(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:retry-token", conv.ID)
	other := h.seedJob("evt:v1:1:555:retry-token-other", conv.ID)
	attempt := claimAttempt(t, h, jobID)
	id := jobTokenIdentity(h, conv.ID, jobID, attempt)
	path := "/jobs/" + itoaTest(jobID) + "/retry"

	if rec := h.doAs(id, "POST", path, map[string]any{"outcome": "invocation_failed", "attempt": attempt + 1}); rec.Code != http.StatusForbidden {
		t.Fatalf("mismatched attempt: status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	if rec := h.doAs(id, "POST", "/jobs/"+itoaTest(other)+"/retry", map[string]any{"outcome": "invocation_failed"}); rec.Code != http.StatusForbidden {
		t.Fatalf("other job: status = %d, want 403, body=%s", rec.Code, rec.Body.String())
	}
	if job, _ := h.store.GetAgentJob(context.Background(), h.userID, jobID); job.Status != db.JobProcessing {
		t.Fatalf("status = %q after refused requests, want processing", job.Status)
	}
	rec := h.doAs(id, "POST", path, map[string]any{"outcome": "invocation_failed"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"pending"`) {
		t.Fatalf("omitted attempt: status = %d body=%s, want 200 pending", rec.Code, rec.Body.String())
	}
}
