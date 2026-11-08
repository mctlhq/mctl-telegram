package agentapi

import (
	"context"
	"net/http"
	"testing"
	"time"

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
