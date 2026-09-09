package agentapi

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// TestHandleReportJobCost_RecordsForClaimedAttempt covers the happy path:
// a worker reports cost for the exact attempt it claimed.
func TestHandleReportJobCost_RecordsForClaimedAttempt(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:cost", conv.ID)

	claimed, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
	}
	attempt := claimed[0].Attempts

	rec := h.do("POST", "/jobs/"+itoaTest(jobID)+"/cost", reportJobCostRequest{
		Attempt: attempt, CostUSD: 0.15,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	job, err := h.store.GetAgentJob(context.Background(), h.userID, jobID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if !job.CostUSD.Valid || job.CostUSD.Float64 != 0.15 {
		t.Fatalf("CostUSD = %+v, want valid 0.15", job.CostUSD)
	}
}

// TestHandleReportJobCost_StaleAttemptReturnsConflict asserts the claim
// fencing surfaces as 409, mirroring handleJobComplete's own stale-claim
// mapping.
func TestHandleReportJobCost_StaleAttemptReturnsConflict(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:cost-stale", conv.ID)

	ctx := context.Background()
	first, err := h.store.ClaimAgentJobs(ctx, "test-replica", h.userID, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("claim: jobs=%+v err=%v", first, err)
	}

	// Age the claim out and let another replica take it, so attempt 1 becomes
	// genuinely stale while staying POSITIVE. Subtracting one from a first
	// claim would produce attempt 0, which the handler now rejects as a bad
	// request before the fence is ever consulted — that path is covered by
	// TestHandleReportJobCost_RejectsNonPositiveAttempt, and using it here
	// would test the validator instead of the claim fence this test is named
	// for.
	if _, err := h.store.DB.ExecContext(ctx,
		`UPDATE agent_jobs SET claimed_at = $1 WHERE id = $2`,
		time.Now().UTC().Add(-10*time.Minute), jobID,
	); err != nil {
		t.Fatalf("backdate claim: %v", err)
	}
	if _, _, err := h.store.RequeueStaleAgentJobs(ctx, 5*time.Minute); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	second, err := h.store.ClaimAgentJobs(ctx, "other-replica", h.userID, 1)
	if err != nil || len(second) != 1 {
		t.Fatalf("re-claim: jobs=%+v err=%v", second, err)
	}
	if second[0].Attempts <= first[0].Attempts {
		t.Fatalf("re-claim attempts = %d, want > %d", second[0].Attempts, first[0].Attempts)
	}
	staleAttempt := first[0].Attempts

	rec := h.do("POST", "/jobs/"+itoaTest(jobID)+"/cost", reportJobCostRequest{
		Attempt: staleAttempt, CostUSD: 9.99,
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleReportJobCost_UnknownJobReturnsNotFound guards the existence
// check.
func TestHandleReportJobCost_UnknownJobReturnsNotFound(t *testing.T) {
	h := newHarness(t)
	rec := h.do("POST", "/jobs/999999/cost", reportJobCostRequest{Attempt: 1, CostUSD: 1})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404, body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleReportJobCost_RejectsNonPositiveAttempt guards the claim fence:
// RecordAgentJobCost carries no status predicate, so attempt 0 would match a
// never-claimed pending job (attempts = 0). ClaimAgentJobs only ever hands
// out attempts >= 1, so the handler rejects it outright.
func TestHandleReportJobCost_RejectsNonPositiveAttempt(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:cost-attempt-zero", conv.ID)

	for _, attempt := range []int{0, -1} {
		rec := h.do("POST", "/jobs/"+itoaTest(jobID)+"/cost", reportJobCostRequest{
			Attempt: attempt, CostUSD: 1.5,
		})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("attempt=%d: status = %d, want 400, body=%s", attempt, rec.Code, rec.Body.String())
		}
	}

	job, err := h.store.GetAgentJob(context.Background(), h.userID, jobID)
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if job.CostUSD.Valid {
		t.Fatalf("CostUSD = %+v, want unset (no cost may land on an unclaimed job)", job.CostUSD)
	}
}

// TestHandleReportJobCost_RejectsNegativeCost keeps spend accounting from
// being corrupted by a negative figure.
func TestHandleReportJobCost_RejectsNegativeCost(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:cost-negative", conv.ID)

	rec := h.do("POST", "/jobs/"+itoaTest(jobID)+"/cost", reportJobCostRequest{
		Attempt: 1, CostUSD: -1,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
}
