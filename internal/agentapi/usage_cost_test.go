package agentapi

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// managedJobHarness claims one managed job with the usage ledger on and
// returns a harness that speaks as that job's token.
func managedJobHarness(t *testing.T) (*testHarness, *metrics.Registry, int64, int) {
	t.Helper()
	h, m := newHarnessWithMetrics(t)
	h.store.WithManagedBudget(db.ManagedBudget{PerJobUSD: 0.5, AccountDayUSD: 5, AccountMonthUSD: 50, GlobalDayUSD: 50})
	h.seedProfile(db.AgentModeObserve)
	if _, err := h.store.DB.Exec(`UPDATE agent_profiles SET runtime = 'managed', managed_consent_version = $1 WHERE user_id = $2`,
		db.ManagedConsentCurrent, h.userID); err != nil {
		t.Fatal(err)
	}
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:usage", conv.ID)
	jobs, err := h.store.ClaimManagedAgentJobs(context.Background(), "pool", h.userID, 1, 2)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("managed claim: %+v %v", jobs, err)
	}
	h.id = &auth.Identity{UserID: h.userID, Subject: "tg:1", TelegramID: 1,
		JobID: jobID, JobAttempt: jobs[0].Attempts, ConversationID: conv.ID}
	return h, m, jobID, jobs[0].Attempts
}

// T6. Mutation: switch the decoder to non-strict and read the identity fields.
func TestRecordCost_IgnoresBodyIdentity(t *testing.T) {
	h, _, jobID, _ := managedJobHarness(t)
	path := "/jobs/" + itoaTest(jobID) + "/cost"
	for _, field := range []string{"user_id", "runtime", "job_id"} {
		rec := h.do("POST", path, map[string]any{"cost_usd": 0.1, field: 7})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s in body: status %d, want 400", field, rec.Code)
		}
	}
	var n int
	if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM agent_usage WHERE status = 'settled'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("settled rows after refused bodies = %d %v", n, err)
	}
	rec := h.do("POST", path, map[string]any{"cost_usd": 0.1, "model": "gpt-x", "runner": "openai", "input_tokens": 10, "output_tokens": 4})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid body: %d %s", rec.Code, rec.Body.String())
	}
	var uid int64
	var rt, status string
	if err := h.store.DB.QueryRow(`SELECT user_id, runtime, status FROM agent_usage WHERE job_id = $1`, jobID).Scan(&uid, &rt, &status); err != nil {
		t.Fatal(err)
	}
	if uid != h.userID || rt != db.RuntimeManaged || status != db.UsageSettled {
		t.Fatalf("row = %d %s %s", uid, rt, status)
	}
	// A body attempt that differs from the token is refused by the binding.
	rec = h.do("POST", path, map[string]any{"cost_usd": 0.1, "attempt": 9})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("mismatched attempt: %d, want 403", rec.Code)
	}
}

// T7. Mutation: make the repeat overwrite or increment.
func TestRecordCost_IdempotentSame(t *testing.T) {
	h, m, jobID, _ := managedJobHarness(t)
	path := "/jobs/" + itoaTest(jobID) + "/cost"
	body := map[string]any{"cost_usd": 0.1, "model": "gpt-x", "runner": "openai", "input_tokens": 10, "output_tokens": 4}
	for i := 0; i < 2; i++ {
		if rec := h.do("POST", path, body); rec.Code != http.StatusOK {
			t.Fatalf("report %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	var n int
	if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM agent_usage WHERE job_id = $1`, jobID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows = %d %v", n, err)
	}
	if v := testutil.ToFloat64(m.AgentUsageCostUSDTotal.WithLabelValues("openai", "gpt-x")); v != 0.1 {
		t.Fatalf("cost metric = %v, want 0.1", v)
	}
	if v := testutil.ToFloat64(m.AgentUsageTokensTotal.WithLabelValues("input", "gpt-x")); v != 10 {
		t.Fatalf("input tokens metric = %v, want 10", v)
	}
	if v := testutil.ToFloat64(m.AgentUsageTokensTotal.WithLabelValues("output", "gpt-x")); v != 4 {
		t.Fatalf("output tokens metric = %v, want 4", v)
	}
}

// T8. Mutation: let the repeat overwrite.
func TestRecordCost_ConflictRefused(t *testing.T) {
	h, m, jobID, _ := managedJobHarness(t)
	path := "/jobs/" + itoaTest(jobID) + "/cost"
	base := map[string]any{"cost_usd": 0.1, "model": "gpt-x", "runner": "openai", "input_tokens": 10, "output_tokens": 4}
	if rec := h.do("POST", path, base); rec.Code != http.StatusOK {
		t.Fatalf("first: %d", rec.Code)
	}
	for field, val := range map[string]any{"cost_usd": 0.2, "model": "other", "input_tokens": 11} {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		body[field] = val
		rec := h.do("POST", path, body)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "usage_conflict") {
			t.Fatalf("%s differs: %d %s, want 409 usage_conflict", field, rec.Code, rec.Body.String())
		}
	}
	var cost float64
	var model string
	if err := h.store.DB.QueryRow(`SELECT cost_usd, model FROM agent_usage WHERE job_id = $1`, jobID).Scan(&cost, &model); err != nil || cost != 0.1 || model != "gpt-x" {
		t.Fatalf("row changed: %v %s %v", cost, model, err)
	}
	var refused int
	if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE tool_name = 'report_agent_job_cost' AND status = 'refused'`).Scan(&refused); err != nil || refused != 3 {
		t.Fatalf("refused audit rows = %d %v, want 3", refused, err)
	}
	if v := testutil.ToFloat64(m.AgentUsageCostUSDTotal.WithLabelValues("openai", "gpt-x")); v != 0.1 {
		t.Fatalf("cost metric = %v after conflicts, want 0.1", v)
	}
}

// T9 (handler half): an own-runtime job settles as own whatever the body says.
// Mutation: default the ledger runtime to managed.
func TestRecordCost_OwnJobRecordedAsOwn(t *testing.T) {
	h := newHarness(t)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:own-usage", conv.ID)
	claimed, err := h.store.ClaimAgentJobs(context.Background(), "r", h.userID, db.RuntimeOwn, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v", err)
	}
	rec := h.do("POST", "/jobs/"+itoaTest(jobID)+"/cost", map[string]any{
		"attempt": claimed[0].Attempts, "cost_usd": 0.3, "runner": "claude", "model": "m"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	var rt string
	if err := h.store.DB.QueryRow(`SELECT runtime FROM agent_usage WHERE job_id = $1`, jobID).Scan(&rt); err != nil || rt != db.RuntimeOwn {
		t.Fatalf("runtime = %q %v", rt, err)
	}
	// Invalid labels are refused.
	rec = h.do("POST", "/jobs/"+itoaTest(jobID)+"/cost", map[string]any{
		"attempt": claimed[0].Attempts, "cost_usd": 0.3, "runner": "bad runner!"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad runner: %d", rec.Code)
	}
}
