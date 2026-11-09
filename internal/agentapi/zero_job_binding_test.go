package agentapi

import (
	"context"
	"net/http"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Regressions for #1266 (revision 0 is never a valid policy input; a jobless
// caller is judged under the server-verified current revision) and #1267 (a
// job credential cannot omit its job, and a named job never falls back to the
// jobless path). Fixtures use the synthetic personas of this package only.

type zeroFixture struct {
	h       *testHarness
	conv    *db.Conversation
	jobID   int64
	attempt int
	jobCred *auth.Identity
}

func newZeroFixture(t *testing.T, mode string) *zeroFixture {
	t.Helper()
	h := newHarness(t)
	h.seedProfile(mode)
	conv := h.seedConversation(920101)
	jobID := h.seedJob("evt:v1:zero:a", conv.ID)
	jobs, err := h.store.ClaimAgentJobs(context.Background(), "zero", h.userID, db.RuntimeOwn, 1)
	if err != nil || len(jobs) != 1 || jobs[0].ID != jobID {
		t.Fatalf("claim: %+v %v", jobs, err)
	}
	return &zeroFixture{
		h: h, conv: conv, jobID: jobID, attempt: jobs[0].Attempts,
		jobCred: &auth.Identity{
			UserID: h.userID, Subject: "tg:1", TelegramID: 1,
			JobID: jobID, JobAttempt: jobs[0].Attempts, ConversationID: conv.ID,
		},
	}
}

func (f *zeroFixture) count(query string, args ...any) int {
	f.h.t.Helper()
	var n int
	if err := f.h.store.DB.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		f.h.t.Fatalf("count %q: %v", query, err)
	}
	return n
}

// noEffects asserts that nothing was persisted that could execute or notify.
func (f *zeroFixture) noEffects() {
	f.h.t.Helper()
	if n := f.count(`SELECT COUNT(*) FROM agent_actions`); n != 0 {
		f.h.t.Errorf("agent_actions rows = %d, want 0", n)
	}
	if n := f.count(`SELECT COUNT(*) FROM owner_notifications`); n != 0 {
		f.h.t.Errorf("owner_notifications rows = %d, want 0", n)
	}
}

func (f *zeroFixture) typedAudits(tool string, code policy.DenyCode) int {
	f.h.t.Helper()
	return f.count(`SELECT COUNT(*) FROM audit_logs WHERE tool_name = $1 AND status = 'denied' AND error LIKE $2`,
		tool, "conversation binding: "+string(code)+":%")
}

func TestZeroJobBinding_JobCredentialOmittingJobIsDeniedBeforeEffects(t *testing.T) {
	cases := []struct {
		tool, path string
		body       map[string]any
	}{
		{"propose_reply", "/actions/propose_reply", map[string]any{"intent": "greet", "text": "Hello there"}},
		{"send_owner_summary", "/notify/summary", map[string]any{"intent": "lead", "text": "summary"}},
		{"request_owner_approval", "/actions/request_owner_approval", map[string]any{"intent": "lead", "text": "approve?"}},
	}
	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			f := newZeroFixture(t, db.AgentModeGuarded)
			rec := f.h.doAs(f.jobCred, "POST", c.path, c.body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			f.noEffects()
			if n := f.typedAudits(c.tool, policy.DenyJobBindingMissing); n != 1 {
				t.Fatalf("typed job_binding_missing denied audits = %d, want 1", n)
			}
		})
	}
	t.Run("attempt omitted", func(t *testing.T) {
		f := newZeroFixture(t, db.AgentModeGuarded)
		rec := f.h.doAs(f.jobCred, "POST", "/notify/summary", map[string]any{"job_id": f.jobID, "intent": "lead", "text": "summary"})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		f.noEffects()
		if n := f.typedAudits("send_owner_summary", policy.DenyJobBindingMissing); n != 1 {
			t.Fatalf("typed denied audits = %d, want 1", n)
		}
	})
}

func TestZeroJobBinding_MismatchedJobIsTypedAndDeniedBeforeEffects(t *testing.T) {
	f := newZeroFixture(t, db.AgentModeGuarded)
	rec := f.h.doAs(f.jobCred, "POST", "/notify/summary", map[string]any{
		"job_id": f.jobID + 1000, "attempt": f.attempt, "intent": "lead", "text": "summary",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	f.noEffects()
	if n := f.typedAudits("send_owner_summary", policy.DenyJobBindingMismatch); n != 1 {
		t.Fatalf("typed job_binding_mismatch denied audits = %d, want 1", n)
	}
}

func TestZeroJobBinding_NamedNonexistentJobNeverFallsBackToJobless(t *testing.T) {
	for _, tc := range []struct{ tool, path string }{
		{"send_owner_summary", "/notify/summary"},
		{"request_owner_approval", "/actions/request_owner_approval"},
		{"propose_reply", "/actions/propose_reply"},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			f := newZeroFixture(t, db.AgentModeGuarded)
			body := map[string]any{"job_id": f.jobID + 1000, "attempt": 1, "intent": "lead", "text": "summary", "conversation_id": f.conv.ID}
			rec := f.h.do("POST", tc.path, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			f.noEffects()
			if n := f.typedAudits(tc.tool, policy.DenyJobBindingMismatch); n != 1 {
				t.Fatalf("typed job_binding_mismatch denied audits = %d, want 1", n)
			}
		})
	}
}

func TestZeroJobBinding_OwnerJobConversationMismatchDenied(t *testing.T) {
	f := newZeroFixture(t, db.AgentModeGuarded)
	other := f.h.seedConversation(920102)
	rec := f.h.do("POST", "/notify/summary", map[string]any{
		"job_id": f.jobID, "attempt": f.attempt, "conversation_id": other.ID, "intent": "lead", "text": "summary",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	f.noEffects()
}

func TestZeroJobBinding_AccountTokenJoblessUsesServerCurrentRevision(t *testing.T) {
	f := newZeroFixture(t, db.AgentModeObserve)
	// Standalone proposal: observe mode parks it for approval under the
	// profile's current revision, which the server read, not the request.
	rec := f.h.do("POST", "/actions/propose_reply", map[string]any{
		"conversation_id": f.conv.ID, "intent": "greet", "text": "Hello there",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("propose status = %d, body %s", rec.Code, rec.Body.String())
	}
	if n := f.count(`SELECT COUNT(*) FROM agent_actions WHERE job_id IS NULL AND status = $1 AND install_revision = (SELECT install_revision FROM agent_profiles WHERE user_id = $2)`,
		db.ActionPendingApproval, f.h.userID); n != 1 {
		t.Fatalf("standalone pending actions under the current revision = %d, want 1", n)
	}
	if n := f.count(`SELECT COUNT(*) FROM owner_notifications`); n != 1 {
		t.Fatalf("approval notifications = %d, want 1", n)
	}
	// Owner summary without a job or conversation still executes.
	rec = f.h.do("POST", "/notify/summary", map[string]any{"intent": "lead", "text": "daily summary"})
	if rec.Code != http.StatusOK {
		t.Fatalf("summary status = %d, body %s", rec.Code, rec.Body.String())
	}
	if n := f.count(`SELECT COUNT(*) FROM agent_actions WHERE action_type = $1 AND status = $2`, db.ActionTypeOwnerSummary, db.ActionExecuted); n != 1 {
		t.Fatalf("executed summaries = %d, want 1", n)
	}
}

func TestZeroJobBinding_ProfileRevisionZeroDeniesJoblessCallers(t *testing.T) {
	f := newZeroFixture(t, db.AgentModeObserve)
	if _, err := f.h.store.DB.ExecContext(context.Background(), `UPDATE agent_profiles SET install_revision = 0 WHERE user_id = $1`, f.h.userID); err != nil {
		t.Fatalf("zero profile revision: %v", err)
	}
	rec := f.h.do("POST", "/notify/summary", map[string]any{"intent": "lead", "text": "daily summary"})
	if rec.Code != http.StatusOK {
		t.Fatalf("summary status = %d, body %s", rec.Code, rec.Body.String())
	}
	if n := f.count(`SELECT COUNT(*) FROM agent_actions WHERE status = $1 AND policy_decision = $2`, db.ActionDenied, string(policy.Deny)); n != 1 {
		t.Fatalf("denied summary actions = %d, want 1", n)
	}
	if n := f.count(`SELECT COUNT(*) FROM owner_notifications`); n != 0 {
		t.Fatalf("notifications = %d, want 0", n)
	}
	rec = f.h.do("POST", "/actions/propose_reply", map[string]any{
		"conversation_id": f.conv.ID, "intent": "greet", "text": "Hello there",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("propose status = %d, body %s", rec.Code, rec.Body.String())
	}
	if n := f.count(`SELECT COUNT(*) FROM agent_actions WHERE status = $1`, db.ActionPendingApproval); n != 0 {
		t.Fatalf("pending actions = %d, want 0", n)
	}
	if n := f.count(`SELECT COUNT(*) FROM owner_notifications`); n != 0 {
		t.Fatalf("notifications = %d, want 0", n)
	}
}

func TestZeroJobBinding_ValidBoundPathWorksAndStaleIsDenied(t *testing.T) {
	f := newZeroFixture(t, db.AgentModeGuarded)
	body := map[string]any{"job_id": f.jobID, "attempt": f.attempt, "intent": "lead", "text": "summary"}
	rec := f.h.doAs(f.jobCred, "POST", "/notify/summary", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("bound summary status = %d, body %s", rec.Code, rec.Body.String())
	}
	if n := f.count(`SELECT COUNT(*) FROM agent_actions WHERE job_id = $1 AND status = $2`, f.jobID, db.ActionExecuted); n != 1 {
		t.Fatalf("executed bound summaries = %d, want 1", n)
	}
}

// A nonzero stale revision keeps its existing install_changed denial.
func TestZeroJobBinding_StaleNonzeroRevisionStaysInstallChanged(t *testing.T) {
	f := newZeroFixture(t, db.AgentModeGuarded)
	if err := f.h.store.UpdateAgentProfileFields(context.Background(), f.h.userID, db.AgentProfileUpdate{BumpInstallRevision: true}); err != nil {
		t.Fatalf("bump: %v", err)
	}
	rec := f.h.doAs(f.jobCred, "POST", "/notify/summary", map[string]any{"job_id": f.jobID, "attempt": f.attempt, "intent": "lead", "text": "summary"})
	if rec.Code != http.StatusOK {
		t.Fatalf("stale summary status = %d, body %s", rec.Code, rec.Body.String())
	}
	if n := f.count(`SELECT COUNT(*) FROM agent_actions WHERE job_id = $1 AND status = $2 AND policy_reasons = $3`,
		f.jobID, db.ActionDenied, policy.ReasonInstallChanged); n != 1 {
		t.Fatalf("denied stale actions = %d, want 1", n)
	}
	if n := f.count(`SELECT COUNT(*) FROM owner_notifications`); n != 0 {
		t.Fatalf("notifications = %d, want 0", n)
	}
}
