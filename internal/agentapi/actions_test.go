package agentapi

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Durable deny codes at the agent API (#1271).

func (h *testHarness) auditCodes(tool string) (denied []string, ok int) {
	h.t.Helper()
	rows, err := h.store.DB.Query(
		`SELECT status, deny_code FROM audit_logs WHERE user_id = $1 AND tool_name = $2 ORDER BY id`,
		h.userID, tool)
	if err != nil {
		h.t.Fatalf("query audit: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var status string
		var code sql.NullString
		if err := rows.Scan(&status, &code); err != nil {
			h.t.Fatal(err)
		}
		switch status {
		case "ok":
			ok++
		case "denied":
			denied = append(denied, code.String)
		}
	}
	return denied, ok
}

func TestHandleProposeReply_DeniedPersistsCodeAndWritesNoOkAudit(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeGuarded)
	conv := h.seedConversation(555)

	rec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: conv.ID, Text: "Check out https://example.com for details",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var status string
	var code sql.NullString
	if err := h.store.DB.QueryRow(`SELECT status, deny_code FROM agent_actions WHERE user_id = $1`, h.userID).Scan(&status, &code); err != nil {
		t.Fatal(err)
	}
	if status != db.ActionDenied || code.String != string(policy.DenyReplyURL) {
		t.Fatalf("action = %q/%+v, want denied/%s", status, code, policy.DenyReplyURL)
	}
	// The denied action's own audit row (tool agent_action_denied) carries the
	// exact code; the call must not also report a successful propose_reply.
	if denied, _ := h.auditCodes(db.AuditToolActionDenied); len(denied) != 1 || denied[0] != string(policy.DenyReplyURL) {
		t.Fatalf("denial audit codes = %v", denied)
	}
	if denied, ok := h.auditCodes("propose_reply"); ok != 0 || len(denied) != 0 {
		t.Fatalf("propose_reply audit: ok=%d denied=%v, want none", ok, denied)
	}
	if res, err := h.store.VerifyAuditChain(context.Background(), h.userID); err != nil || !res.OK {
		t.Fatalf("chain: %+v err=%v", res, err)
	}
}

func TestHandleProposeReply_ReplayOfDeniedActionAddsNoSecondDenialAudit(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeGuarded)
	conv := h.seedConversation(555)
	req := proposeReplyRequest{ConversationID: conv.ID, Text: "Check out https://example.com for details"}
	for i := 0; i < 2; i++ {
		if rec := h.do("POST", "/actions/propose_reply", req); rec.Code != http.StatusOK {
			t.Fatalf("call %d status = %d", i, rec.Code)
		}
	}
	// Jobless proposals are not idempotent, so two calls are two actions and
	// two denial rows; each action has exactly one.
	var actions int
	if err := h.store.DB.QueryRow(`SELECT count(*) FROM agent_actions WHERE user_id = $1`, h.userID).Scan(&actions); err != nil {
		t.Fatal(err)
	}
	if denied, _ := h.auditCodes(db.AuditToolActionDenied); len(denied) != actions {
		t.Fatalf("%d denial audit rows for %d denied actions", len(denied), actions)
	}
}

func TestHandleProposeReply_AllowedStillWritesOkAudit(t *testing.T) {
	h := newHarness(t)
	if err := h.store.UpsertAgentProfile(context.Background(), db.AgentProfile{
		UserID: h.userID, Mode: db.AgentModeGuarded, DisclosureText: "I'm an AI assistant.", IntentAllowlist: "greet",
	}); err != nil {
		t.Fatal(err)
	}
	conv := h.seedConversation(555)
	if rec := h.do("POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: conv.ID, Intent: "greet", Text: "Hello there, thanks for reaching out.",
	}); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var code sql.NullString
	if err := h.store.DB.QueryRow(`SELECT deny_code FROM agent_actions WHERE user_id = $1`, h.userID).Scan(&code); err != nil || code.Valid {
		t.Fatalf("allowed action deny_code = %+v err=%v, want NULL", code, err)
	}
	if denied, ok := h.auditCodes("propose_reply"); ok != 1 || len(denied) != 0 {
		t.Fatalf("propose_reply audit: ok=%d denied=%v", ok, denied)
	}
	if denied, _ := h.auditCodes(db.AuditToolActionDenied); len(denied) != 0 {
		t.Fatalf("allowed action wrote a denial audit: %v", denied)
	}
}

func TestDenyJobBindingAudit_IsTypedCheckedAndHasConstantError(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeGuarded)
	rec := httptest.NewRecorder()
	h.srv.denyJobBinding(rec, context.Background(), h.userID, "propose_reply", "propose_reply", "job_id does not belong to conversation_id")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", rec.Code)
	}
	var status, errMsg string
	var code sql.NullString
	if err := h.store.DB.QueryRow(
		`SELECT status, error, deny_code FROM audit_logs WHERE user_id = $1 AND tool_name = 'propose_reply'`, h.userID,
	).Scan(&status, &errMsg, &code); err != nil {
		t.Fatal(err)
	}
	if status != "denied" || code.String != string(policy.DenyJobBindingMismatch) ||
		errMsg != auditErrBinding(policy.DenyJobBindingMismatch) {
		t.Fatalf("audit = %q/%q/%+v", status, errMsg, code)
	}
	// No action row is fabricated for an audit-only refusal.
	var n int
	if err := h.store.DB.QueryRow(`SELECT count(*) FROM agent_actions WHERE user_id = $1`, h.userID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("agent_actions rows = %d err=%v", n, err)
	}
}

// Owner-facing denial (kill switch) and its replay: the same-transaction
// agent_action_denied row is the only audit record. The response keeps its
// reasons, and no tool audit row (which would carry the reason prose) is
// written, on the first call or the replay.
func TestHandleOwnerFacing_DeniedReplayWritesOnlyTheTransitionAudit(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	conv := h.seedConversation(555)
	jobID := h.seedJob("evt:v1:1:555:notify-denied-audit", conv.ID)
	claimed, err := h.store.ClaimAgentJobs(context.Background(), "test-replica", h.userID, db.RuntimeOwn, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
	}
	req := ownerNotifyRequest{JobID: jobID, Attempt: claimed[0].Attempts, Text: "Daily digest"}
	h.srv.GlobalKill = true
	for i := 0; i < 2; i++ {
		rec := h.do("POST", "/notify/summary", req)
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d status = %d, body=%s", i, rec.Code, rec.Body.String())
		}
		var body struct {
			Decision string   `json:"decision"`
			Reasons  []string `json:"reasons"`
		}
		decodeBody(t, rec, &body)
		if body.Decision != db.PolicyDeny || len(body.Reasons) == 0 {
			t.Fatalf("call %d body = %+v, want deny with reasons", i, body)
		}
	}
	var persisted string
	if err := h.store.DB.QueryRow(`SELECT policy_reasons FROM agent_actions WHERE user_id = $1`, h.userID).Scan(&persisted); err != nil || persisted == "" {
		t.Fatalf("policy_reasons = %q err=%v", persisted, err)
	}
	rows, err := h.store.DB.Query(`SELECT tool_name, status, COALESCE(error, '') FROM audit_logs WHERE user_id = $1 ORDER BY id`, h.userID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var tool, status, errMsg string
		if err := rows.Scan(&tool, &status, &errMsg); err != nil {
			t.Fatal(err)
		}
		n++
		if tool != db.AuditToolActionDenied || status != "denied" || errMsg != "agent action denied" {
			t.Fatalf("audit row %d = %q/%q/%q, want only the transition row with constant text", n, tool, status, errMsg)
		}
	}
	if n != 1 {
		t.Fatalf("audit rows = %d, want exactly 1 (no replay duplicate)", n)
	}
	var notifs int
	if err := h.store.DB.QueryRow(`SELECT count(*) FROM owner_notifications WHERE user_id = $1`, h.userID).Scan(&notifs); err != nil || notifs != 0 {
		t.Fatalf("notifications = %d err=%v", notifs, err)
	}
}

func TestHandleOwnerFacing_DenialAuditFailureRollsBackAndIsServerError(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeObserve)
	h.srv.GlobalKill = true
	if _, err := h.store.DB.Exec(`CREATE TRIGGER owner_audit_fail BEFORE INSERT ON audit_logs
		BEGIN SELECT RAISE(ABORT, 'audit write refused'); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = h.store.DB.Exec(`DROP TRIGGER IF EXISTS owner_audit_fail`) })
	rec := h.do("POST", "/notify/summary", ownerNotifyRequest{Text: "Daily digest"})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
	}
	var actions, notifs int
	if err := h.store.DB.QueryRow(`SELECT count(*) FROM agent_actions WHERE user_id = $1`, h.userID).Scan(&actions); err != nil || actions != 0 {
		t.Fatalf("actions = %d err=%v, want rollback", actions, err)
	}
	if err := h.store.DB.QueryRow(`SELECT count(*) FROM owner_notifications WHERE user_id = $1`, h.userID).Scan(&notifs); err != nil || notifs != 0 {
		t.Fatalf("notifications = %d err=%v", notifs, err)
	}
}

func TestToolGate_UnknownToolSetAuditIsCheckedBeforeTheNormal503(t *testing.T) {
	t.Run("audit committed then 503", func(t *testing.T) {
		f := newGateFixture(t, "no-such-assistant")
		rec := f.saveLead(f.h.id, jobEnvelope{})
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503, body=%s", rec.Code, rec.Body.String())
		}
		if denied, _ := f.h.auditCodes("save_job_lead"); len(denied) != 1 || denied[0] != string(policy.DenyUnknown) {
			t.Fatalf("durable unknown-code audit = %v, want exactly one", denied)
		}
	})
	t.Run("audit failure is the sanitized 500, handler stopped", func(t *testing.T) {
		f := newGateFixture(t, "no-such-assistant")
		if _, err := f.h.store.DB.Exec(`CREATE TRIGGER gate_audit_fail BEFORE INSERT ON audit_logs
			BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END`); err != nil {
			t.Fatal(err)
		}
		rec := f.saveLead(f.h.id, jobEnvelope{})
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500, body=%s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "synthetic audit failure") || strings.Contains(rec.Body.String(), "audit_logs") {
			t.Fatalf("response leaks the storage error: %s", rec.Body.String())
		}
		for _, table := range []string{"audit_logs", "job_leads", "agent_actions"} {
			var n int
			if err := f.h.store.DB.QueryRow(`SELECT count(*) FROM `+table+` WHERE user_id = $1`, f.h.userID).Scan(&n); err != nil || n != 0 {
				t.Fatalf("%s rows = %d err=%v, want 0", table, n, err)
			}
		}
	})
}

func TestDenyBindingCode_AuditFailureIsNotReportedAsRecorded(t *testing.T) {
	h := newHarness(t)
	h.seedProfile(db.AgentModeGuarded)
	if _, err := h.store.DB.Exec(`CREATE TRIGGER binding_audit_fail BEFORE INSERT ON audit_logs
		BEGIN SELECT RAISE(ABORT, 'audit write refused'); END`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = h.store.DB.Exec(`DROP TRIGGER IF EXISTS binding_audit_fail`) })
	rec := httptest.NewRecorder()
	h.srv.denyJobBinding(rec, context.Background(), h.userID, "propose_reply", "propose_reply", "msg")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want the sanitized 500, not a normal refusal", rec.Code)
	}
}
