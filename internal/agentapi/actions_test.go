package agentapi

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
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
