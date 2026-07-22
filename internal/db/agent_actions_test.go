package db

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func TestAgentAction_LifecycleCAS(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	conv, err := s.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}

	const proposed = "Здравствуйте! Я AI-помощник. Подскажите, пожалуйста, компанию и роль?"
	id, err := s.InsertAgentAction(ctx, AgentAction{
		ApprovalCode:   "a1b2",
		ConversationID: conv.ID,
		UserID:         uid,
		ActionType:     ActionTypeReply,
		Intent:         "request_company",
		Payload:        proposed,
		PolicyDecision: PolicyRequireApproval,
		Status:         ActionPendingApproval,
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Payload must round-trip decrypted and never sit in plaintext.
	var blob []byte
	if err := s.DB.QueryRowContext(ctx,
		`SELECT payload_encrypted FROM agent_actions WHERE id = $1`, id,
	).Scan(&blob); err != nil {
		t.Fatalf("select blob: %v", err)
	}
	if string(blob) == proposed {
		t.Fatal("payload stored in plaintext")
	}
	got, err := s.GetAgentActionByCode(ctx, uid, "a1b2")
	if err != nil {
		t.Fatalf("get by code: %v", err)
	}
	if got.ID != id || got.Payload != proposed {
		t.Fatalf("get by code = %+v", got)
	}

	// CAS transition: pending_approval → approved succeeds once.
	ok, err := s.UpdateAgentActionStatus(ctx, uid, id, ActionPendingApproval, ActionApproved)
	if err != nil || !ok {
		t.Fatalf("approve: ok=%v err=%v", ok, err)
	}
	// A second decision on the same action must lose the race.
	ok, err = s.UpdateAgentActionStatus(ctx, uid, id, ActionPendingApproval, ActionRejected)
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if ok {
		t.Fatal("double decision succeeded; CAS must reject")
	}

	// approved → executing → executed with the sent message id.
	if ok, _ = s.UpdateAgentActionStatus(ctx, uid, id, ActionApproved, ActionExecuting); !ok {
		t.Fatal("executing transition failed")
	}
	if ok, err = s.SetAgentActionExecuted(ctx, uid, id, 777); err != nil || !ok {
		t.Fatalf("executed: ok=%v err=%v", ok, err)
	}
	got, _ = s.GetAgentAction(ctx, uid, id)
	if got.Status != ActionExecuted || got.ExecutedTGMessageID != 777 {
		t.Fatalf("final action = %+v", got)
	}
	// SetAgentActionExecuted must be a no-op when not executing (crash replay).
	if ok, _ = s.SetAgentActionExecuted(ctx, uid, id, 888); ok {
		t.Fatal("double executed succeeded")
	}

	// Cross-user scoping.
	other := seedAgentUser(t, s, "other")
	if _, err := s.GetAgentAction(ctx, other, id); err != ErrAgentActionNotFound {
		t.Fatalf("cross-user get err = %v, want ErrAgentActionNotFound", err)
	}

	// Reaching a terminal state releases the approval code so it can be reused.
	var code sql.NullString
	if err := s.DB.QueryRowContext(ctx,
		`SELECT approval_code FROM agent_actions WHERE id = $1`, id,
	).Scan(&code); err != nil {
		t.Fatalf("select code: %v", err)
	}
	if code.Valid {
		t.Fatalf("approval code not released after executed: %q", code.String)
	}
	if _, err := s.InsertAgentAction(ctx, AgentAction{
		ApprovalCode: "a1b2", UserID: uid, ActionType: ActionTypeReply,
		PolicyDecision: PolicyRequireApproval, Status: ActionPendingApproval,
	}); err != nil {
		t.Fatalf("reuse released code: %v", err)
	}
}

func TestUpdateAgentActionStatus_RejectsIllegalTransition(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	id, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, ActionType: ActionTypeReply,
		PolicyDecision: PolicyRequireApproval, Status: ActionPendingApproval,
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	// pending_approval -> executed skips approval + execution: illegal.
	if _, err := s.UpdateAgentActionStatus(ctx, uid, id, ActionPendingApproval, ActionExecuted); err == nil {
		t.Fatal("illegal transition accepted")
	}
	// A transition out of a terminal state is illegal (terminal not in the map).
	if _, err := s.UpdateAgentActionStatus(ctx, uid, id, ActionExecuted, ActionApproved); err == nil {
		t.Fatal("transition out of terminal state accepted")
	}
	// The legitimate step still works.
	if ok, err := s.UpdateAgentActionStatus(ctx, uid, id, ActionPendingApproval, ActionApproved); err != nil || !ok {
		t.Fatalf("legal transition: ok=%v err=%v", ok, err)
	}
}

func TestInsertAgentAction_RejectsForeignConversation(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	owner := seedAgentUser(t, s, "owner")
	other := seedAgentUser(t, s, "other")
	conv, err := s.EnsureConversation(ctx, owner, 555, "anna", "Anna")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: other, ConversationID: conv.ID, ActionType: ActionTypeReply,
		PolicyDecision: PolicyRequireApproval,
	}); err != ErrConversationNotFound {
		t.Fatalf("foreign conversation err = %v, want ErrConversationNotFound", err)
	}
}

func TestInsertOwnerNotification_RejectsForeignAction(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	owner := seedAgentUser(t, s, "owner")
	other := seedAgentUser(t, s, "other")
	actionID, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: owner, ActionType: ActionTypeReply, PolicyDecision: PolicyRequireApproval,
	})
	if err != nil {
		t.Fatalf("insert action: %v", err)
	}
	if _, err := s.InsertOwnerNotification(ctx, OwnerNotification{
		UserID: other, Kind: NotificationApproval, ActionID: actionID,
	}); err != ErrAgentActionNotFound {
		t.Fatalf("foreign action err = %v, want ErrAgentActionNotFound", err)
	}
}

func TestExpireStaleAgentActions(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	stale, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, ActionType: ActionTypeReply,
		PolicyDecision: PolicyRequireApproval, Status: ActionPendingApproval,
	})
	if err != nil {
		t.Fatalf("insert stale: %v", err)
	}
	// Expiry is measured from updated_at (approval-request time), so backdate
	// that, not created_at.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_actions SET updated_at = $1 WHERE id = $2`,
		time.Now().UTC().Add(-48*time.Hour), stale,
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	fresh, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, ActionType: ActionTypeReply,
		PolicyDecision: PolicyRequireApproval, Status: ActionPendingApproval,
	})
	if err != nil {
		t.Fatalf("insert fresh: %v", err)
	}

	n, err := s.ExpireStaleAgentActions(ctx, 24*time.Hour)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired %d rows, want 1", n)
	}
	got, _ := s.GetAgentAction(ctx, uid, stale)
	if got.Status != ActionExpired {
		t.Fatalf("stale status = %q, want expired", got.Status)
	}
	got, _ = s.GetAgentAction(ctx, uid, fresh)
	if got.Status != ActionPendingApproval {
		t.Fatalf("fresh status = %q, want pending_approval", got.Status)
	}
}

func TestUpsertJobLead_PartialMerge(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	conv, err := s.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}

	id1, err := s.UpsertJobLead(ctx, JobLead{
		UserID: uid, ConversationID: conv.ID, Role: "Senior Python Engineer",
	})
	if err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	// Second partial save fills company but omits role — role must survive.
	id2, err := s.UpsertJobLead(ctx, JobLead{
		UserID: uid, ConversationID: conv.ID, Company: "Acme",
		Detail: `{"stack":["python","django"]}`,
	})
	if err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	if id2 != id1 {
		t.Fatalf("upsert created new row: %d != %d", id2, id1)
	}
	got, err := s.GetJobLeadByConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Role != "Senior Python Engineer" || got.Company != "Acme" {
		t.Fatalf("merged lead = %+v", got)
	}
	if got.Detail != `{"stack":["python","django"]}` {
		t.Fatalf("detail = %q", got.Detail)
	}

	leads, err := s.ListJobLeads(ctx, uid, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(leads) != 1 || leads[0].ID != id1 {
		t.Fatalf("list = %+v", leads)
	}
	if _, err := s.GetJobLead(ctx, uid+999, id1); err != ErrJobLeadNotFound {
		t.Fatalf("cross-user get err = %v, want ErrJobLeadNotFound", err)
	}
}

func TestUpsertJobLead_StatusPreservedOnMetadataOnlySave(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	conv, err := s.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}

	// Empty status on first insert defaults to "new".
	if _, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: conv.ID}); err != nil {
		t.Fatalf("upsert 1: %v", err)
	}
	got, _ := s.GetJobLeadByConversation(ctx, uid, conv.ID)
	if got.Status != "new" {
		t.Fatalf("initial status = %q, want new", got.Status)
	}

	// Progress the lead, then perform a metadata-only save (empty status).
	if _, err := s.UpsertJobLead(ctx, JobLead{
		UserID: uid, ConversationID: conv.ID, Status: "contacted",
	}); err != nil {
		t.Fatalf("upsert 2: %v", err)
	}
	if _, err := s.UpsertJobLead(ctx, JobLead{
		UserID: uid, ConversationID: conv.ID, Company: "Acme",
	}); err != nil {
		t.Fatalf("upsert 3: %v", err)
	}
	got, _ = s.GetJobLeadByConversation(ctx, uid, conv.ID)
	if got.Status != "contacted" {
		t.Fatalf("status reset to %q by metadata-only save, want contacted", got.Status)
	}
	if got.Company != "Acme" {
		t.Fatalf("company = %q", got.Company)
	}
}

func TestUpsertJobLead_RejectsForeignConversation(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	owner := seedAgentUser(t, s, "owner")
	other := seedAgentUser(t, s, "other")
	conv, err := s.EnsureConversation(ctx, owner, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	if _, err := s.UpsertJobLead(ctx, JobLead{
		UserID: owner, ConversationID: conv.ID, Role: "Senior Python Engineer",
	}); err != nil {
		t.Fatalf("owner upsert: %v", err)
	}

	// A different user passing the owner's conversation id must be rejected
	// and must not corrupt the owner's lead.
	if _, err := s.UpsertJobLead(ctx, JobLead{
		UserID: other, ConversationID: conv.ID, Role: "Junior PHP Developer",
	}); err != ErrConversationNotFound {
		t.Fatalf("foreign upsert err = %v, want ErrConversationNotFound", err)
	}
	got, err := s.GetJobLeadByConversation(ctx, owner, conv.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Role != "Senior Python Engineer" {
		t.Fatalf("owner lead corrupted: role = %q", got.Role)
	}
}

func TestOwnerNotifications_Lifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	const body = "Новая вакансия: Acme / Senior Backend Engineer"
	id, err := s.InsertOwnerNotification(ctx, OwnerNotification{
		UserID: uid, Kind: NotificationSummary, Body: body,
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	var blob []byte
	var status string
	if err := s.DB.QueryRowContext(ctx,
		`SELECT body_encrypted, status FROM owner_notifications WHERE id = $1`, id,
	).Scan(&blob, &status); err != nil {
		t.Fatalf("select: %v", err)
	}
	if string(blob) == body {
		t.Fatal("notification body stored in plaintext")
	}
	if status != NotificationPending {
		t.Fatalf("status = %q, want pending", status)
	}

	if err := s.MarkOwnerNotificationSent(ctx, uid, id, 901); err != nil {
		t.Fatalf("mark sent: %v", err)
	}
	var tgID int64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT tg_message_id FROM owner_notifications WHERE id = $1 AND status = $2`,
		id, NotificationSent,
	).Scan(&tgID); err != nil {
		t.Fatalf("select sent: %v", err)
	}
	if tgID != 901 {
		t.Fatalf("tg_message_id = %d, want 901", tgID)
	}

	id2, err := s.InsertOwnerNotification(ctx, OwnerNotification{
		UserID: uid, Kind: NotificationApproval, Body: "draft",
	})
	if err != nil {
		t.Fatalf("insert 2: %v", err)
	}
	if err := s.MarkOwnerNotificationFailed(ctx, uid, id2); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	if err := s.DB.QueryRowContext(ctx,
		`SELECT id FROM owner_notifications WHERE id = $1 AND status = $2`,
		id2, NotificationFailed,
	).Scan(new(int64)); err != nil {
		t.Fatalf("failed row not found: %v", err)
	}

	// Wrong id / wrong user must surface, not silently no-op.
	if err := s.MarkOwnerNotificationSent(ctx, uid, id2+999, 1); err != ErrOwnerNotificationNotFound {
		t.Fatalf("mark sent missing err = %v, want ErrOwnerNotificationNotFound", err)
	}
	if err := s.MarkOwnerNotificationFailed(ctx, uid+999, id2); err != ErrOwnerNotificationNotFound {
		t.Fatalf("mark failed cross-user err = %v, want ErrOwnerNotificationNotFound", err)
	}

	// A sent notification must never be flipped to failed by a racing/late
	// failure report — the CAS guard rejects the transition.
	if err := s.MarkOwnerNotificationFailed(ctx, uid, id); err != ErrOwnerNotificationNotFound {
		t.Fatalf("failed-after-sent err = %v, want ErrOwnerNotificationNotFound", err)
	}
	if err := s.DB.QueryRowContext(ctx,
		`SELECT id FROM owner_notifications WHERE id = $1 AND status = $2`, id, NotificationSent,
	).Scan(new(int64)); err != nil {
		t.Fatalf("sent notification was overwritten: %v", err)
	}
}

func TestHasAgentActionForJob(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	jobID := seedJob(t, s, uid, "evt:v1:1:1:has-action")

	has, err := s.HasAgentActionForJob(ctx, uid, jobID)
	if err != nil {
		t.Fatalf("has (before insert): %v", err)
	}
	if has {
		t.Fatalf("has = true before any action exists, want false")
	}

	if _, err := s.InsertAgentAction(ctx, AgentAction{
		JobID: jobID, UserID: uid, ActionType: ActionTypeReply,
		PolicyDecision: PolicyAllow, Status: ActionApproved,
	}); err != nil {
		t.Fatalf("insert action: %v", err)
	}

	has, err = s.HasAgentActionForJob(ctx, uid, jobID)
	if err != nil {
		t.Fatalf("has (after insert): %v", err)
	}
	if !has {
		t.Fatalf("has = false after inserting an action, want true")
	}

	// Scoped to the owning user: a different user must not see it.
	otherUID := seedAgentUser(t, s, "other")
	has, err = s.HasAgentActionForJob(ctx, otherUID, jobID)
	if err != nil {
		t.Fatalf("has (other user): %v", err)
	}
	if has {
		t.Fatalf("has = true for a different user's job, want false")
	}
}
