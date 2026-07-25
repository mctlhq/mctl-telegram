package db

import (
	"context"
	"database/sql"
	"errors"
	"sync"
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

// TestRecordAgentActionSent_AtomicWithTurnAndHistory covers a Codex finding
// on #307: before RecordAgentActionSent existed, the executor called
// SetAgentActionExecuted, IncrementAutonomousTurns, and
// InsertConversationMessage as three separate, independently-committing
// statements — a crash between the first and the other two left the action
// terminal (`executed`, so no recovery sweep ever revisits it) while
// under-counting the turn budget and rate-limit history for a send that
// genuinely happened. This test proves the all-or-nothing property directly:
// a lost CAS (row not in `executing`) must leave the conversation's turn
// counter and message history completely untouched, not partially updated.
func TestRecordAgentActionSent_AtomicWithTurnAndHistory(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	conv, err := s.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	id, err := s.InsertAgentAction(ctx, AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: ActionTypeReply,
		Payload: "Thanks!", PolicyDecision: PolicyRequireApproval, Status: ActionPendingApproval,
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Lost-CAS case: the row is still pending_approval, never reached
	// executing, so the CAS inside RecordAgentActionSent must fail — and
	// crucially, NEITHER the turn counter NOR conversation_messages may be
	// touched even though this call reaches the point where those writes
	// would otherwise happen.
	ok, err := s.RecordAgentActionSent(ctx, uid, id, conv.ID, 999, "should not be recorded")
	if err != nil {
		t.Fatalf("record sent (lost CAS): %v", err)
	}
	if ok {
		t.Fatal("RecordAgentActionSent succeeded on a row that was never executing")
	}
	gotConv, err := s.GetConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if gotConv.AutonomousTurns != 0 {
		t.Fatalf("autonomous_turns = %d after a lost CAS, want 0 (no partial write)", gotConv.AutonomousTurns)
	}
	msgs, err := s.ListConversationMessages(ctx, uid, conv.ID, 10)
	if err != nil {
		t.Fatalf("list conversation messages: %v", err)
	}
	if len(msgs) != 0 {
		t.Fatalf("conversation_messages = %d rows after a lost CAS, want 0 (no partial write)", len(msgs))
	}

	// Now the real transition: approved -> executing, then a successful
	// RecordAgentActionSent must flip the action AND increment the turn AND
	// insert the history row, all together.
	if ok, err := s.UpdateAgentActionStatus(ctx, uid, id, ActionPendingApproval, ActionApproved); err != nil || !ok {
		t.Fatalf("approve: ok=%v err=%v", ok, err)
	}
	if ok, err := s.BeginExecutingAgentAction(ctx, uid, id, 42); err != nil || !ok {
		t.Fatalf("begin executing: ok=%v err=%v", ok, err)
	}
	ok, err = s.RecordAgentActionSent(ctx, uid, id, conv.ID, 999, "Thanks! I'm an AI assistant.")
	if err != nil {
		t.Fatalf("record sent: %v", err)
	}
	if !ok {
		t.Fatal("RecordAgentActionSent failed on a row that was executing")
	}
	action, err := s.GetAgentAction(ctx, uid, id)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != ActionExecuted || action.ExecutedTGMessageID != 999 {
		t.Fatalf("action = %+v, want executed/999", action)
	}
	gotConv, err = s.GetConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if gotConv.AutonomousTurns != 1 {
		t.Fatalf("autonomous_turns = %d, want 1", gotConv.AutonomousTurns)
	}
	msgs, err = s.ListConversationMessages(ctx, uid, conv.ID, 10)
	if err != nil {
		t.Fatalf("list conversation messages: %v", err)
	}
	if len(msgs) != 1 || msgs[0].Direction != DirectionAgentOutgoing || msgs[0].TGMessageID != 999 {
		t.Fatalf("conversation messages = %+v, want one agent_outgoing row with tg_message_id=999", msgs)
	}

	// A second call (crash-recovery double call) must lose the CAS again and
	// must NOT double-increment the turn counter or insert a second row.
	ok, err = s.RecordAgentActionSent(ctx, uid, id, conv.ID, 999, "Thanks! I'm an AI assistant.")
	if err != nil {
		t.Fatalf("record sent (double call): %v", err)
	}
	if ok {
		t.Fatal("RecordAgentActionSent succeeded on an already-executed row")
	}
	gotConv, err = s.GetConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if gotConv.AutonomousTurns != 1 {
		t.Fatalf("autonomous_turns = %d after a double call, want still 1", gotConv.AutonomousTurns)
	}
	msgs, err = s.ListConversationMessages(ctx, uid, conv.ID, 10)
	if err != nil {
		t.Fatalf("list conversation messages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("conversation_messages = %d rows after a double call, want still 1", len(msgs))
	}
}

func TestReserveAgentActionSend_SerializesBudgetAndPersistsExactBody(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "reservation-owner")
	conv, err := s.EnsureConversation(ctx, uid, 777, "peer", "Peer")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	const finalBody = "Draft\n\nDisclosure snapshot"
	var ids []int64
	for i := 0; i < 2; i++ {
		id, err := s.InsertAgentAction(ctx, AgentAction{
			ConversationID: conv.ID,
			UserID:         uid,
			ActionType:     ActionTypeReply,
			Payload:        "Draft",
			PolicyDecision: PolicyAllow,
			Status:         ActionApproved,
		})
		if err != nil {
			t.Fatalf("insert action %d: %v", i, err)
		}
		ids = append(ids, id)
	}

	type result struct {
		id  int64
		ok  bool
		err error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id int64) {
			defer wg.Done()
			<-start
			action, err := s.GetAgentAction(ctx, uid, id)
			if err != nil {
				results <- result{id: id, err: err}
				return
			}
			ok, err := s.ReserveAgentActionSend(
				ctx, *action, int64(100+i), finalBody,
				1, 1, time.Now().UTC().Add(-time.Minute), true,
			)
			results <- result{id: id, ok: ok, err: err}
		}(i, id)
	}
	close(start)
	wg.Wait()
	close(results)

	var winner int64
	var budgetDenied int
	for r := range results {
		switch {
		case r.ok && r.err == nil:
			winner = r.id
		case errors.Is(r.err, ErrAgentSendBudgetExhausted):
			budgetDenied++
		default:
			t.Fatalf("unexpected reservation result for action %d: ok=%v err=%v", r.id, r.ok, r.err)
		}
	}
	if winner == 0 || budgetDenied != 1 {
		t.Fatalf("winner=%d budgetDenied=%d, want one of each", winner, budgetDenied)
	}
	got, err := s.GetAgentAction(ctx, uid, winner)
	if err != nil {
		t.Fatalf("get winning action: %v", err)
	}
	if got.Status != ActionExecuting || got.SendBody != finalBody || got.SendRandomID == 0 {
		t.Fatalf("winning action = %+v, want executing with persisted body/random id", got)
	}
	gotConv, err := s.GetConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if gotConv.AutonomousTurns != 1 {
		t.Fatalf("autonomous_turns=%d, want one durable reservation", gotConv.AutonomousTurns)
	}
	recent, err := s.ListRecentAgentOutgoingTimestamps(ctx, uid, conv.ID, time.Now().UTC().Add(-time.Minute))
	if err != nil {
		t.Fatalf("list recent reservations: %v", err)
	}
	if len(recent) != 1 {
		t.Fatalf("recent reservations=%d, want 1", len(recent))
	}

	// A recovery-time deny is ambiguous: the original RPC may have landed.
	// Keep both turn and per-minute accounting fail-closed.
	if ok, err := s.UpdateAgentActionStatus(ctx, uid, winner, ActionExecuting, ActionDenied); err != nil || !ok {
		t.Fatalf("deny reserved action: ok=%v err=%v", ok, err)
	}
	recent, err = s.ListRecentAgentOutgoingTimestamps(ctx, uid, conv.ID, time.Now().UTC().Add(-time.Minute))
	if err != nil {
		t.Fatalf("list denied reservation: %v", err)
	}
	if len(recent) != 1 {
		t.Fatalf("denied reservation disappeared from rate accounting: %d", len(recent))
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

func TestUpsertJobLead_FencesActiveJobAttempt(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	conv, err := s.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	jobID := seedJob(t, s, uid, "evt:v1:1:555:lead-fence")
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_jobs SET conversation_id=$1 WHERE id=$2`, conv.ID, jobID,
	); err != nil {
		t.Fatalf("bind job conversation: %v", err)
	}
	first, err := s.ClaimAgentJobs(ctx, "worker-1", uid, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("first claim: jobs=%+v err=%v", first, err)
	}
	if _, err := s.UpsertJobLead(ctx, JobLead{
		UserID: uid, ConversationID: conv.ID, JobID: jobID, Attempt: first[0].Attempts,
		Company: "Original",
	}); err != nil {
		t.Fatalf("first save: %v", err)
	}

	if _, err := s.RetryAgentJob(ctx, jobID, first[0].Attempts, "worker lost"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_jobs SET next_run_at=$1 WHERE id=$2`, time.Now().UTC(), jobID,
	); err != nil {
		t.Fatalf("unbackoff: %v", err)
	}
	second, err := s.ClaimAgentJobs(ctx, "worker-2", uid, 1)
	if err != nil || len(second) != 1 {
		t.Fatalf("second claim: jobs=%+v err=%v", second, err)
	}

	if _, err := s.UpsertJobLead(ctx, JobLead{
		UserID: uid, ConversationID: conv.ID, JobID: jobID, Attempt: first[0].Attempts,
		Company: "Stale overwrite",
	}); err != ErrAgentJobNotFound {
		t.Fatalf("stale save err=%v, want ErrAgentJobNotFound", err)
	}
	got, err := s.GetJobLeadByConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get after stale save: %v", err)
	}
	if got.Company != "Original" {
		t.Fatalf("stale attempt changed company to %q", got.Company)
	}

	if _, err := s.UpsertJobLead(ctx, JobLead{
		UserID: uid, ConversationID: conv.ID, JobID: jobID, Attempt: second[0].Attempts,
		Company: "Fresh",
	}); err != nil {
		t.Fatalf("fresh save: %v", err)
	}
	got, _ = s.GetJobLeadByConversation(ctx, uid, conv.ID)
	if got.Company != "Fresh" {
		t.Fatalf("fresh attempt left company at %q", got.Company)
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

// TestListPendingOwnerNotifications_ExcludesLeasedRows covers a Codex
// finding on #307: a currently-claimed row (e.g. one another replica or the
// same sweep tick's own failed-but-still-leased attempt is holding) used to
// still occupy a slot in the oldest-N batch, so a run of permanently-failing
// notifications could crowd out a healthy account's newer, deliverable one
// for as long as their claims kept getting re-issued. The leased row must
// not be returned while its lease is active, and must reappear once it
// expires.
func TestListPendingOwnerNotifications_ExcludesLeasedRows(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	leasedID, err := s.InsertOwnerNotification(ctx, OwnerNotification{
		UserID: uid, Kind: NotificationSummary, Body: "stuck",
	})
	if err != nil {
		t.Fatalf("insert leased: %v", err)
	}
	healthyID, err := s.InsertOwnerNotification(ctx, OwnerNotification{
		UserID: uid, Kind: NotificationSummary, Body: "healthy",
	})
	if err != nil {
		t.Fatalf("insert healthy: %v", err)
	}

	_, claimed, err := s.ClaimOwnerNotification(ctx, uid, leasedID, 12345, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("claim leased row: claimed=%v err=%v", claimed, err)
	}

	pending, err := s.ListPendingOwnerNotifications(ctx, 50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pending) != 1 || pending[0].ID != healthyID {
		t.Fatalf("pending = %+v, want only the healthy row (id=%d) while the other is leased", pending, healthyID)
	}

	// Force the lease to have expired and confirm the row becomes visible
	// again — this is not a permanent exclusion, only a temporary one.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE owner_notifications SET claimed_until = $1 WHERE id = $2`,
		time.Now().Add(-time.Minute).UTC(), leasedID,
	); err != nil {
		t.Fatalf("force-expire lease: %v", err)
	}
	pending, err = s.ListPendingOwnerNotifications(ctx, 50)
	if err != nil {
		t.Fatalf("list after expiry: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("pending after expiry = %d rows, want 2", len(pending))
	}
}

// TestClaimOwnerNotification_ReusesPersistedRandomIDOnRetry covers a Codex
// finding on #307: the claim lease alone only protects against two
// REPLICAS racing the same row concurrently — it does nothing for a single
// replica that crashes AFTER SendToSelf reaches Telegram but BEFORE
// MarkOwnerNotificationSent commits. Without a persisted random_id, the
// retry (once the lease expires) would call SendToSelf again with a FRESH
// random_id, and Telegram has no way to dedup that against the first,
// genuinely-delivered send. The second claim (after the first lease
// expires without ever completing) must return the SAME random_id as the
// first, not the new candidate it was offered.
func TestClaimOwnerNotification_ReusesPersistedRandomIDOnRetry(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	notifID, err := s.InsertOwnerNotification(ctx, OwnerNotification{
		UserID: uid, Kind: NotificationSummary, Body: "hello",
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	firstRandomID, claimed, err := s.ClaimOwnerNotification(ctx, uid, notifID, 111, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("first claim: claimed=%v err=%v", claimed, err)
	}
	if firstRandomID != 111 {
		t.Fatalf("first claim random id = %d, want the candidate 111 (nothing persisted yet)", firstRandomID)
	}

	// Simulate a crash: the lease expires without SendToSelf's outcome ever
	// being recorded (no MarkOwnerNotificationSent/Failed call).
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE owner_notifications SET claimed_until = $1 WHERE id = $2`,
		time.Now().Add(-time.Minute).UTC(), notifID,
	); err != nil {
		t.Fatalf("force-expire lease: %v", err)
	}

	secondRandomID, claimed, err := s.ClaimOwnerNotification(ctx, uid, notifID, 222, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("second claim: claimed=%v err=%v", claimed, err)
	}
	if secondRandomID != firstRandomID {
		t.Fatalf("second claim random id = %d, want the original %d reused (not the new candidate 222)", secondRandomID, firstRandomID)
	}

	var stored sql.NullInt64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT random_id FROM owner_notifications WHERE id = $1`, notifID,
	).Scan(&stored); err != nil {
		t.Fatalf("select stored random_id: %v", err)
	}
	if !stored.Valid || stored.Int64 != firstRandomID {
		t.Fatalf("stored random_id = %+v, want %d", stored, firstRandomID)
	}
}

func TestHasAgentActionForJob(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	jobID := seedJob(t, s, uid, "evt:v1:1:1:has-action")
	claimed, err := s.ClaimAgentJobs(ctx, "r", uid, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
	}

	has, err := s.HasAgentActionForJob(ctx, uid, jobID)
	if err != nil {
		t.Fatalf("has (before insert): %v", err)
	}
	if has {
		t.Fatalf("has = true before any action exists, want false")
	}

	if _, err := s.InsertAgentAction(ctx, AgentAction{
		JobID: jobID, Attempt: claimed[0].Attempts, UserID: uid, ActionType: ActionTypeReply,
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
