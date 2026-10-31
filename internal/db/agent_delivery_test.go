package db

import (
	"context"
	"testing"
	"time"
)

// bobTGID is the synthetic peer persona (Bob) used by these tests.
const bobTGID = 500100202

// executingSend seeds an approved reply to Bob and reserves its send with
// body, leaving it executing the way a send with a lost answer leaves it.
func executingSend(t *testing.T, s *Store, uid int64, randomID int64, body string) (actionID int64, conv *Conversation) {
	t.Helper()
	ctx := context.Background()
	conv, err := s.EnsureConversation(ctx, uid, bobTGID, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	actionID, err = s.InsertAgentAction(ctx, AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: ActionTypeReply,
		Payload: "draft", PolicyDecision: PolicyRequireApproval, Status: ActionApproved,
	})
	if err != nil {
		t.Fatalf("insert action: %v", err)
	}
	action, err := s.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if ok, err := s.ReserveAgentActionSend(ctx, *action, randomID, body, 0, 0, time.Time{}, false); err != nil || !ok {
		t.Fatalf("reserve: ok=%v err=%v", ok, err)
	}
	return actionID, conv
}

func countRows(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestNoteAgentActionSendAttempt_CountsOnlyWhileExecuting(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "attempts-owner")
	id, conv := executingSend(t, s, uid, 701, "hello Bob")

	for want := 1; want <= 2; want++ {
		got, ok, err := s.NoteAgentActionSendAttempt(ctx, uid, id)
		if err != nil || !ok || got != want {
			t.Fatalf("attempt %d: got=%d ok=%v err=%v", want, got, ok, err)
		}
	}
	if ok, err := s.RecordAgentActionSent(ctx, uid, id, conv.ID, 9001, "hello Bob"); err != nil || !ok {
		t.Fatalf("record sent: ok=%v err=%v", ok, err)
	}
	if _, ok, err := s.NoteAgentActionSendAttempt(ctx, uid, id); err != nil || ok {
		t.Fatalf("attempt on an executed row: ok=%v err=%v, want not ok", ok, err)
	}
}

// TestMarkAgentActionDeliveryUnknown_AlertsOnce: the transition is the
// alert's dedup, so a second caller racing on the same row neither moves it
// nor queues a second alert.
func TestMarkAgentActionDeliveryUnknown_AlertsOnce(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "unknown-owner")
	id, _ := executingSend(t, s, uid, 702, "hello Bob")

	for i, want := range []bool{true, false} {
		ok, err := s.MarkAgentActionDeliveryUnknown(ctx, uid, id, "delivery unknown: test", "check the chat")
		if err != nil || ok != want {
			t.Fatalf("call %d: ok=%v err=%v, want %v", i+1, ok, err, want)
		}
	}
	a, err := s.GetAgentAction(ctx, uid, id)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if a.Status != ActionDeliveryUnknown || a.PolicyReasons != "delivery unknown: test" {
		t.Fatalf("status=%q reasons=%q", a.Status, a.PolicyReasons)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM owner_notifications WHERE user_id = $1 AND kind = $2`, uid, NotificationDeliveryUnknown); n != 1 {
		t.Fatalf("alerts = %d, want 1", n)
	}
}

// TestMarkAgentActionDeliveryUnknown_AlertNotSwallowedByApprovalRequest: an
// approved action already owns the per-action_id notification slot with its
// approval request; the delivery-unknown alert must still be queued.
func TestMarkAgentActionDeliveryUnknown_AlertNotSwallowedByApprovalRequest(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "unknown-approval-owner")
	id, _ := executingSend(t, s, uid, 703, "hello Bob")
	if _, err := s.InsertOwnerNotification(ctx, OwnerNotification{
		UserID: uid, Kind: NotificationApproval, ActionID: id, Body: "approve?",
	}); err != nil {
		t.Fatalf("seed approval request: %v", err)
	}
	if ok, err := s.MarkAgentActionDeliveryUnknown(ctx, uid, id, "delivery unknown: test", "check the chat"); err != nil || !ok {
		t.Fatalf("mark: ok=%v err=%v", ok, err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM owner_notifications WHERE user_id = $1 AND kind = $2`, uid, NotificationDeliveryUnknown); n != 1 {
		t.Fatalf("alerts = %d, want 1", n)
	}
}

// TestMatchUnconfirmedAgentSend_ExecutingNotesIDForCompletion: an echo seen
// while the send is still executing is the agent's, and the id it carries
// is what RecordAgentActionSent records when the retry itself learns none.
func TestMatchUnconfirmedAgentSend_ExecutingNotesIDForCompletion(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "echo-executing-owner")
	id, conv := executingSend(t, s, uid, 704, "hello Bob\n\n- AI")
	since := time.Now().Add(-time.Hour)

	if ok, err := s.MatchUnconfirmedAgentSend(ctx, uid, bobTGID, 8100, "someone else's words", since); err != nil || ok {
		t.Fatalf("different text: ok=%v err=%v, want no match", ok, err)
	}
	if ok, err := s.MatchUnconfirmedAgentSend(ctx, uid, 500100101, 8100, "hello Bob\n\n- AI", since); err != nil || ok {
		t.Fatalf("other chat: ok=%v err=%v, want no match", ok, err)
	}
	if ok, err := s.MatchUnconfirmedAgentSend(ctx, uid, bobTGID, 8100, "  hello Bob\n\n- AI ", since); err != nil || !ok {
		t.Fatalf("echo: ok=%v err=%v, want match", ok, err)
	}
	if ok, err := s.RecordAgentActionSent(ctx, uid, id, conv.ID, 0, "hello Bob\n\n- AI"); err != nil || !ok {
		t.Fatalf("record sent: ok=%v err=%v", ok, err)
	}
	a, err := s.GetAgentAction(ctx, uid, id)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if a.Status != ActionExecuted || a.ExecutedTGMessageID != 8100 {
		t.Fatalf("status=%q id=%d, want executed with the echoed 8100", a.Status, a.ExecutedTGMessageID)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM conversation_messages WHERE conversation_id = $1 AND tg_message_id = 8100`, conv.ID); n != 1 {
		t.Fatalf("history rows with the echoed id = %d, want 1", n)
	}
}

// TestMatchUnconfirmedAgentSend_ProvesDeliveryUnknownDelivered: the echo
// of a delivery_unknown send is proof of delivery, so the action moves to
// executed with that id and a history row.
func TestMatchUnconfirmedAgentSend_ProvesDeliveryUnknownDelivered(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "echo-unknown-owner")
	id, conv := executingSend(t, s, uid, 705, "hello Bob")
	if ok, err := s.MarkAgentActionDeliveryUnknown(ctx, uid, id, "delivery unknown: test", "check the chat"); err != nil || !ok {
		t.Fatalf("mark: ok=%v err=%v", ok, err)
	}
	if ok, err := s.MatchUnconfirmedAgentSend(ctx, uid, bobTGID, 8200, "hello Bob", time.Now().Add(-time.Hour)); err != nil || !ok {
		t.Fatalf("echo: ok=%v err=%v, want match", ok, err)
	}
	a, err := s.GetAgentAction(ctx, uid, id)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if a.Status != ActionExecuted || a.ExecutedTGMessageID != 8200 {
		t.Fatalf("status=%q id=%d, want executed with 8200", a.Status, a.ExecutedTGMessageID)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM conversation_messages WHERE conversation_id = $1 AND tg_message_id = 8200`, conv.ID); n != 1 {
		t.Fatalf("history rows = %d, want 1", n)
	}
}

// TestMatchUnconfirmedAgentSend_FillsExecutedUnknownID covers the echo that
// arrives after recovery already recorded the send with an unknown id.
func TestMatchUnconfirmedAgentSend_FillsExecutedUnknownID(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "echo-executed-owner")
	id, conv := executingSend(t, s, uid, 706, "hello Bob")
	if ok, err := s.RecordAgentActionSent(ctx, uid, id, conv.ID, 0, "hello Bob"); err != nil || !ok {
		t.Fatalf("record sent: ok=%v err=%v", ok, err)
	}
	if ok, err := s.MatchUnconfirmedAgentSend(ctx, uid, bobTGID, 8300, "hello Bob", time.Now().Add(-time.Hour)); err != nil || !ok {
		t.Fatalf("echo: ok=%v err=%v, want match", ok, err)
	}
	a, err := s.GetAgentAction(ctx, uid, id)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if a.ExecutedTGMessageID != 8300 || a.SendBody != "" {
		t.Fatalf("id=%d body kept=%v, want 8300 and the body cleared", a.ExecutedTGMessageID, a.SendBody != "")
	}
	// Matched once: a second echo of the same text is no longer the agent's.
	if ok, err := s.MatchUnconfirmedAgentSend(ctx, uid, bobTGID, 8301, "hello Bob", time.Now().Add(-time.Hour)); err != nil || ok {
		t.Fatalf("second echo: ok=%v err=%v, want no match", ok, err)
	}
}

// TestReserveAgentActionSend_CountsDeliveryUnknownAgainstRate: a send that
// may have been delivered counts toward the per-minute limit, like an
// executing reservation does.
func TestReserveAgentActionSend_CountsDeliveryUnknownAgainstRate(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "rate-owner")
	id, conv := executingSend(t, s, uid, 707, "hello Bob")
	if ok, err := s.MarkAgentActionDeliveryUnknown(ctx, uid, id, "delivery unknown: test", ""); err != nil || !ok {
		t.Fatalf("mark: ok=%v err=%v", ok, err)
	}
	next, err := s.InsertAgentAction(ctx, AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: ActionTypeReply,
		Payload: "again", PolicyDecision: PolicyAllow, Status: ActionApproved,
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	action, err := s.GetAgentAction(ctx, uid, next)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	_, err = s.ReserveAgentActionSend(ctx, *action, 708, "again", 0, 1, time.Now().UTC().Add(-time.Minute), true)
	if err == nil {
		t.Fatal("reservation passed the one-per-minute limit with a delivery_unknown send in the window")
	}
}

// TestListRecentAgentOutgoing_IncludesDeliveryUnknown: the recovery-side
// rate window counts a send that may have been delivered.
func TestListRecentAgentOutgoing_IncludesDeliveryUnknown(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "recent-owner")
	id, conv := executingSend(t, s, uid, 709, "hello Bob")
	if ok, err := s.MarkAgentActionDeliveryUnknown(ctx, uid, id, "delivery unknown: test", ""); err != nil || !ok {
		t.Fatalf("mark: ok=%v err=%v", ok, err)
	}
	got, err := s.ListRecentAgentOutgoingTimestampsExcludingAction(ctx, uid, conv.ID, time.Now().UTC().Add(-time.Minute), 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("recent sends = %d, want 1 (the delivery_unknown send)", len(got))
	}
}

// TestSweepAgentMessageBodies_ClearsDeliveryUnknownBody: the send body kept
// for echo matching still expires with retention.
func TestSweepAgentMessageBodies_ClearsDeliveryUnknownBody(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "sweep-owner")
	id, _ := executingSend(t, s, uid, 710, "hello Bob")
	if ok, err := s.MarkAgentActionDeliveryUnknown(ctx, uid, id, "delivery unknown: test", ""); err != nil || !ok {
		t.Fatalf("mark: ok=%v err=%v", ok, err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour)
	if _, err := s.DB.ExecContext(ctx, `UPDATE agent_actions SET created_at = $1, updated_at = $1 WHERE id = $2`, old, id); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if _, err := s.SweepAgentMessageBodies(ctx, 24*time.Hour); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM agent_actions WHERE id = $1 AND send_body_encrypted IS NOT NULL`, id); n != 0 {
		t.Fatal("delivery_unknown send body survived the retention sweep")
	}
}
