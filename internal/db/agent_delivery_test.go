package db

import (
	"context"
	"fmt"
	"os"
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

// attempted stamps one send attempt, as send() does before its RPC.
func attempted(t *testing.T, s *Store, uid, id int64) {
	t.Helper()
	if _, ok, err := s.NoteAgentActionSendAttempt(context.Background(), uid, id); err != nil || !ok {
		t.Fatalf("note attempt: ok=%v err=%v", ok, err)
	}
}

func countRows(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func caseNoteAgentActionSendAttempt_CountsOnlyWhileExecuting(t *testing.T, s *Store, uid int64) {
	ctx := context.Background()
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
func caseMarkAgentActionDeliveryUnknown_AlertsOnce(t *testing.T, s *Store, uid int64) {
	ctx := context.Background()
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
func caseMarkAgentActionDeliveryUnknown_AlertNotSwallowedByApprovalRequest(t *testing.T, s *Store, uid int64) {
	ctx := context.Background()
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
func caseMatchUnconfirmedAgentSend_ExecutingNotesIDForCompletion(t *testing.T, s *Store, uid int64) {
	ctx := context.Background()
	id, conv := executingSend(t, s, uid, 704, "hello Bob\n\n- AI")
	since := time.Now().Add(-time.Hour)
	// No attempt stamped yet: nothing can have been sent, so no echo.
	if ok, err := s.MatchUnconfirmedAgentSend(ctx, uid, bobTGID, 8099, "hello Bob\n\n- AI", since); err != nil || ok {
		t.Fatalf("before any attempt: ok=%v err=%v, want no match", ok, err)
	}
	attempted(t, s, uid, id)

	if ok, err := s.MatchUnconfirmedAgentSend(ctx, uid, bobTGID, 8100, "someone else's words", since); err != nil || ok {
		t.Fatalf("different text: ok=%v err=%v, want no match", ok, err)
	}
	if ok, err := s.MatchUnconfirmedAgentSend(ctx, uid, 500100101, 8100, "hello Bob\n\n- AI", since); err != nil || ok {
		t.Fatalf("other chat: ok=%v err=%v, want no match", ok, err)
	}
	if ok, err := s.MatchUnconfirmedAgentSend(ctx, uid, bobTGID, 8100, "  hello Bob\n\n- AI ", since); err != nil || !ok {
		t.Fatalf("echo: ok=%v err=%v, want match", ok, err)
	}
	// One echo per send: a later identical message is the owner's.
	if ok, err := s.MatchUnconfirmedAgentSend(ctx, uid, bobTGID, 8101, "hello Bob\n\n- AI", since); err != nil || ok {
		t.Fatalf("second identical message: ok=%v err=%v, want no match", ok, err)
	}
	// A noted id proves delivery, so the send cannot end delivery_unknown.
	if ok, err := s.MarkAgentActionDeliveryUnknown(ctx, uid, id, "delivery unknown: test", "check the chat"); err != nil || ok {
		t.Fatalf("mark after a noted echo: ok=%v err=%v, want refused", ok, err)
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
func caseMatchUnconfirmedAgentSend_ProvesDeliveryUnknownDelivered(t *testing.T, s *Store, uid int64) {
	ctx := context.Background()
	id, conv := executingSend(t, s, uid, 705, "hello Bob")
	attempted(t, s, uid, id)
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
func caseMatchUnconfirmedAgentSend_FillsExecutedUnknownID(t *testing.T, s *Store, uid int64) {
	ctx := context.Background()
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
func caseReserveAgentActionSend_CountsDeliveryUnknownAgainstRate(t *testing.T, s *Store, uid int64) {
	ctx := context.Background()
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
func caseListRecentAgentOutgoing_IncludesDeliveryUnknown(t *testing.T, s *Store, uid int64) {
	ctx := context.Background()
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
func caseSweepAgentMessageBodies_ClearsDeliveryUnknownBody(t *testing.T, s *Store, uid int64) {
	ctx := context.Background()
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

// caseHumanInputUnknownMessageIDStoresNull: a human-input notification
// proven delivered by a duplicate, with no located id, records its message
// id as unknown (NULL) on both the notification and the delivery row.
func caseHumanInputUnknownMessageIDStoresNull(t *testing.T, s *Store, uid int64) {
	ctx := context.Background()
	code := fmt.Sprintf("U%05d", uid%100000)
	if _, _, err := s.UpsertHumanInputDeliveryTx(ctx, HumanInputDelivery{
		UserID: uid, RequestID: fmt.Sprintf("hi_dup_%d", uid), RequestHash: "h", RequestVersion: 1,
		WorkItemID: "wi_dup", Kind: "single_choice", AnswerCode: code,
		OptionDigests: []string{"0123456789abcdef"},
	}, "question for Dana"); err != nil {
		t.Fatalf("upsert delivery: %v", err)
	}
	d, err := s.GetHumanInputDeliveryByCode(ctx, uid, code)
	if err != nil {
		t.Fatalf("get delivery: %v", err)
	}
	if err := s.MarkOwnerNotificationSent(ctx, uid, d.NotificationID, 0); err != nil {
		t.Fatalf("mark sent: %v", err)
	}
	if _, found, err := s.SetHumanInputDeliveryMessageID(ctx, d.NotificationID, 0); err != nil || !found {
		t.Fatalf("set message id: found=%v err=%v", found, err)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM owner_notifications WHERE id = $1 AND tg_message_id IS NULL`, d.NotificationID); n != 1 {
		t.Fatal("notification message id stored as a value, want NULL")
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM human_input_deliveries WHERE notification_id = $1 AND tg_message_id IS NULL`, d.NotificationID); n != 1 {
		t.Fatal("delivery message id stored as a value, want NULL")
	}
}

// deliveryCases runs every #1029 store case against one dialect. Postgres
// keeps state between runs, so each case gets its own user.
func deliveryCases(t *testing.T, s *Store, prefix string) {
	cases := []struct {
		name string
		run  func(t *testing.T, s *Store, uid int64)
	}{
		{"NoteAgentActionSendAttempt_CountsOnlyWhileExecuting", caseNoteAgentActionSendAttempt_CountsOnlyWhileExecuting},
		{"MarkAgentActionDeliveryUnknown_AlertsOnce", caseMarkAgentActionDeliveryUnknown_AlertsOnce},
		{"MarkAgentActionDeliveryUnknown_AlertNotSwallowedByApprovalRequest", caseMarkAgentActionDeliveryUnknown_AlertNotSwallowedByApprovalRequest},
		{"MatchUnconfirmedAgentSend_ExecutingNotesIDForCompletion", caseMatchUnconfirmedAgentSend_ExecutingNotesIDForCompletion},
		{"MatchUnconfirmedAgentSend_ProvesDeliveryUnknownDelivered", caseMatchUnconfirmedAgentSend_ProvesDeliveryUnknownDelivered},
		{"MatchUnconfirmedAgentSend_FillsExecutedUnknownID", caseMatchUnconfirmedAgentSend_FillsExecutedUnknownID},
		{"ReserveAgentActionSend_CountsDeliveryUnknownAgainstRate", caseReserveAgentActionSend_CountsDeliveryUnknownAgainstRate},
		{"ListRecentAgentOutgoing_IncludesDeliveryUnknown", caseListRecentAgentOutgoing_IncludesDeliveryUnknown},
		{"SweepAgentMessageBodies_ClearsDeliveryUnknownBody", caseSweepAgentMessageBodies_ClearsDeliveryUnknownBody},
		{"HumanInputUnknownMessageIDStoresNull", caseHumanInputUnknownMessageIDStoresNull},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.run(t, s, seedAgentUser(t, s, fmt.Sprintf("%s-%s-%d", prefix, tc.name, time.Now().UnixNano())))
		})
	}
}

func TestDelivery_SQLite(t *testing.T) {
	deliveryCases(t, newTestStoreCrypted(t), "sqlite")
}

func TestDelivery_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	deliveryCases(t, newPostgresTestStore(t, dsn), "pg")
}
