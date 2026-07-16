package db

import (
	"context"
	"testing"
)

func TestHardDeleteAccount_PurgesAgentData(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	// Seed a full slice of agent data for the account.
	if err := s.UpsertAgentProfile(ctx, AgentProfile{UserID: uid, ListenerEnabled: true}); err != nil {
		t.Fatalf("profile: %v", err)
	}
	if _, _, err := s.InsertIncomingEvent(ctx, IncomingEvent{
		EventID: "evt:v1:1:1:1", UserID: uid, Kind: EventKindPrivateMessage,
		ChatTGID: 1, SenderTGID: 1, MessageID: 1, Body: "hi",
	}); err != nil {
		t.Fatalf("event: %v", err)
	}
	conv, err := s.EnsureConversation(ctx, uid, 555, "anna", "Anna")
	if err != nil {
		t.Fatalf("conversation: %v", err)
	}
	if _, err := s.InsertConversationMessage(ctx, uid, ConversationMessage{
		ConversationID: conv.ID, Direction: DirectionIncoming, Body: "hello",
	}); err != nil {
		t.Fatalf("message: %v", err)
	}
	if _, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: conv.ID, Role: "Dev"}); err != nil {
		t.Fatalf("lead: %v", err)
	}
	actionID, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, ConversationID: conv.ID, ActionType: ActionTypeReply,
		PolicyDecision: PolicyRequireApproval, Payload: "draft",
	})
	if err != nil {
		t.Fatalf("action: %v", err)
	}
	if _, err := s.InsertOwnerNotification(ctx, OwnerNotification{
		UserID: uid, Kind: NotificationApproval, ActionID: actionID, Body: "draft",
	}); err != nil {
		t.Fatalf("notification: %v", err)
	}
	// Seed gotd watermark tables via raw SQL (the typed setters land in a
	// later PR; the tables themselves exist in this schema).
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO tg_update_state(user_id, pts) VALUES($1, 1)`, uid); err != nil {
		t.Fatalf("update state: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO tg_channel_state(user_id, channel_id, pts) VALUES($1, 777, 5)`, uid); err != nil {
		t.Fatalf("channel state: %v", err)
	}
	// A telegram_accounts row so HardDeleteAccount has something to delete.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted) VALUES($1, $2)`,
		uid, []byte("blob"),
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
		t.Fatalf("hard delete: %v", err)
	}

	// Every agent table must be empty for this user.
	tables := []string{
		"agent_profiles", "incoming_events", "conversations", "job_leads",
		"agent_actions", "owner_notifications", "tg_update_state", "tg_channel_state",
	}
	for _, tbl := range tables {
		var n int
		if err := s.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM `+tbl+` WHERE user_id = $1`, uid,
		).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		if n != 0 {
			t.Fatalf("%s still has %d rows after account delete", tbl, n)
		}
	}
	// conversation_messages is keyed by conversation_id — verify none survive.
	var msgs int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM conversation_messages`,
	).Scan(&msgs); err != nil {
		t.Fatalf("count messages: %v", err)
	}
	if msgs != 0 {
		t.Fatalf("conversation_messages still has %d rows", msgs)
	}
}
