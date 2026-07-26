package db

import (
	"context"
	"testing"
	"time"
)

// seedAgentUser creates a user row and returns its id.
func seedAgentUser(t *testing.T, s *Store, login string) int64 {
	t.Helper()
	uid, err := s.EnsureUser(context.Background(), login, "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	return uid
}

func TestInsertIncomingEvent_DedupByEventID(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	ev := IncomingEvent{
		EventID:    "evt:v1:1:100:5",
		UserID:     uid,
		Kind:       EventKindPrivateMessage,
		ChatTGID:   100,
		SenderTGID: 100,
		MessageID:  5,
		Body:       "hello, are you open to offers?",
	}
	id1, inserted, err := s.InsertIncomingEvent(ctx, ev)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if !inserted || id1 == 0 {
		t.Fatalf("first insert: inserted=%v id=%d, want true/nonzero", inserted, id1)
	}

	// Redelivery of the same update (same event_id) must be a silent no-op.
	id2, inserted, err := s.InsertIncomingEvent(ctx, ev)
	if err != nil {
		t.Fatalf("duplicate insert: %v", err)
	}
	if inserted || id2 != 0 {
		t.Fatalf("duplicate insert: inserted=%v id=%d, want false/0", inserted, id2)
	}
}

func TestGetIncomingEvent_RoundTripsEncryptedBody(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	const body = "Здравствуйте! Рассматриваете предложения?"
	if _, _, err := s.InsertIncomingEvent(ctx, IncomingEvent{
		EventID: "evt:v1:1:100:6", UserID: uid, Kind: EventKindPrivateMessage,
		ChatTGID: 100, SenderTGID: 100, MessageID: 6, Body: body,
		Meta: `{"sender_username":"anna_hr"}`,
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// The stored blob must not be plaintext.
	var blob []byte
	if err := s.DB.QueryRowContext(ctx,
		`SELECT body_encrypted FROM incoming_events WHERE event_id = $1`, "evt:v1:1:100:6",
	).Scan(&blob); err != nil {
		t.Fatalf("select blob: %v", err)
	}
	if string(blob) == body {
		t.Fatal("body stored in plaintext")
	}

	got, err := s.GetIncomingEvent(ctx, uid, "evt:v1:1:100:6")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Body != body {
		t.Fatalf("body = %q, want %q", got.Body, body)
	}
	if got.Meta != `{"sender_username":"anna_hr"}` {
		t.Fatalf("meta = %q", got.Meta)
	}
}

func TestGetIncomingEvent_ScopedToUser(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	owner := seedAgentUser(t, s, "owner")
	other := seedAgentUser(t, s, "other")

	if _, _, err := s.InsertIncomingEvent(ctx, IncomingEvent{
		EventID: "evt:v1:1:100:7", UserID: owner, Kind: EventKindPrivateMessage,
		ChatTGID: 100, SenderTGID: 100, MessageID: 7, Body: "private",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, err := s.GetIncomingEvent(ctx, other, "evt:v1:1:100:7"); err != ErrIncomingEventNotFound {
		t.Fatalf("cross-user read err = %v, want ErrIncomingEventNotFound", err)
	}
}

func TestSweepAgentMessageBodies_DeletesOldRowsOnly(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	if _, _, err := s.InsertIncomingEvent(ctx, IncomingEvent{
		EventID: "evt:v1:1:100:8", UserID: uid, Kind: EventKindPrivateMessage,
		ChatTGID: 100, SenderTGID: 100, MessageID: 8, Body: "old",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Backdate the row past the retention window.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE incoming_events SET created_at = $1 WHERE event_id = $2`,
		time.Now().UTC().Add(-40*24*time.Hour), "evt:v1:1:100:8",
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if _, _, err := s.InsertIncomingEvent(ctx, IncomingEvent{
		EventID: "evt:v1:1:100:9", UserID: uid, Kind: EventKindPrivateMessage,
		ChatTGID: 100, SenderTGID: 100, MessageID: 9, Body: "fresh",
	}); err != nil {
		t.Fatalf("insert fresh: %v", err)
	}

	rows, err := s.SweepAgentMessageBodies(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rows != 1 {
		t.Fatalf("sweep cleared %d bodies, want 1", rows)
	}
	// The aged event survives as a tombstone (dedup key preserved) but its
	// body is cleared; a redelivery must still collide on event_id.
	old, err := s.GetIncomingEvent(ctx, uid, "evt:v1:1:100:8")
	if err != nil {
		t.Fatalf("tombstone gone: %v", err)
	}
	if old.Body != "" {
		t.Fatalf("tombstone body not cleared: %q", old.Body)
	}
	if _, inserted, err := s.InsertIncomingEvent(ctx, IncomingEvent{
		EventID: "evt:v1:1:100:8", UserID: uid, Kind: EventKindPrivateMessage,
		ChatTGID: 100, SenderTGID: 100, MessageID: 8, Body: "redelivered",
	}); err != nil || inserted {
		t.Fatalf("redelivery after tombstone: inserted=%v err=%v, want false", inserted, err)
	}
	// The fresh event keeps its body.
	fresh, err := s.GetIncomingEvent(ctx, uid, "evt:v1:1:100:9")
	if err != nil {
		t.Fatalf("fresh event gone: %v", err)
	}
	if fresh.Body != "fresh" {
		t.Fatalf("fresh event body = %q, want fresh", fresh.Body)
	}

	// retention <= 0 means keep forever — must be a no-op.
	rows, err = s.SweepAgentMessageBodies(ctx, 0)
	if err != nil {
		t.Fatalf("sweep with zero retention: %v", err)
	}
	if rows != 0 {
		t.Fatalf("zero-retention sweep removed %d rows, want 0", rows)
	}
}

func TestSweepAgentMessageBodies_RetiresAndClearsOldActionContent(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "old-action-owner")
	actionID, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, ActionType: ActionTypeReply, PolicyDecision: PolicyRequireApproval,
		Status: ActionPendingApproval, ApprovalCode: "AB12", Payload: "private draft",
	})
	if err != nil {
		t.Fatalf("insert action: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status=$1, send_body_encrypted=$2, created_at=$3, updated_at=$3
		  WHERE id=$4`,
		ActionApproved, []byte("encrypted-final-body"), time.Now().UTC().Add(-40*24*time.Hour), actionID,
	); err != nil {
		t.Fatalf("backdate action: %v", err)
	}

	if _, err := s.SweepAgentMessageBodies(ctx, 30*24*time.Hour); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	var (
		status                                      string
		payload, sendBody, codeHash, codeCiphertext []byte
		code                                        *string
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT status, payload_encrypted, send_body_encrypted,
		        approval_code_hash, approval_code_encrypted, approval_code
		   FROM agent_actions WHERE id=$1`, actionID,
	).Scan(&status, &payload, &sendBody, &codeHash, &codeCiphertext, &code); err != nil {
		t.Fatalf("read action: %v", err)
	}
	if status != ActionDenied {
		t.Fatalf("status = %q, want denied", status)
	}
	if payload != nil || sendBody != nil || codeHash != nil || codeCiphertext != nil || code != nil {
		t.Fatalf("expired action retained content/capability: payload=%x send=%x hash=%x ciphertext=%x code=%v",
			payload, sendBody, codeHash, codeCiphertext, code)
	}
}

func TestSweepAgentMessageBodies_DoesNotClearExecutingOldAction(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "active-old-action-owner")
	actionID, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, ActionType: ActionTypeReply, PolicyDecision: PolicyRequireApproval,
		Status: ActionPendingApproval, ApprovalCode: "CD34", Payload: "active private draft",
	})
	if err != nil {
		t.Fatalf("insert action: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status=$1, send_body_encrypted=$2, created_at=$3, updated_at=$4
		  WHERE id=$5`,
		ActionExecuting, []byte("active-encrypted-final-body"),
		time.Now().UTC().Add(-40*24*time.Hour), time.Now().UTC().Add(-40*24*time.Hour), actionID,
	); err != nil {
		t.Fatalf("backdate active action: %v", err)
	}

	if _, err := s.SweepAgentMessageBodies(ctx, 30*24*time.Hour); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	var (
		status            string
		payload, sendBody []byte
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT status, payload_encrypted, send_body_encrypted
		   FROM agent_actions WHERE id=$1`, actionID,
	).Scan(&status, &payload, &sendBody); err != nil {
		t.Fatalf("read action: %v", err)
	}
	if status != ActionExecuting {
		t.Fatalf("status = %q, want executing", status)
	}
	if payload == nil || sendBody == nil {
		t.Fatalf("active action content cleared: payload=%x send=%x", payload, sendBody)
	}
}
