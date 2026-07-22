package control

import (
	"context"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func TestNotifier_DeliverPending_FormatsApprovalWithCode(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "peer", "Peer")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply,
		Payload: "Thanks for reaching out!", PolicyDecision: db.PolicyRequireApproval,
		Status: db.ActionPendingApproval, ApprovalCode: "CODE01",
	})
	if err != nil {
		t.Fatalf("seed action: %v", err)
	}
	if _, err := store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: uid, Kind: db.NotificationApproval, ActionID: actionID, Body: "ignored for approval kind",
	}); err != nil {
		t.Fatalf("seed notification: %v", err)
	}

	notifier := NewNotifier(store, sender)
	delivered, failed, err := notifier.DeliverPending(ctx)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if delivered != 1 || failed != 0 {
		t.Fatalf("delivered=%d failed=%d, want 1/0", delivered, failed)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("sent = %d, want 1", len(sender.sent))
	}
	text := sender.sent[0]
	if !strings.Contains(text, "Thanks for reaching out!") {
		t.Fatalf("body missing draft text: %q", text)
	}
	if !strings.Contains(text, "/mctl approve CODE01") || !strings.Contains(text, "/mctl reject CODE01") {
		t.Fatalf("body missing approve/reject instructions: %q", text)
	}
}

func TestNotifier_DeliverPending_SummaryDeliveredAsIs(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	if _, err := store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: uid, Kind: db.NotificationSummary, Body: "Daily digest: 3 new recruiters.",
	}); err != nil {
		t.Fatalf("seed notification: %v", err)
	}

	notifier := NewNotifier(store, sender)
	if _, _, err := notifier.DeliverPending(ctx); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(sender.sent) != 1 || sender.sent[0] != "Daily digest: 3 new recruiters." {
		t.Fatalf("sent = %v, want the raw summary body", sender.sent)
	}
}

func TestNotifier_DeliverPending_MarksSentAndIsIdempotent(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	notifID, err := store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: uid, Kind: db.NotificationSummary, Body: "hello",
	})
	if err != nil {
		t.Fatalf("seed notification: %v", err)
	}
	notifier := NewNotifier(store, sender)
	if _, _, err := notifier.DeliverPending(ctx); err != nil {
		t.Fatalf("deliver 1: %v", err)
	}
	// A second sweep must not re-deliver an already-sent notification.
	if _, _, err := notifier.DeliverPending(ctx); err != nil {
		t.Fatalf("deliver 2: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("total sends = %d, want 1 (already-sent row must not be re-delivered)", len(sender.sent))
	}
	pending, err := store.ListPendingOwnerNotifications(ctx, 50)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	for _, n := range pending {
		if n.ID == notifID {
			t.Fatalf("notification %d still pending after delivery", notifID)
		}
	}
}
