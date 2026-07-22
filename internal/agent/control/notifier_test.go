package control

import (
	"context"
	"strings"
	"testing"
	"time"

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

// TestNotifier_DeliverPending_SkipsAlreadyClaimedRow guards against the P2
// found in review: two replicas (or two overlapping sweep ticks) racing on
// the same pending row must not both call SendToSelf for it. Simulated here
// by claiming the row out from under DeliverPending before calling it.
func TestNotifier_DeliverPending_SkipsAlreadyClaimedRow(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	notifID, err := store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: uid, Kind: db.NotificationSummary, Body: "hello",
	})
	if err != nil {
		t.Fatalf("seed notification: %v", err)
	}
	// A concurrent attempt already holds the lease.
	claimed, err := store.ClaimOwnerNotification(ctx, uid, notifID, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("pre-claim: claimed=%v err=%v", claimed, err)
	}

	notifier := NewNotifier(store, sender)
	delivered, failed, err := notifier.DeliverPending(ctx)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if delivered != 0 || failed != 0 {
		t.Fatalf("delivered=%d failed=%d, want 0/0 (row already claimed by someone else)", delivered, failed)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("sent = %d, want 0", len(sender.sent))
	}
}

// TestNotifier_DeliverPending_ClaimExpiresAndBecomesRetryable is the
// self-healing half of the same fix: a lease that is never released (the
// process died between claiming and Mark*) must expire and become claimable
// again, rather than orphaning the row outside every future
// ListPendingOwnerNotifications scan forever.
func TestNotifier_DeliverPending_ClaimExpiresAndBecomesRetryable(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	notifID, err := store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: uid, Kind: db.NotificationSummary, Body: "hello",
	})
	if err != nil {
		t.Fatalf("seed notification: %v", err)
	}
	// A lease that has already expired (simulating a crash long enough ago).
	claimed, err := store.ClaimOwnerNotification(ctx, uid, notifID, -time.Minute)
	if err != nil || !claimed {
		t.Fatalf("pre-claim: claimed=%v err=%v", claimed, err)
	}

	notifier := NewNotifier(store, sender)
	delivered, _, err := notifier.DeliverPending(ctx)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if delivered != 1 {
		t.Fatalf("delivered = %d, want 1 (expired lease must be reclaimable)", delivered)
	}
}

// TestNotifier_DeliverPending_RetiresPermanentlyFailingNotification guards
// against the P1 found in review: a notification that always fails to send
// (e.g. a revoked owner session) must eventually be retired rather than
// occupying a slot in the oldest-50 batch forever and starving newer,
// healthy accounts' notifications.
func TestNotifier_DeliverPending_RetiresPermanentlyFailingNotification(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	sender.err = errNotifySendFailed
	notifID, err := store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: uid, Kind: db.NotificationSummary, Body: "hello",
	})
	if err != nil {
		t.Fatalf("seed notification: %v", err)
	}

	notifier := NewNotifier(store, sender)
	// A nanosecond age limit: by the time DeliverPending's DB round trips
	// complete, any real duration comfortably exceeds it, forcing the
	// retire-on-failure branch. 0 is deliberately NOT used here — it means
	// "no age limit, retry forever" (matching AgentRetentionDays' "0 keeps
	// rows forever" convention elsewhere in this codebase), the opposite of
	// what this test needs.
	notifier.MaxPendingAge = time.Nanosecond
	notifier.ClaimLease = time.Millisecond
	_, failed, err := notifier.DeliverPending(ctx)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if failed != 1 {
		t.Fatalf("failed = %d, want 1", failed)
	}
	pending, err := store.ListPendingOwnerNotifications(ctx, 50)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	for _, n := range pending {
		if n.ID == notifID {
			t.Fatalf("notification %d still pending after exceeding MaxPendingAge — should have been retired", notifID)
		}
	}
}

type notifySendErr struct{ msg string }

func (e *notifySendErr) Error() string { return e.msg }

var errNotifySendFailed = &notifySendErr{"send failed"}

// TestNotifier_DeliverPending_OwnerApprovalRequestFormattedAsRequest guards
// against the P1 found in review: request_owner_approval actions (inserted
// as `executed` with no approval code) were formatted as "Draft reply
// (already resolved)" — misleading, since there was never an approve/reject
// mechanism for them in the first place.
func TestNotifier_DeliverPending_OwnerApprovalRequestFormattedAsRequest(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		UserID: uid, ActionType: db.ActionTypeOwnerApproval,
		Payload:        "May I offer to schedule a call for Thursday?",
		PolicyDecision: db.PolicyAllow, Status: db.ActionExecuted,
	})
	if err != nil {
		t.Fatalf("seed action: %v", err)
	}
	if _, err := store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: uid, Kind: db.NotificationApproval, ActionID: actionID, Body: "ignored",
	}); err != nil {
		t.Fatalf("seed notification: %v", err)
	}

	notifier := NewNotifier(store, sender)
	if _, _, err := notifier.DeliverPending(ctx); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("sent = %d, want 1", len(sender.sent))
	}
	text := sender.sent[0]
	if strings.Contains(text, "Draft reply") {
		t.Fatalf("owner-approval request misformatted as a draft reply: %q", text)
	}
	if !strings.Contains(text, "May I offer to schedule a call for Thursday?") {
		t.Fatalf("body missing the request text: %q", text)
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
