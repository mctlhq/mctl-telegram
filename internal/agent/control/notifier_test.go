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

// TestNotifier_DeliverPending_TruncatesOversizedSummary guards against a
// Codex finding on #307: an unbounded summary body sent as-is fails with
// Telegram's MESSAGE_TOO_LONG — a permanent error for that exact payload —
// yet DeliverPending's send-failure path treats every failure as transient
// until MaxPendingAge, so the owner would never receive it for a full day.
func TestNotifier_DeliverPending_TruncatesOversizedSummary(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	huge := strings.Repeat("x", maxTelegramMessageLen+500)
	if _, err := store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: uid, Kind: db.NotificationSummary, Body: huge,
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
	if got := len([]rune(sender.sent[0])); got > maxTelegramMessageLen {
		t.Fatalf("sent body is %d runes, want <= %d", got, maxTelegramMessageLen)
	}
}

// TestNotifier_DeliverPending_TruncatesDraftButKeepsApprovalCommands is the
// approval-specific half of the same fix: truncating the composed string
// blindly from the end (as the summary path does) risks cutting off the
// /mctl approve|reject lines entirely if the draft payload alone is already
// near the limit — leaving the owner with no visible way to act on it.
func TestNotifier_DeliverPending_TruncatesDraftButKeepsApprovalCommands(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "peer", "Peer")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	hugePayload := strings.Repeat("x", maxTelegramMessageLen+500)
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply,
		Payload: hugePayload, PolicyDecision: db.PolicyRequireApproval,
		Status: db.ActionPendingApproval, ApprovalCode: "CODE01",
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
	if got := len([]rune(text)); got > maxTelegramMessageLen {
		t.Fatalf("sent body is %d runes, want <= %d", got, maxTelegramMessageLen)
	}
	if !strings.Contains(text, "/mctl approve CODE01") || !strings.Contains(text, "/mctl reject CODE01") {
		t.Fatalf("truncation cut off the approve/reject commands: %q", text)
	}
}

// TestNotifier_DeliverPending_TransientFormatErrorStaysPending guards
// against a Codex finding on #307: format's only failure mode
// (GetAgentAction erroring) was treated as permanent and retired the row
// immediately, discarding the notification forever on the first hiccup —
// the owner never receives it and never finds out delivery was even
// attempted. An orphaned action_id (simulating GetAgentAction failing —
// InsertOwnerNotification validates the action exists at insert time, so
// the row is deleted out from under it afterward) must leave the
// notification pending for another attempt, same as a transient send
// failure.
func TestNotifier_DeliverPending_TransientFormatErrorStaysPending(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "peer", "Peer")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply,
		Payload: "hi", PolicyDecision: db.PolicyRequireApproval,
		Status: db.ActionPendingApproval, ApprovalCode: "CODE02",
	})
	if err != nil {
		t.Fatalf("seed action: %v", err)
	}
	notifID, err := store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: uid, Kind: db.NotificationApproval, ActionID: actionID, Body: "ignored",
	})
	if err != nil {
		t.Fatalf("seed notification: %v", err)
	}
	if _, err := store.DB.ExecContext(ctx, `DELETE FROM agent_actions WHERE id = ?`, actionID); err != nil {
		t.Fatalf("orphan the linked action: %v", err)
	}

	notifier := NewNotifier(store, sender)
	notifier.MaxPendingAge = time.Hour // comfortably not exceeded yet
	delivered, failed, err := notifier.DeliverPending(ctx)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if delivered != 0 || failed != 1 {
		t.Fatalf("delivered=%d failed=%d, want 0/1", delivered, failed)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("sent = %d, want 0 (format failed before any send attempt)", len(sender.sent))
	}
	pending, err := store.ListPendingOwnerNotifications(ctx, 50)
	if err != nil {
		t.Fatalf("list pending: %v", err)
	}
	found := false
	for _, n := range pending {
		if n.ID == notifID {
			found = true
		}
	}
	if !found {
		t.Fatal("notification was retired on a format error before MaxPendingAge elapsed — should still be pending")
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
