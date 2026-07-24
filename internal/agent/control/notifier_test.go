package control

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// TestNotifier_Reply_TruncatesOversizedText covers a Codex finding on #307:
// Reply (the synchronous /mctl command response path) bypassed the
// truncation DeliverPending already applies to queued notifications, so a
// long enough /mctl leads/show response could exceed Telegram's
// 4096-character limit, fail with the permanent MESSAGE_TOO_LONG, and — since
// the command is only marked audited after a successful Reply — replay the
// identical oversized text on every redelivery.
func TestNotifier_Reply_TruncatesOversizedText(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	notifier := NewNotifier(store, sender)

	oversized := strings.Repeat("x", maxTelegramMessageLen+500)
	if err := notifier.Reply(context.Background(), uid, oversized); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("sent = %d, want 1", len(sender.sent))
	}
	if got := len([]rune(sender.sent[0])); got > maxTelegramMessageLen {
		t.Fatalf("sent text length = %d, want <= %d", got, maxTelegramMessageLen)
	}
	if !strings.HasSuffix(sender.sent[0], truncatedSuffix) {
		t.Fatalf("sent text missing truncation marker: %q", sender.sent[0][len(sender.sent[0])-30:])
	}
}

// TestNotifier_DeliverPending_ApprovalIdentifiesRecipient covers a Codex
// finding on #307: the approval-awaiting message carried no conversation or
// recruiter identity at all. With more than one pending draft, the owner
// had no way to tell WHO a given approval code's text would be sent to
// before authorizing it — approving is immediate and sends straight to the
// action's linked peer.
func TestNotifier_DeliverPending_ApprovalIdentifiesRecipient(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "peer_username", "Jane Recruiter")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply,
		Payload: "Thanks for reaching out!", PolicyDecision: db.PolicyRequireApproval,
		Status: db.ActionPendingApproval, ApprovalCode: "CODE99",
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
	if _, _, err := notifier.DeliverPending(ctx); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("sent = %d, want 1", len(sender.sent))
	}
	if !strings.Contains(sender.sent[0], "Jane Recruiter") {
		t.Fatalf("approval message does not identify the recipient: %q", sender.sent[0])
	}
}

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

// TestNotifier_DeliverPending_KillSwitchSilencesQueuedDelivery covers a
// Codex finding on #307: the notifier had no way to observe
// AGENT_KILL_SWITCH at all, so a summary/approval request queued before the
// switch flipped on was still delivered — contradicting the policy path's
// documented guarantee that the emergency switch silences every
// owner-facing message. The row must stay pending (not failed) so it
// delivers normally once the switch is off again.
func TestNotifier_DeliverPending_KillSwitchSilencesQueuedDelivery(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	if _, err := store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: uid, Kind: db.NotificationSummary, Body: "hello",
	}); err != nil {
		t.Fatalf("seed notification: %v", err)
	}

	notifier := NewNotifier(store, sender)
	notifier.GlobalKill = func() bool { return true }
	delivered, failed, err := notifier.DeliverPending(ctx)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if delivered != 0 || failed != 0 {
		t.Fatalf("delivered=%d failed=%d, want 0/0 while the kill switch is on", delivered, failed)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("sent = %d, want 0 while the kill switch is on", len(sender.sent))
	}

	// Once the switch is off, the same row delivers normally — it must not
	// have been marked failed or otherwise consumed while silenced.
	notifier.GlobalKill = func() bool { return false }
	delivered, failed, err = notifier.DeliverPending(ctx)
	if err != nil {
		t.Fatalf("deliver after kill switch off: %v", err)
	}
	if delivered != 1 || failed != 0 {
		t.Fatalf("delivered=%d failed=%d, want 1/0 once the kill switch is off", delivered, failed)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("sent = %d, want 1 once the kill switch is off", len(sender.sent))
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
	// Checked directly against the row's status rather than via
	// ListPendingOwnerNotifications: DeliverPending leaves the row claimed
	// after a format failure (see the retry-next-sweep comment in
	// DeliverPending), and ListPendingOwnerNotifications now deliberately
	// excludes currently-leased rows (a separate #307 fix) — the row is
	// genuinely still `pending`, just not currently claimable, and that
	// distinction is exactly what this test needs to assert.
	var status string
	if err := store.DB.QueryRowContext(ctx,
		`SELECT status FROM owner_notifications WHERE id = ?`, notifID,
	).Scan(&status); err != nil {
		t.Fatalf("select notification status: %v", err)
	}
	if status != db.NotificationPending {
		t.Fatalf("status = %q, want %q (notification was retired on a format error before MaxPendingAge elapsed)", status, db.NotificationPending)
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
