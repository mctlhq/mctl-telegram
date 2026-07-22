package control

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// SelfSender is the narrow capability the Notifier needs: posting into the
// owner's own Saved Messages. Implemented in cmd/server/main.go over
// telegram.ClientPool + internal/telegram/sendself.go's SendToSelf; kept as
// an interface here so this package stays testable without a real MTProto
// client and does not need to import internal/telegram directly.
type SelfSender interface {
	SendToSelf(ctx context.Context, userID int64, text string) (int64, error)
}

// Notifier delivers owner_notifications rows (queued by the agent API's
// send_owner_summary/request_owner_approval, and by propose_reply for a
// pending_approval reply) into Saved Messages, and sends synchronous
// confirmations for /mctl commands.
type Notifier struct {
	Store  *db.Store
	Sender SelfSender
}

// NewNotifier constructs a Notifier.
func NewNotifier(store *db.Store, sender SelfSender) *Notifier {
	return &Notifier{Store: store, Sender: sender}
}

// Reply sends a short synchronous confirmation for a /mctl command — not
// queued through owner_notifications, since it is a direct response to
// something the owner just typed, not a background summary.
func (n *Notifier) Reply(ctx context.Context, userID int64, text string) error {
	_, err := n.Sender.SendToSelf(ctx, userID, text)
	return err
}

// DeliverPending sends every currently-pending owner_notifications row,
// formatting per Kind, and marks each sent or failed. System-wide (no user
// scoping) — call periodically from a goroutine in cmd/server/main.go, the
// same pattern as the other background sweeps in this codebase. Returns
// (delivered, failed) counts; a delivery failure for one notification does
// not stop the batch (the row stays `pending` and is retried next sweep).
func (n *Notifier) DeliverPending(ctx context.Context) (delivered, failed int, err error) {
	notifs, err := n.Store.ListPendingOwnerNotifications(ctx, 50)
	if err != nil {
		return 0, 0, fmt.Errorf("list pending notifications: %w", err)
	}
	for _, notif := range notifs {
		text, ferr := n.format(ctx, notif)
		if ferr != nil {
			slog.Warn("notifier: format failed, marking failed", "notification_id", notif.ID, "err", ferr)
			if merr := n.Store.MarkOwnerNotificationFailed(ctx, notif.UserID, notif.ID); merr != nil {
				slog.Warn("notifier: mark failed errored", "notification_id", notif.ID, "err", merr)
			}
			failed++
			continue
		}
		msgID, serr := n.Sender.SendToSelf(ctx, notif.UserID, text)
		if serr != nil {
			slog.Warn("notifier: send failed, will retry next sweep", "notification_id", notif.ID, "err", serr)
			failed++
			continue
		}
		if merr := n.Store.MarkOwnerNotificationSent(ctx, notif.UserID, notif.ID, msgID); merr != nil {
			slog.Warn("notifier: mark sent errored", "notification_id", notif.ID, "err", merr)
		}
		delivered++
	}
	return delivered, failed, nil
}

// format renders a notification body for delivery. Approval requests need
// the linked action's approval_code and draft text (the notification row
// itself only carries the raw intent text); every other kind is delivered
// as-is.
func (n *Notifier) format(ctx context.Context, notif db.OwnerNotification) (string, error) {
	if notif.Kind != db.NotificationApproval || notif.ActionID == 0 {
		return notif.Body, nil
	}
	action, err := n.Store.GetAgentAction(ctx, notif.UserID, notif.ActionID)
	if err != nil {
		return "", fmt.Errorf("load linked action: %w", err)
	}
	if action.ApprovalCode == "" {
		// Already decided (approved/rejected/expired) between insert and
		// delivery — the code was nulled on the terminal transition. Deliver
		// the draft as an FYI without approve/reject instructions that would
		// no longer work.
		return fmt.Sprintf("Draft reply (already resolved, status: %s):\n\n%s", action.Status, action.Payload), nil
	}
	return fmt.Sprintf(
		"Draft reply awaiting approval:\n\n%s\n\n/mctl approve %s\n/mctl reject %s",
		action.Payload, action.ApprovalCode, action.ApprovalCode,
	), nil
}
