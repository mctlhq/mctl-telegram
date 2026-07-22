package control

import (
	"context"
	"fmt"
	"log/slog"
	"time"

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
	// ClaimLease bounds how long a claimed-for-delivery notification blocks
	// a concurrent claim attempt (another replica, or an overlapping sweep
	// tick) before it becomes claimable again — see Store.ClaimOwnerNotification.
	ClaimLease time.Duration
	// MaxPendingAge bounds how long a notification may keep failing delivery
	// before it is retired (MarkOwnerNotificationFailed) instead of being
	// retried forever. Without this, a permanently undeliverable account
	// (e.g. a revoked owner session) accumulates enough always-failing rows
	// in ListPendingOwnerNotifications' oldest-50 batch that the sweep never
	// reaches a healthy account's newer notifications at all.
	MaxPendingAge time.Duration
}

// defaultClaimLease and defaultMaxPendingAge are NewNotifier's defaults.
// defaultClaimLease matches executor.Executor's default StuckGrace — both
// bound "how long can one delivery attempt plausibly still be in flight
// before we assume it died". defaultMaxPendingAge matches the approval TTL
// default (AgentApprovalTTL) as the codebase's existing convention for "how
// long is a day-scale undelivered thing acceptable to keep retrying".
const (
	defaultClaimLease    = 2 * time.Minute
	defaultMaxPendingAge = 24 * time.Hour
)

// NewNotifier constructs a Notifier.
func NewNotifier(store *db.Store, sender SelfSender) *Notifier {
	return &Notifier{Store: store, Sender: sender, ClaimLease: defaultClaimLease, MaxPendingAge: defaultMaxPendingAge}
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
		// Claim before sending: two replicas (or two overlapping sweep
		// ticks) can both list the same pending row, but only one wins the
		// lease and should actually call SendToSelf for it. A lost claim is
		// not a failure — it means another attempt already owns this row.
		claimed, cerr := n.Store.ClaimOwnerNotification(ctx, notif.UserID, notif.ID, n.claimLease())
		if cerr != nil {
			slog.Warn("notifier: claim failed", "notification_id", notif.ID, "err", cerr)
			continue
		}
		if !claimed {
			continue
		}
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
			if n.MaxPendingAge > 0 && time.Since(notif.CreatedAt) > n.MaxPendingAge {
				// Permanently undeliverable (e.g. a revoked owner session) —
				// retire it instead of letting it keep occupying a slot in
				// the oldest-50 batch and starving newer, healthy accounts'
				// notifications forever.
				if merr := n.Store.MarkOwnerNotificationFailed(ctx, notif.UserID, notif.ID); merr != nil {
					slog.Warn("notifier: mark failed errored", "notification_id", notif.ID, "err", merr)
				}
			} else {
				slog.Warn("notifier: send failed, will retry next sweep", "notification_id", notif.ID, "err", serr)
				// Left claimed; the lease expires on its own and the row
				// becomes claimable again next sweep — no explicit release
				// needed (see Store.ClaimOwnerNotification's doc comment).
			}
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

func (n *Notifier) claimLease() time.Duration {
	if n.ClaimLease > 0 {
		return n.ClaimLease
	}
	return defaultClaimLease
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
	if action.ActionType == db.ActionTypeOwnerApproval {
		// request_owner_approval actions (handleOwnerFacing) are inserted
		// directly as `executed` with no approval code — they are the agent
		// asking the owner something, not a reply draft awaiting an
		// approve/reject code. Formatting this as "Draft reply (already
		// resolved)" below would be actively misleading: there was never an
		// approve/reject mechanism to resolve in the first place.
		return fmt.Sprintf("Owner input requested:\n\n%s", action.Payload), nil
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
