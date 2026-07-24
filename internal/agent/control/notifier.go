package control

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// maxTelegramMessageLen matches this codebase's established Telegram
// text-message cap (see internal/sanitize.UserContent's doc comment: "pass
// 4096 for Telegram message bodies"). Owner notification bodies are built
// from model-generated summaries and drafts with no length validation
// upstream — an over-length send fails with MESSAGE_TOO_LONG, which is a
// PERMANENT error for that exact payload, not a transient one: without
// truncating first, DeliverPending's retry-until-MaxPendingAge logic would
// keep retrying the identical oversized text for a full day before finally
// giving up, and the owner never receives even a partial notification in
// that entire window.
const maxTelegramMessageLen = 4096

const truncatedSuffix = "\n\n[truncated]"

func truncateForTelegram(s string) string {
	r := []rune(s)
	if len(r) <= maxTelegramMessageLen {
		return s
	}
	cut := maxTelegramMessageLen - len([]rune(truncatedSuffix))
	if cut < 0 {
		cut = 0
	}
	return string(r[:cut]) + truncatedSuffix
}

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
	// GlobalKill reads config.Config.AgentKillSwitch at call time (never a
	// snapshot — see executor.Executor.GlobalKill's identical doc comment).
	// nil ⇒ no kill-switch gate, matching tests that construct a Notifier
	// directly without wiring cmd/server/main.go's config. A Codex finding
	// on #307 caught that DeliverPending had no way to observe the kill
	// switch at all: a summary or approval request queued BEFORE the switch
	// flipped on would still go out, contradicting the policy path's
	// documented guarantee that the emergency switch silences every
	// owner-facing message, not just new ones.
	GlobalKill func() bool
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
//
// Truncated the same way DeliverPending's queued notifications are (a
// Codex finding on #307 caught this path bypassing that truncation
// entirely): /mctl leads/show compose their reply from model-supplied
// company/role/lead text with no length bound, so a long enough response
// can exceed Telegram's 4096-character limit. SendToSelf would then fail
// with the permanent MESSAGE_TOO_LONG, and — because HandleSavedText's
// caller only persists the audit dedup row after a successful Reply — the
// command is left unaudited and replays the identical oversized response
// on every redelivery.
func (n *Notifier) Reply(ctx context.Context, userID int64, text string) error {
	_, err := n.Sender.SendToSelf(ctx, userID, truncateForTelegram(text))
	return err
}

// DeliverPending sends every currently-pending owner_notifications row,
// formatting per Kind, and marks each sent or failed. System-wide (no user
// scoping) — call periodically from a goroutine in cmd/server/main.go, the
// same pattern as the other background sweeps in this codebase. Returns
// (delivered, failed) counts; a delivery failure for one notification does
// not stop the batch (the row stays `pending` and is retried next sweep).
func (n *Notifier) DeliverPending(ctx context.Context) (delivered, failed int, err error) {
	if n.GlobalKill != nil && n.GlobalKill() {
		// Silence ALL owner-facing delivery while the kill switch is on,
		// including rows queued before it flipped — leave them pending
		// (not failed) so they deliver normally once the switch is off
		// again, exactly like a claim lease that simply expires unused.
		return 0, 0, nil
	}
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
			// format's only failure mode today is GetAgentAction erroring —
			// which is far more likely a transient DB blip than a permanent
			// data problem (a genuinely missing/corrupt linked action would
			// be a schema bug, not something that self-heals). Retiring the
			// row on the first such error permanently discards the
			// notification — the owner never receives it and never even
			// finds out delivery was attempted. Leave it pending instead,
			// same as a transient send failure below: the claim lease
			// expires on its own and the row is retried next sweep, still
			// subject to MaxPendingAge if it keeps failing.
			slog.Warn("notifier: format failed, will retry next sweep", "notification_id", notif.ID, "err", ferr)
			if n.MaxPendingAge > 0 && time.Since(notif.CreatedAt) > n.MaxPendingAge {
				if merr := n.Store.MarkOwnerNotificationFailed(ctx, notif.UserID, notif.ID); merr != nil {
					slog.Warn("notifier: mark failed errored", "notification_id", notif.ID, "err", merr)
				}
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
// as-is. The returned string is always within maxTelegramMessageLen — see
// truncateForTelegram's doc comment for why that has to happen here rather
// than left to the send call to fail on.
func (n *Notifier) format(ctx context.Context, notif db.OwnerNotification) (string, error) {
	if notif.Kind != db.NotificationApproval || notif.ActionID == 0 {
		return truncateForTelegram(notif.Body), nil
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
		return truncateForTelegram(fmt.Sprintf("Owner input requested:\n\n%s", action.Payload)), nil
	}
	if action.ApprovalCode == "" {
		// Already decided (approved/rejected/expired) between insert and
		// delivery — the code was nulled on the terminal transition. Deliver
		// the draft as an FYI without approve/reject instructions that would
		// no longer work.
		return truncateForTelegram(fmt.Sprintf("Draft reply (already resolved, status: %s):\n\n%s", action.Status, action.Payload)), nil
	}
	// The /mctl approve|reject lines are the whole point of this message —
	// truncating the composed string from the end (as every other branch
	// does) risks cutting them off entirely if the draft payload alone is
	// already near the limit, leaving the owner with no visible way to act
	// on it. Truncate only the payload first, reserving room for the
	// fixed-length prefix/instructions, so the commands always survive
	// intact.
	instructions := fmt.Sprintf("\n\n/mctl approve %s\n/mctl reject %s", action.ApprovalCode, action.ApprovalCode)
	prefix := "Draft reply awaiting approval:\n\n"
	marker := "[truncated]"
	budget := maxTelegramMessageLen - len([]rune(prefix)) - len([]rune(instructions))
	payload := []rune(action.Payload)
	if budget < 0 {
		budget = 0
	}
	if len(payload) > budget {
		cut := budget - len([]rune(marker))
		if cut < 0 {
			cut = 0
		}
		payload = append(payload[:cut], []rune(marker)...)
	}
	return prefix + string(payload) + instructions, nil
}
