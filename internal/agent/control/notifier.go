package control

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
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
// telegram.ClientPool + internal/telegram/sendself.go; kept as an interface
// here so this package stays testable without a real MTProto client and
// does not need to import internal/telegram directly.
type SelfSender interface {
	// SendToSelf is used only by Reply — a synchronous /mctl command
	// confirmation that is never retried, so it has no crash-safety story
	// (matches internal/telegram.SendToSelf's own doc comment).
	SendToSelf(ctx context.Context, userID int64, text string) (int64, error)
	// SendToSelfWithRandomID delivers text using EXACTLY randomID as the
	// MTProto random_id — DeliverPending's crash-safe path, mirroring
	// executor.Sender.SendWithRandomID's identical rationale: persist the
	// id before the RPC (see Store.ClaimOwnerNotification), retry with the
	// SAME id after a crash, rely on MTProto's server-side dedup.
	// A RANDOM_ID_DUPLICATE refusal must be returned wrapped in
	// executor.ErrAlreadyDelivered: the notification is already there.
	SendToSelfWithRandomID(ctx context.Context, userID, randomID int64, text string) (int64, error)
}

// SelfDeliveryLocator is an optional SelfSender capability, the
// notification counterpart of executor.DeliveryLocator: find the Saved
// Messages id of a notification Telegram reported as a duplicate. found is
// true only for exactly one message with this text at or after since;
// anything else leaves the id unknown (#1029).
type SelfDeliveryLocator interface {
	LocateSelfDelivered(ctx context.Context, userID int64, text string, since time.Time) (messageID int64, found bool, err error)
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
	// Metrics is optional (nil-safe); it counts human-input deliveries.
	Metrics *metrics.Registry
}

// defaultClaimLease and defaultMaxPendingAge are NewNotifier's defaults,
// used as-is by tests and any caller that never overrides the field.
// defaultClaimLease matches executor.Executor's default StuckGrace — both
// bound "how long can one delivery attempt plausibly still be in flight
// before we assume it died". defaultMaxPendingAge matches AgentApprovalTTL's
// own default (24h) only by coincidence of both defaulting the same way;
// cmd/server/main.go overwrites MaxPendingAge with the actually-configured
// cfg.AgentApprovalTTL after construction so the two stay in sync even when
// AGENT_APPROVAL_TTL is set above 24h — see that wiring's comment for the
// Codex finding this fixed.
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
	// Live kill-switch recheck immediately before the sender (#1269). Only the
	// kill switch applies to a synchronous owner command reply: mode=off and
	// session state deliberately do not, so the owner can still run commands
	// such as /mctl status or a mode change while the assistant is off. A
	// denied reply is a deterministic error, never a silent drop: the caller
	// then does not persist its audit dedup row, which is the existing
	// contract for any failed Reply.
	if err := n.killFence(); err != nil {
		return err
	}
	_, err := n.Sender.SendToSelf(ctx, userID, truncateForTelegram(text))
	return err
}

// ErrSendBlocked marks an owner-facing send refused by the notifier's
// send-time fence (kill switch on, mode off, no usable session). The refusal
// is a state, not a failure of the notification: queued rows stay pending.
var ErrSendBlocked = errors.New("owner send blocked")

// ErrSendFenceUnverifiable means the fence could not read the state it
// authorizes against (database error). It fails closed exactly like a denial.
var ErrSendFenceUnverifiable = errors.New("owner send authorization unverifiable")

// killFence reads GlobalKill at call time (never a snapshot). nil GlobalKill
// means no kill gate, as before.
func (n *Notifier) killFence() error {
	if n.GlobalKill != nil && n.GlobalKill() {
		return fmt.Errorf("%w: global kill switch is on", ErrSendBlocked)
	}
	return nil
}

// sendFence is the single send-time authorization recheck for a queued
// notification. DeliverPending runs it per notification, both before claiming
// and again immediately before the sender call, so a flip in the middle of a
// batch is observed. Checks, cheapest and side-effect-free first:
//
//  1. live GlobalKill;
//  2. agent mode, for agent kinds only (summary, approval_request and any
//     unknown kind): mode=off, a missing profile and an unreadable profile all
//     deny. human_input is profile- and mode-independent by design (its code
//     never consults the agent profile) and skips this step only;
//  3. a live Telegram session for every kind, the same Store.CheckSessionValid
//     the ClientPool.Borrow beneath the real sender runs. NOT side-effect-free:
//     CheckSessionValid revokes an expired, idle or half-login session row
//     itself. Any error, including a database error, denies.
//
// It is not atomic with the send: the checks are database reads and the send
// is an RPC, so a flip between the last read and the RPC still goes out. The
// window is one DB round trip wide here; the real sender additionally
// rechecks the session in Borrow (the lower fence), which narrows but does
// not remove it either.
func (n *Notifier) sendFence(ctx context.Context, userID int64, kind string) error {
	if err := n.killFence(); err != nil {
		return err
	}
	if kind != db.NotificationHumanInput {
		p, err := n.Store.GetAgentProfile(ctx, userID)
		switch {
		case errors.Is(err, db.ErrAgentProfileNotFound):
			return fmt.Errorf("%w: no agent profile", ErrSendBlocked)
		case err != nil:
			return fmt.Errorf("%w: read agent profile: %w", ErrSendFenceUnverifiable, err)
		case p.Mode == db.AgentModeOff:
			return fmt.Errorf("%w: agent mode is off", ErrSendBlocked)
		}
	}
	if _, err := n.Store.CheckSessionValid(ctx, userID); err != nil {
		if errors.Is(err, db.ErrNoActiveSession) || errors.Is(err, db.ErrSessionExpired) ||
			errors.Is(err, db.ErrSessionUnauthorized) || errors.Is(err, db.ErrSessionRevoked) {
			return fmt.Errorf("%w: no usable session: %w", ErrSendBlocked, err)
		}
		return fmt.Errorf("%w: check session: %w", ErrSendFenceUnverifiable, err)
	}
	return nil
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
		// Fence before claiming so a blocked row is neither claimed nor leased
		// and resumes on the very next sweep once the block clears. A blocked
		// row stays pending, unclaimed, payload untouched.
		if ferr := n.sendFence(ctx, notif.UserID, notif.Kind); ferr != nil {
			if n.fenceSkip(notif, ferr) {
				failed++
			}
			continue
		}
		// Claim before sending: two replicas (or two overlapping sweep
		// ticks) can both list the same pending row, but only one wins the
		// lease and should actually call SendToSelf for it. A lost claim is
		// not a failure — it means another attempt already owns this row.
		//
		// A fresh candidate id is generated on every attempt but only ever
		// actually PERSISTED once (ClaimOwnerNotification's COALESCE) — a
		// retry after a crash gets back that same original value, not this
		// new candidate, so the eventual SendWithRandomID call always uses
		// whichever id Telegram may have already seen for this row.
		candidate, rerr := newSelfRandomID()
		if rerr != nil {
			slog.Warn("notifier: random id generation failed", "notification_id", notif.ID, "err", rerr)
			continue
		}
		randomID, claimed, cerr := n.Store.ClaimOwnerNotification(ctx, notif.UserID, notif.ID, candidate, n.claimLease())
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
		// Final boundary recheck, as close to the sender as the code allows:
		// the claim, the format lookups and earlier notifications in this
		// batch all took time, and the kill switch, mode or session may have
		// flipped since the pre-claim check. The row is already claimed and
		// its random_id persisted; it stays that way (the lease expires on its
		// own, the same id is reused on resume), and no send is attempted.
		if ferr := n.sendFence(ctx, notif.UserID, notif.Kind); ferr != nil {
			if n.fenceSkip(notif, ferr) {
				failed++
			}
			continue
		}
		msgID, serr := n.Sender.SendToSelfWithRandomID(ctx, notif.UserID, randomID, text)
		if errors.Is(serr, executor.ErrAlreadyDelivered) {
			// A retry of a claimed notification whose earlier send reached
			// Telegram but was never marked sent (a crash, or a lost
			// answer). Telegram refuses every reuse of the random_id the
			// same way, so treating it as a failure retried it on every
			// sweep until MaxPendingAge, then marked a delivered
			// notification failed (#1029). It is delivered; the id is
			// looked up, and stays unknown (NULL) without a single match.
			slog.Warn("notifier: retry found the notification already delivered", "notification_id", notif.ID)
			msgID, serr = n.locateDelivered(ctx, notif, text), nil
		}
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
		if notif.Kind == db.NotificationHumanInput {
			n.recordHumanInputSent(ctx, notif, msgID)
		}
		delivered++
	}
	return delivered, failed, nil
}

// fenceSkip logs a fence refusal and reports whether it counts as a failed
// delivery. A deterministic block (ErrSendBlocked) is a pending state and is
// not counted, like the kill switch at sweep entry; an unverifiable state is
// counted as failed. Neither marks the row sent or failed.
func (n *Notifier) fenceSkip(notif db.OwnerNotification, err error) (counted bool) {
	if errors.Is(err, ErrSendBlocked) {
		slog.Info("notifier: send blocked, row left pending", "notification_id", notif.ID, "kind", notif.Kind, "err", err)
		return false
	}
	slog.Warn("notifier: send authorization unverifiable, row left pending", "notification_id", notif.ID, "kind", notif.Kind, "err", err)
	return true
}

// locateDelivered asks the SelfSender, when it can, for the id of a
// notification Telegram reported as a duplicate. Any failure leaves it 0
// (unknown): the delivery itself is proven by the duplicate refusal.
func (n *Notifier) locateDelivered(ctx context.Context, notif db.OwnerNotification, text string) int64 {
	locator, ok := n.Sender.(SelfDeliveryLocator)
	if !ok {
		return 0
	}
	id, found, err := locator.LocateSelfDelivered(ctx, notif.UserID, text, notif.CreatedAt)
	if err != nil {
		slog.Warn("notifier: could not look up the delivered notification id", "notification_id", notif.ID, "err", err)
		return 0
	}
	if !found {
		return 0
	}
	return id
}

// recordHumanInputSent writes the Telegram message id back onto the
// human-input delivery row (queued -> sent) and counts the delivery. Failure
// here never undoes the send: the message is already in Saved Messages and
// the notification row is already marked sent. Follow-up notifications carry
// no delivery row, so found=false is normal for them.
func (n *Notifier) recordHumanInputSent(ctx context.Context, notif db.OwnerNotification, msgID int64) {
	createdAt, found, err := n.Store.SetHumanInputDeliveryMessageID(ctx, notif.ID, msgID)
	if err != nil {
		slog.Warn("notifier: human input delivery write-back failed", "notification_id", notif.ID, "err", err)
		n.Metrics.CountHumanInputEvent(metrics.HumanInputEventDelivered, "error")
		return
	}
	if !found {
		return
	}
	n.Metrics.CountHumanInputEvent(metrics.HumanInputEventDelivered, "ok")
	n.Metrics.ObserveHumanInputDeliverLatency(time.Since(createdAt))
	slog.Info("human input delivered", "notification_id", notif.ID, "tg_message_id", msgID)
}

// newSelfRandomID draws a fresh Telegram RPC random_id from crypto/rand.
// Deliberately duplicated from internal/telegram's identical helper rather
// than exported and imported: this package must not depend on
// internal/telegram (see SelfSender's doc comment), matching
// executor.defaultRandomID's identical rationale.
func newSelfRandomID() (int64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(b[:])), nil
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
		//
		// Nothing the owner writes in Saved Messages reaches the agent, so
		// the notice says what the owner can actually do (#952): the model's
		// text alone used to invite a "tell me what to say" reply that went
		// nowhere. The footer is reserved before truncation, like the
		// approve/reject lines below.
		who, convID := n.peerLabel(ctx, action)
		footer := "\n\nThe agent cannot read a reply here. To act on this, write to the sender in that chat yourself (the agent then stops replying there)."
		if convID != 0 {
			footer = fmt.Sprintf("\n\nThe agent cannot read a reply here. To act on this, write to %s in that chat yourself (the agent then stops replying there). Details: /mctl show %d", who, convID)
		}
		return reserveTail("Owner input requested:\n\n", action.Payload, footer), nil
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
	// A Codex finding on #307 caught that this message carried no recipient
	// identity at all: with more than one pending draft, the owner had no
	// way to tell WHO would receive a given approval code's text before
	// authorizing it — approving is immediate and sends straight to the
	// action's linked peer. Best-effort: a lookup failure (e.g. the
	// conversation row was since deleted) degrades to the un-identified
	// prefix rather than failing the whole notification, since the
	// approve/reject codes are still the load-bearing part of this message.
	prefix := "Draft reply awaiting approval:\n"
	if who, convID := n.peerLabel(ctx, action); convID != 0 {
		prefix = fmt.Sprintf("Draft reply awaiting approval (to %s, conv #%d):\n", who, convID)
	}
	// Say why a reply that looks routine needs the owner (#989). The
	// reasons are the policy's, rewritten for the owner; the model's text
	// never goes into them.
	if reasons := policy.OwnerHoldReasons(action.PolicyReasons); len(reasons) > 0 {
		prefix += "Held because " + strings.Join(reasons, "; ") + ".\n"
	}
	prefix += "\n"
	return reserveTail(prefix, action.Payload, instructions), nil
}

// peerLabel names the action's conversation peer for an owner notice. A
// failed lookup (e.g. the conversation row was since deleted) returns
// convID 0 so callers fall back to an un-identified wording.
func (n *Notifier) peerLabel(ctx context.Context, action *db.AgentAction) (who string, convID int64) {
	if action.ConversationID == 0 {
		return "", 0
	}
	conv, err := n.Store.GetConversation(ctx, action.UserID, action.ConversationID)
	if err != nil {
		return "", 0
	}
	who = conv.PeerDisplayName
	if who == "" {
		who = conv.PeerUsername
	}
	if who == "" {
		who = fmt.Sprintf("peer %d", conv.PeerTGID)
	}
	return who, conv.ID
}

// reserveTail composes prefix+payload+tail within maxTelegramMessageLen,
// truncating only the payload so the tail (commands the owner acts on)
// always survives intact.
func reserveTail(prefix, body, tail string) string {
	marker := "[truncated]"
	budget := maxTelegramMessageLen - len([]rune(prefix)) - len([]rune(tail))
	payload := []rune(body)
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
	return prefix + string(payload) + tail
}
