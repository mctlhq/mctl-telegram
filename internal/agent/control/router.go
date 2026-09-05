package control

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Approver is the subset of *executor.Executor the router needs for /mctl
// approve|reject — an interface (rather than a direct *executor.Executor
// field) purely to keep Router trivially testable with a fake. This
// package still imports executor directly for its two sentinel errors
// (ErrApprovalCodeNotFound, ErrLostRace) so approverErrText can render a
// useful owner-facing message; executor has no reciprocal dependency on
// control, so this is a one-way edge, not a cycle.
type Approver interface {
	Approve(ctx context.Context, userID int64, code string) error
	Reject(ctx context.Context, userID int64, code string) error
}

// Router implements listener.CommandRouter (HandleSavedText) — the concrete
// handler wired into listener.New in cmd/server/main.go, replacing the nil
// placeholder every earlier communication-agent PR shipped with.
type Router struct {
	Store    *db.Store
	Executor Approver
	Notifier *Notifier
}

// NewRouter constructs a Router.
func NewRouter(store *db.Store, executor Approver, notifier *Notifier) *Router {
	return &Router{Store: store, Executor: executor, Notifier: notifier}
}

// HandleSavedText implements listener.CommandRouter. The listener has
// already confirmed text starts with /mctl (isMCTLCommand) before ever
// calling this — errors from ParseCommand here are almost always a bad
// subcommand or a missing argument, not a false trigger.
func (r *Router) HandleSavedText(ctx context.Context, userID int64, text string) error {
	cmd, err := ParseCommand(text)
	if err != nil {
		return r.Notifier.Reply(ctx, userID, "Unknown command. Try:\n/mctl status\n/mctl leads\n/mctl conversations\n/mctl show <id>\n/mctl continue <id>\n/mctl pause\n/mctl takeover <id>\n/mctl approve <code>\n/mctl reject <code>")
	}
	switch cmd.Type {
	case CmdStatus:
		return r.handleStatus(ctx, userID)
	case CmdLeads:
		return r.handleLeads(ctx, userID)
	case CmdConversations:
		return r.handleConversations(ctx, userID)
	case CmdShow:
		return r.handleShow(ctx, userID, cmd.Arg)
	case CmdContinue:
		return r.handleContinue(ctx, userID, cmd.Arg)
	case CmdPause:
		return r.handlePause(ctx, userID)
	case CmdTakeover:
		return r.handleTakeover(ctx, userID, cmd.Arg)
	case CmdApprove:
		return r.handleApprove(ctx, userID, cmd.Arg)
	case CmdReject:
		return r.handleReject(ctx, userID, cmd.Arg)
	}
	return nil
}

func (r *Router) handleStatus(ctx context.Context, userID int64) error {
	profile, err := r.Store.GetAgentProfile(ctx, userID)
	if errors.Is(err, db.ErrAgentProfileNotFound) {
		return r.Notifier.Reply(ctx, userID, "No agent profile configured for this account.")
	}
	if err != nil {
		return fmt.Errorf("load profile: %w", err)
	}
	paused := "no"
	if profile.AutopilotPaused {
		paused = "yes"
	}
	return r.Notifier.Reply(ctx, userID, fmt.Sprintf(
		"Mode: %s\nAutopilot paused: %s\nMax autonomous turns: %d\nMax messages/min: %d",
		profile.Mode, paused, profile.MaxAutonomousTurns, profile.MaxMsgsPerMinute,
	))
}

func (r *Router) handleLeads(ctx context.Context, userID int64) error {
	leads, err := r.Store.ListJobLeads(ctx, userID, 20)
	if err != nil {
		return fmt.Errorf("list leads: %w", err)
	}
	if len(leads) == 0 {
		return r.Notifier.Reply(ctx, userID, "No leads yet.")
	}
	var sb strings.Builder
	sb.WriteString("Recent leads:\n")
	for _, l := range leads {
		// l.ConversationID, not l.ID (job_leads.id) — /mctl show takes a
		// conversation id, and the two are different sequences. Showing the
		// lead's own id here would send the owner to look up the wrong row.
		// A missing conversation row is a real, expected state (the lead
		// outlived it) and a dash is the honest answer for it. Any other error
		// is a live DB failure: propagate it rather than rendering a list of
		// dashes that reads like a successful answer.
		name := "—"
		conv, err := r.Store.GetConversation(ctx, userID, l.ConversationID)
		switch {
		case err == nil:
			name = orDash(conv.PeerDisplayName)
		case errors.Is(err, db.ErrConversationNotFound):
			// conversation row is gone; keep the dash.
		default:
			return fmt.Errorf("get conversation %d: %w", l.ConversationID, err)
		}
		fmt.Fprintf(&sb, "Conv #%d — %s — %s / %s (%s)\n", l.ConversationID, name, orDash(l.Company), orDash(l.Role), l.Status)
	}
	sb.WriteString("\n/mctl show <conversation id> for details")
	return r.Notifier.Reply(ctx, userID, sb.String())
}

func (r *Router) handleConversations(ctx context.Context, userID int64) error {
	convs, err := r.Store.ListConversations(ctx, userID, 20)
	if err != nil {
		return fmt.Errorf("list conversations: %w", err)
	}
	if len(convs) == 0 {
		return r.Notifier.Reply(ctx, userID, "No conversations yet.")
	}
	var sb strings.Builder
	sb.WriteString("Recent conversations:\n")
	for _, c := range convs {
		fmt.Fprintf(&sb, "Conv #%d — %s (%s)\n", c.ID, orDash(c.PeerDisplayName), c.State)
	}
	sb.WriteString("\n/mctl show <conversation id> for details")
	return r.Notifier.Reply(ctx, userID, sb.String())
}

func (r *Router) handleShow(ctx context.Context, userID int64, arg string) error {
	convID, err := r.resolveConversationID(ctx, userID, arg)
	if errors.Is(err, errNotAReference) {
		return r.Notifier.Reply(ctx, userID, "Usage: /mctl show <conversation id> | user:<id> | @username")
	}
	if errors.Is(err, db.ErrConversationNotFound) {
		return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Conversation %s not found.", arg))
	}
	if err != nil {
		return fmt.Errorf("resolve conversation: %w", err)
	}
	conv, err := r.Store.GetConversation(ctx, userID, convID)
	if errors.Is(err, db.ErrConversationNotFound) {
		return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Conversation %d not found.", convID))
	}
	if err != nil {
		return fmt.Errorf("load conversation: %w", err)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Conversation #%d — %s\nState: %s | Autonomous turns: %d\n",
		conv.ID, orDash(conv.PeerDisplayName), conv.State, conv.AutonomousTurns)
	if lead, err := r.Store.GetJobLeadByConversation(ctx, userID, convID); err == nil {
		fmt.Fprintf(&sb, "\nLead: %s / %s (%s)\n", orDash(lead.Company), orDash(lead.Role), lead.Status)
	} else if !errors.Is(err, db.ErrJobLeadNotFound) {
		return fmt.Errorf("load lead: %w", err)
	}
	return r.Notifier.Reply(ctx, userID, sb.String())
}

func (r *Router) handleContinue(ctx context.Context, userID int64, arg string) error {
	convID, err := r.resolveConversationID(ctx, userID, arg)
	if errors.Is(err, errNotAReference) {
		return r.Notifier.Reply(ctx, userID, "Usage: /mctl continue <conversation id> | user:<id> | @username")
	}
	if errors.Is(err, db.ErrConversationNotFound) {
		return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Conversation %s not found.", arg))
	}
	if err != nil {
		return fmt.Errorf("resolve conversation: %w", err)
	}
	// Continuing un-does a takeover (explicit or listener-detected) and
	// grants the agent a fresh autonomous-turn budget — matches
	// ResetAutonomousTurns' documented purpose.
	if err := r.Store.SetConversationState(ctx, userID, convID, db.ConversationActive); err != nil {
		if errors.Is(err, db.ErrConversationNotFound) {
			return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Conversation %d not found.", convID))
		}
		return fmt.Errorf("set conversation active: %w", err)
	}
	if err := r.Store.ResetAutonomousTurns(ctx, userID, convID); err != nil {
		return fmt.Errorf("reset autonomous turns: %w", err)
	}
	return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Conversation %d resumed — agent may reply again.", convID))
}

func (r *Router) handlePause(ctx context.Context, userID int64) error {
	if err := r.Store.SetAgentAutopilotPaused(ctx, userID, true); err != nil {
		if errors.Is(err, db.ErrAgentProfileNotFound) {
			return r.Notifier.Reply(ctx, userID, "No agent profile configured for this account.")
		}
		return fmt.Errorf("pause autopilot: %w", err)
	}
	return r.Notifier.Reply(ctx, userID, "Autopilot paused. /mctl continue <id> resumes a specific conversation once you're ready — autopilot itself stays paused until you re-enable it via the agent API.")
}

func (r *Router) handleTakeover(ctx context.Context, userID int64, arg string) error {
	convID, err := r.resolveConversationID(ctx, userID, arg)
	if errors.Is(err, errNotAReference) {
		return r.Notifier.Reply(ctx, userID, "Usage: /mctl takeover <conversation id> | user:<id> | @username")
	}
	if errors.Is(err, db.ErrConversationNotFound) {
		return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Conversation %s not found.", arg))
	}
	if err != nil {
		return fmt.Errorf("resolve conversation: %w", err)
	}
	if err := r.Store.SetConversationState(ctx, userID, convID, db.ConversationTakenOver); err != nil {
		if errors.Is(err, db.ErrConversationNotFound) {
			return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Conversation %d not found.", convID))
		}
		return fmt.Errorf("set conversation taken over: %w", err)
	}
	// Deny any pending/approved reply immediately rather than waiting for the
	// executor's send-time re-check to catch it — an explicit takeover
	// command should visibly stop a queued reply right away.
	if _, err := r.Store.DenyPendingActionsForConversation(ctx, userID, convID, "owner took over via /mctl takeover"); err != nil {
		return fmt.Errorf("deny pending actions: %w", err)
	}
	return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Took over conversation %d — agent will stay silent until /mctl continue %d.", convID, convID))
}

func (r *Router) handleApprove(ctx context.Context, userID int64, code string) error {
	code = normalizeApprovalCode(code)
	err := r.Executor.Approve(ctx, userID, code)
	switch {
	case err == nil:
		return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Approved and sent (%s).", code))
	case errors.Is(err, executor.ErrSendQueuedForRetry):
		// The action is genuinely approved and left executing for
		// RecoverStuck to retry — NOT a failed approval. Telling the owner
		// "could not approve" here would be actively misleading: the
		// message will very likely still go out on its own shortly after.
		return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Approved (%s) — the send hit a transient error and is queued for automatic retry; it should go out shortly.", code))
	default:
		return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Could not approve %s: %s", code, approverErrText(err)))
	}
}

func (r *Router) handleReject(ctx context.Context, userID int64, code string) error {
	code = normalizeApprovalCode(code)
	if err := r.Executor.Reject(ctx, userID, code); err != nil {
		return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Could not reject %s: %s", code, approverErrText(err)))
	}
	return r.Notifier.Reply(ctx, userID, fmt.Sprintf("Rejected %s.", code))
}

// normalizeApprovalCode uppercases and trims an owner-typed approval code.
// GetAgentActionByCode documents case-sensitive matching and expects the
// caller to normalize — codes are generated uppercase-only (see
// agentapi.newApprovalCode's alphabet), so a phone keyboard autocorrecting
// "/mctl approve AB12CD" to "Ab12cd" would otherwise get a confusing "code
// not found" reply for a code that is actually live (Codex finding, #307).
func normalizeApprovalCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

// approverErrText renders an executor error as owner-facing text without
// leaking internal wrapping detail — the owner only needs to know "wrong
// code" vs "already handled" vs a generic failure.
func approverErrText(err error) string {
	switch {
	case errors.Is(err, executor.ErrApprovalCodeNotFound):
		return "code not found or already used"
	case errors.Is(err, executor.ErrApprovalExpired):
		return "this draft expired before it was approved — too old to send now"
	case errors.Is(err, executor.ErrLostRace):
		return "already resolved (approved, rejected, or expired) by the time this was processed"
	default:
		return "an internal error occurred"
	}
}

// errNotAReference means arg is neither a plain numeric conversation id nor
// a recognized peer reference (user:<telegram id> or @username) —
// resolveConversationID never even attempted a store lookup, so the caller
// should reply with usage text rather than a "not found" message.
var errNotAReference = errors.New("not a conversation reference")

// resolveConversationID turns a /mctl show|continue|takeover argument into a
// conversation id. A plain numeric id is returned as-is without a store
// lookup here — unchanged from the pre-existing behavior, so an id that
// doesn't exist is still reported by the caller's own store call as
// db.ErrConversationNotFound. A user:<telegram id> or @username reference is
// resolved against the already-persisted conversations table; no live
// Telegram/MTProto RPC is made.
func (r *Router) resolveConversationID(ctx context.Context, userID int64, arg string) (int64, error) {
	if id, err := strconv.ParseInt(arg, 10, 64); err == nil {
		return id, nil
	}
	switch {
	case strings.HasPrefix(arg, "user:"):
		peerTGID, err := strconv.ParseInt(strings.TrimPrefix(arg, "user:"), 10, 64)
		if err != nil {
			return 0, db.ErrConversationNotFound
		}
		conv, err := r.Store.GetConversationByPeer(ctx, userID, peerTGID)
		if err != nil {
			return 0, err
		}
		return conv.ID, nil
	case strings.HasPrefix(arg, "@"):
		conv, err := r.Store.GetConversationByUsername(ctx, userID, strings.TrimPrefix(arg, "@"))
		if err != nil {
			return 0, err
		}
		return conv.ID, nil
	default:
		return 0, errNotAReference
	}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
