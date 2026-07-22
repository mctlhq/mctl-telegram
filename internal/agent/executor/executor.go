// Package executor turns an approved communication-agent action into an
// actual Telegram send. It is the only code path in this repo that sends a
// reply on the agent's behalf — everything before it (policy, propose_reply,
// the owner's /mctl approve) only ever decides whether a send may happen.
//
// Crash safety: a Telegram send_random_id is persisted on the action row
// BEFORE the send RPC fires (Store.BeginExecutingAgentAction), so a process
// restart while an action is `executing` is recovered by retrying the exact
// same send with the exact same random_id — MTProto dedups on it
// server-side, making the retry a safe no-op if the original send actually
// reached Telegram. See RecoverStuck.
package executor

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// ErrApprovalCodeNotFound is returned by Approve/Reject when no live action
// carries the given code (wrong code, already decided, or expired).
var ErrApprovalCodeNotFound = errors.New("approval code not found")

// ErrLostRace is returned when a CAS transition finds the action no longer
// in the expected state — someone else (a second /mctl approve, a takeover,
// the TTL sweep) already decided it.
var ErrLostRace = errors.New("action state changed concurrently")

// Sender is the narrow interface the executor needs to actually deliver a
// reply. Implemented in cmd/server/main.go over telegram.ClientPool +
// telegram.SendMessageWithRandomID; kept as an interface here so this
// package never imports internal/telegram directly and stays trivially
// testable with a fake.
type Sender interface {
	// SendWithRandomID delivers text to peerTGID on behalf of userID using
	// EXACTLY randomID as the MTProto random_id (never generated internally
	// — see the package doc for why that matters for crash recovery).
	// Returns the server-assigned Telegram message id.
	SendWithRandomID(ctx context.Context, userID, peerTGID, randomID int64, text string) (int64, error)
}

// RandomIDSource abstracts random_id generation so tests can supply
// deterministic values without depending on crypto/rand timing.
type RandomIDSource func() (int64, error)

// Executor holds the dependencies every method needs.
type Executor struct {
	Store       *db.Store
	Sender      Sender
	GlobalKill  func() bool // reads config.Config.AgentKillSwitch at call time, not a snapshot
	NewRandomID RandomIDSource
	// StuckGrace bounds RecoverStuck's sweep — an action must have sat in
	// executing with no update for at least this long before it is assumed
	// crashed rather than genuinely in flight in this same process.
	StuckGrace time.Duration
	m          *metrics.Registry
}

// New constructs an Executor. m may be nil (tests).
func New(store *db.Store, sender Sender, globalKill func() bool, m *metrics.Registry) *Executor {
	return &Executor{
		Store:       store,
		Sender:      sender,
		GlobalKill:  globalKill,
		NewRandomID: defaultRandomID,
		StuckGrace:  2 * time.Minute,
		m:           m,
	}
}

// Approve is called for an owner's `/mctl approve <code>`. It re-checks
// policy (approval and send are not atomic — state can change in between:
// takeover, autopilot pause, kill switch, a rate limit newly exceeded) and,
// if still allowed, sends immediately.
func (e *Executor) Approve(ctx context.Context, userID int64, code string) error {
	action, err := e.Store.GetAgentActionByCode(ctx, userID, code)
	if errors.Is(err, db.ErrAgentActionNotFound) {
		return ErrApprovalCodeNotFound
	}
	if err != nil {
		return fmt.Errorf("lookup action by code: %w", err)
	}
	if action.Status != db.ActionPendingApproval {
		return fmt.Errorf("%w: action is %s, not pending_approval", ErrLostRace, action.Status)
	}
	ok, err := e.Store.UpdateAgentActionStatus(ctx, userID, action.ID, db.ActionPendingApproval, db.ActionApproved)
	if err != nil {
		return fmt.Errorf("approve action: %w", err)
	}
	if !ok {
		return ErrLostRace
	}
	action.Status = db.ActionApproved
	return e.send(ctx, *action)
}

// Reject is called for an owner's `/mctl reject <code>`.
func (e *Executor) Reject(ctx context.Context, userID int64, code string) error {
	action, err := e.Store.GetAgentActionByCode(ctx, userID, code)
	if errors.Is(err, db.ErrAgentActionNotFound) {
		return ErrApprovalCodeNotFound
	}
	if err != nil {
		return fmt.Errorf("lookup action by code: %w", err)
	}
	ok, err := e.Store.UpdateAgentActionStatus(ctx, userID, action.ID, db.ActionPendingApproval, db.ActionRejected)
	if err != nil {
		return fmt.Errorf("reject action: %w", err)
	}
	if !ok {
		return ErrLostRace
	}
	return nil
}

// ProcessApproved sends every action already sitting in `approved` — the
// guarded-mode auto-send path (propose_reply inserts these directly, no
// owner ever types /mctl approve for them). System-wide, matching the other
// background sweeps in this codebase (RequeueStaleAgentJobs,
// ExpireStaleAgentActions); call it periodically from a goroutine in
// cmd/server/main.go. Returns the number processed; per-action errors are
// logged, not returned, so one bad action cannot block the rest of the
// batch.
func (e *Executor) ProcessApproved(ctx context.Context) (int, error) {
	actions, err := e.Store.ListActionsByStatus(ctx, db.ActionApproved, 50)
	if err != nil {
		return 0, fmt.Errorf("list approved actions: %w", err)
	}
	for _, a := range actions {
		if err := e.send(ctx, a); err != nil {
			slog.Warn("executor: guarded auto-send failed", "action_id", a.ID, "user_id", a.UserID, "err", err)
		}
	}
	return len(actions), nil
}

// send re-checks policy immediately before the send RPC and, if still
// allowed, transitions approved -> executing (persisting send_random_id in
// that same atomic update) -> executed. If policy now denies, the action is
// moved to denied instead of sent — a stale approval must not bypass a deny
// condition that has since become true.
func (e *Executor) send(ctx context.Context, action db.AgentAction) error {
	profile, err := e.Store.GetAgentProfile(ctx, action.UserID)
	if err != nil {
		return fmt.Errorf("load profile: %w", err)
	}
	conv, err := e.Store.GetConversation(ctx, action.UserID, action.ConversationID)
	if err != nil {
		return fmt.Errorf("load conversation: %w", err)
	}
	result := policy.Evaluate(policy.Input{
		Profile:      *profile,
		Conversation: *conv,
		Action: policy.Action{
			Type: action.ActionType, Intent: action.Intent, Text: action.Payload, PeerTGID: conv.PeerTGID,
		},
		GlobalKill: e.GlobalKill(),
		Now:        time.Now(),
	})
	// Only a hard Deny stops the send here — RequireApproval is not a second
	// vote against a row that is already `approved`. Evaluate has no notion
	// of "a human already approved this specific action"; it recomputes the
	// SAME require-approval reasons every time for observe mode / turn
	// budget / intent-not-allowlisted / rate-limit, none of which should
	// re-litigate a decision the owner (or guarded-mode auto-approval)
	// already made. Deny conditions (kill switch, mode off, autopilot
	// paused, taken over, blocked sender, peer mismatch, disclosure/length/
	// URL/credential checks) are different: those are hard stops that must
	// re-fire even on an already-approved row if they turned true since
	// approval.
	if result.Decision == policy.Deny {
		if _, err := e.Store.UpdateAgentActionStatus(ctx, action.UserID, action.ID, db.ActionApproved, db.ActionDenied); err != nil {
			return fmt.Errorf("deny stale approval: %w", err)
		}
		return fmt.Errorf("policy denies at send time: %s", result.Reasons)
	}

	randomID, err := e.NewRandomID()
	if err != nil {
		return fmt.Errorf("generate random id: %w", err)
	}
	ok, err := e.Store.BeginExecutingAgentAction(ctx, action.UserID, action.ID, randomID)
	if err != nil {
		return fmt.Errorf("begin executing: %w", err)
	}
	if !ok {
		return ErrLostRace
	}

	text := action.Payload
	if sep := policy.DisclosureSep; profile.DisclosureText != "" {
		text = text + sep + profile.DisclosureText
	}
	tgMessageID, err := e.Sender.SendWithRandomID(ctx, action.UserID, conv.PeerTGID, randomID, text)
	if err != nil {
		// Leave the row in executing with its random_id intact — RecoverStuck
		// will retry the identical send once the grace window elapses. Do NOT
		// revert to approved here: a revert could let a second, independent
		// send race this one with a DIFFERENT random_id, defeating the
		// dedup guarantee this whole design relies on.
		return fmt.Errorf("send: %w", err)
	}
	if _, err := e.Store.SetAgentActionExecuted(ctx, action.UserID, action.ID, tgMessageID); err != nil {
		return fmt.Errorf("record executed: %w", err)
	}
	if err := e.Store.IncrementAutonomousTurns(ctx, action.UserID, action.ConversationID); err != nil {
		slog.Warn("executor: increment autonomous turns failed", "action_id", action.ID, "err", err)
	}
	if e.m != nil {
		e.m.AgentApprovalLatencySeconds.Observe(time.Since(action.UpdatedAt).Seconds())
	}
	return nil
}

// RecoverStuck retries every action found stuck in executing past
// StuckGrace — the crash-recovery sweep. Call periodically (e.g. every
// StuckGrace/2) from a goroutine in cmd/server/main.go. Returns the number
// found stuck (retried, successfully or not); a nonzero count is logged and
// gauged (AgentActionsExecutingStuck) because it is a genuine signal
// something crashed or a send is persistently failing — it is never
// expected noise.
func (e *Executor) RecoverStuck(ctx context.Context) (int, error) {
	stuck, err := e.Store.ListStuckExecutingActions(ctx, e.StuckGrace)
	if err != nil {
		return 0, fmt.Errorf("list stuck executing actions: %w", err)
	}
	if e.m != nil {
		e.m.AgentActionsExecutingStuck.Set(float64(len(stuck)))
	}
	if len(stuck) == 0 {
		return 0, nil
	}
	if e.m != nil {
		e.m.AgentExecutorRestartsTotal.Inc()
	}
	slog.Warn("executor: recovering stuck executing actions", "count", len(stuck))
	for _, a := range stuck {
		if err := e.recoverOne(ctx, a); err != nil {
			slog.Warn("executor: recovery send failed, will retry next sweep",
				"action_id", a.ID, "user_id", a.UserID, "err", err)
		}
	}
	return len(stuck), nil
}

// recoverOne retries the exact send an interrupted executing row was mid-way
// through, using its already-persisted random_id — never a fresh one.
func (e *Executor) recoverOne(ctx context.Context, action db.AgentAction) error {
	if action.SendRandomID == 0 {
		// Should be unreachable: BeginExecutingAgentAction always persists a
		// random_id in the same statement that sets status=executing. Refuse
		// to invent one here rather than silently risking a duplicate send
		// under a scenario this code does not understand.
		return fmt.Errorf("action %d is executing with no send_random_id", action.ID)
	}
	conv, err := e.Store.GetConversation(ctx, action.UserID, action.ConversationID)
	if err != nil {
		return fmt.Errorf("load conversation: %w", err)
	}
	profile, err := e.Store.GetAgentProfile(ctx, action.UserID)
	if err != nil {
		return fmt.Errorf("load profile: %w", err)
	}
	text := action.Payload
	if profile.DisclosureText != "" {
		text = text + policy.DisclosureSep + profile.DisclosureText
	}
	tgMessageID, err := e.Sender.SendWithRandomID(ctx, action.UserID, conv.PeerTGID, action.SendRandomID, text)
	if err != nil {
		return fmt.Errorf("retry send: %w", err)
	}
	if _, err := e.Store.SetAgentActionExecuted(ctx, action.UserID, action.ID, tgMessageID); err != nil {
		return fmt.Errorf("record executed: %w", err)
	}
	if err := e.Store.IncrementAutonomousTurns(ctx, action.UserID, action.ConversationID); err != nil {
		slog.Warn("executor: increment autonomous turns failed", "action_id", action.ID, "err", err)
	}
	return nil
}

// defaultRandomID draws a fresh Telegram RPC random_id from crypto/rand.
// Deliberately duplicated from internal/telegram's identical helper rather
// than exported and imported: this package must not depend on
// internal/telegram (see Sender's doc comment) so it stays trivially
// testable with a fake sender.
func defaultRandomID() (int64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(b[:])), nil
}
