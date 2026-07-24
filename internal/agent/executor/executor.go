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
	"strings"
	"sync"
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

// ErrApprovalExpired is returned by Approve when the code is still live
// (GetAgentActionByCode found it, still pending_approval) but has already
// sat past ApprovalTTL — see Approve's doc comment for why this check
// cannot simply be left to the async ExpireStaleAgentActions sweeper alone.
var ErrApprovalExpired = errors.New("approval code expired")

// ErrSendQueuedForRetry is returned by Approve when the initial Telegram
// send fails with a transient error. The action is deliberately left in
// `executing` (not reverted) for RecoverStuck to retry with the same
// random_id — this is NOT a failed approval, and callers (see
// control.Router.handleApprove) must not report it to the owner as one: the
// send is still queued and will very likely go out on its own within the
// recovery sweep's grace window.
var ErrSendQueuedForRetry = errors.New("send failed transiently, queued for automatic retry")

// Sender is the narrow interface the executor needs to actually deliver a
// reply. Implemented in cmd/server/agentwiring.go over telegram.ClientPool +
// telegram.SendToInputPeerWithRandomID; kept as an interface here so this
// package never imports internal/telegram directly and stays trivially
// testable with a fake.
type Sender interface {
	// SendWithRandomID delivers text to peerTGID on behalf of userID using
	// EXACTLY randomID as the MTProto random_id (never generated internally
	// — see the package doc for why that matters for crash recovery).
	// peerAccessHash is the conversation's stored Conversation.PeerAccessHash
	// — messages.* RPCs reject an InputPeerUser carrying a zero access_hash
	// with PEER_ID_INVALID, so a Sender implementation must build the peer
	// directly from this value rather than re-resolving the bare peerTGID
	// through a lookup that has no way to recover a hash it was never given.
	// Returns the server-assigned Telegram message id.
	SendWithRandomID(ctx context.Context, userID, peerTGID, peerAccessHash, randomID int64, text string) (int64, error)
}

// RandomIDSource abstracts random_id generation so tests can supply
// deterministic values without depending on crypto/rand timing.
type RandomIDSource func() (int64, error)

// RestrictedFieldChecker exposes the owner's YAML-configured restricted
// fields (never_auto_send / approval_required — see internal/agent/profile)
// so the executor can refuse to send a payload that echoes one, regardless
// of what the DB-backed policy engine decided: policy.Evaluate knows nothing
// about this profile, so this is the ONLY enforcement point for those two
// markers. An interface here so this package does not import
// internal/agent/profile, matching Sender's rationale.
type RestrictedFieldChecker interface {
	// MatchRestricted reports the first restricted field (if any) whose
	// value appears verbatim in text.
	MatchRestricted(text string) (key string, neverAutoSend, approvalRequired, matched bool)
}

// Executor holds the dependencies every method needs.
type Executor struct {
	Store       *db.Store
	Sender      Sender
	GlobalKill  func() bool // reads config.Config.AgentKillSwitch at call time, not a snapshot
	NewRandomID RandomIDSource
	// Profile is optional (nil ⇒ no restricted-field enforcement, matching
	// AGENT_PROFILE_PATH being optional — see cmd/server/main.go). When set,
	// every send checks the payload against it before the RPC fires.
	Profile RestrictedFieldChecker
	// ProfileOwnerTGID is the one Telegram account Profile's restricted
	// section actually belongs to (config.Config.AgentProfileOwnerTGID —
	// mctl-telegram is multi-tenant but AGENT_PROFILE_PATH loads a single
	// process-wide YAML file, see cmd/server/main.go). 0 means "not
	// configured" and disables the scoping check entirely, matching a nil
	// Profile. A Codex finding on #307 caught that restrictedFieldBlocks had
	// no such scoping at all: in a multi-tenant deployment, EVERY action —
	// regardless of which account it belonged to — was checked against this
	// one owner's private restricted values, so an unrelated tenant's
	// approved reply could be incorrectly denied whenever its text happened
	// to match a restricted value that has nothing to do with them.
	ProfileOwnerTGID int64
	// StuckGrace bounds RecoverStuck's sweep — an action must have sat in
	// executing with no update for at least this long before it is assumed
	// crashed rather than genuinely in flight in this same process.
	StuckGrace time.Duration
	// ApprovalTTL bounds how long a pending_approval action stays
	// approvable — 0 disables the check (matching tests that construct an
	// Executor directly). config.Config.AgentApprovalTTL's doc comment
	// already documents the async ExpireStaleAgentActions sweeper as the
	// mechanism that transitions a stale row to `expired`, but a Codex
	// finding on #307 caught that sweeper runs on its own minute-scale
	// interval (and could simply be failing) — with no check here, an
	// owner typing /mctl approve on a code that is already past the TTL
	// but hasn't been swept YET would still succeed, sending an
	// already-stale draft. Approve() re-checks the TTL itself instead of
	// relying solely on the sweeper having already caught up.
	ApprovalTTL time.Duration
	m           *metrics.Registry

	// stuckMu guards stuckSeen, the set of action IDs RecoverStuck has
	// already counted toward AgentExecutorRestartsTotal — see
	// trackNewlyStuck.
	stuckMu   sync.Mutex
	stuckSeen map[int64]struct{}
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
	// GetAgentActionByCode matches case-sensitively and documents that the
	// caller normalizes (see its doc comment) — codes are always minted
	// uppercase (approvalcode.go's alphabet), but an owner typing or pasting
	// one by hand on a phone keyboard may not preserve that case.
	code = strings.ToUpper(strings.TrimSpace(code))
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
	if e.ApprovalTTL > 0 && time.Since(action.UpdatedAt) > e.ApprovalTTL {
		// The row is still pending_approval — ExpireStaleAgentActions
		// hasn't reached it yet, or is currently failing — but it is
		// already past the configured TTL. Transition it ourselves rather
		// than sending an already-stale draft just because the async
		// sweeper hasn't caught up. Not a hard requirement that this call
		// wins its own CAS (someone else, e.g. the sweeper itself, may have
		// already expired it a moment earlier) — either way the row is no
		// longer approvable, so ErrApprovalExpired is correct regardless.
		if _, err := e.Store.ExpireAgentActionIfStale(ctx, userID, action.ID, e.ApprovalTTL); err != nil {
			return fmt.Errorf("expire stale approval: %w", err)
		}
		return ErrApprovalExpired
	}
	ok, err := e.Store.UpdateAgentActionStatus(ctx, userID, action.ID, db.ActionPendingApproval, db.ActionApproved)
	if err != nil {
		return fmt.Errorf("approve action: %w", err)
	}
	if !ok {
		return ErrLostRace
	}
	action.Status = db.ActionApproved
	// UpdateAgentActionStatus wrote updated_at = now() to the row but has no
	// return value to hand that timestamp back — refresh the in-memory copy
	// to match, or send()'s AgentApprovalLatencySeconds observation would
	// measure from when the row entered pending_approval (however long the
	// owner took to notice and type /mctl approve) instead of from the
	// approval itself, wildly overstating approval-to-send latency for any
	// draft that sat waiting for a while.
	action.UpdatedAt = time.Now().UTC()
	return e.send(ctx, *action)
}

// Reject is called for an owner's `/mctl reject <code>`.
func (e *Executor) Reject(ctx context.Context, userID int64, code string) error {
	code = strings.ToUpper(strings.TrimSpace(code))
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
	// Every error return between here and BeginExecutingAgentAction's
	// success leaves the action row untouched at `approved` — no CAS has
	// run yet to move it anywhere else. That means ProcessApproved's own
	// periodic sweep (matching status=approved, regardless of whether the
	// row got there via guarded-mode auto-insert or a manual /mctl
	// approve's CAS) will pick it up and retry on its own, exactly like
	// RecoverStuck does for a row already in `executing`. A Codex finding
	// on #307 caught that only the post-BeginExecutingAgentAction send
	// failure below was wrapped in ErrSendQueuedForRetry — these earlier
	// transient failures (profile/conversation load, random ID
	// generation, the CAS call itself) were left on the generic error
	// path, so control.Router.handleApprove reported them as "could not
	// approve" even though they're genuinely the same "queued, will retry"
	// case.
	profile, err := e.Store.GetAgentProfile(ctx, action.UserID)
	if err != nil {
		return fmt.Errorf("%w: load profile: %w", ErrSendQueuedForRetry, err)
	}
	conv, err := e.Store.GetConversation(ctx, action.UserID, action.ConversationID)
	if err != nil {
		return fmt.Errorf("%w: load conversation: %w", ErrSendQueuedForRetry, err)
	}
	// A Codex finding on #307 caught that this call never passed
	// RecentAgentSends at all, so overRate's slice was always empty and
	// MaxMsgsPerMinute was silently unenforced at send time — only
	// propose_reply's initial policy check (internal/agentapi) ever saw real
	// send history. Two guarded actions approved back-to-back before either
	// delivered could both send within the same minute even with
	// MaxMsgsPerMinute=1, since each one's own evaluation still saw zero
	// prior sends.
	recentSends, err := e.recentAgentSends(ctx, action.UserID, action.ConversationID, time.Now().Add(-time.Minute))
	if err != nil {
		return fmt.Errorf("%w: load recent sends: %w", ErrSendQueuedForRetry, err)
	}
	result := policy.Evaluate(policy.Input{
		Profile:      *profile,
		Conversation: *conv,
		Action: policy.Action{
			Type: action.ActionType, Intent: action.Intent, Text: action.Payload, PeerTGID: conv.PeerTGID,
		},
		RecentAgentSends: recentSends,
		GlobalKill:       e.GlobalKill(),
		Now:              time.Now(),
	})
	// A hard Deny always stops the send — RequireApproval is more subtle: it
	// is not a second vote against a row a HUMAN already approved via
	// /mctl approve (action.PolicyDecision == PolicyRequireApproval when it
	// was first proposed, meaning a person actually saw and approved this
	// exact draft), because Evaluate recomputes the SAME require-approval
	// reasons every time for observe mode / turn budget / intent-not-
	// allowlisted / rate-limit, none of which should re-litigate a decision
	// a person already made. But a row that reached `approved` WITHOUT any
	// human ever reviewing it (action.PolicyDecision == PolicyAllow —
	// propose_reply's own policy auto-approved it in guarded mode) has no
	// such decision to defer to: if the CURRENT re-evaluation says
	// RequireApproval — e.g. an earlier action in the same ProcessApproved
	// batch just exhausted MaxAutonomousTurns — nothing has actually
	// approved THIS send, and letting it through anyway is exactly the
	// guarded-mode bypass a Codex finding on #307 caught: two queued
	// PolicyAllow actions could both send under a one-turn budget instead of
	// the second correctly falling back to requiring approval. Treat that
	// case as a deny (fail closed) rather than inventing a re-queue path
	// this codebase has no precedent for.
	requireApprovalBypassesUnreviewedAllow := result.Decision == policy.RequireApproval && action.PolicyDecision == db.PolicyAllow
	if result.Decision == policy.Deny || requireApprovalBypassesUnreviewedAllow {
		if _, err := e.Store.UpdateAgentActionStatus(ctx, action.UserID, action.ID, db.ActionApproved, db.ActionDenied); err != nil {
			return fmt.Errorf("deny stale approval: %w", err)
		}
		if requireApprovalBypassesUnreviewedAllow {
			return fmt.Errorf("policy now requires approval for this never-reviewed auto-approved action: %s", strings.Join(result.Reasons, "; "))
		}
		return fmt.Errorf("policy denies at send time: %s", strings.Join(result.Reasons, "; "))
	}
	reason, blocked, err := e.restrictedFieldBlocks(ctx, action)
	if err != nil {
		return fmt.Errorf("%w: check restricted fields: %w", ErrSendQueuedForRetry, err)
	}
	if blocked {
		if _, err := e.Store.UpdateAgentActionStatus(ctx, action.UserID, action.ID, db.ActionApproved, db.ActionDenied); err != nil {
			return fmt.Errorf("deny restricted-field payload: %w", err)
		}
		return fmt.Errorf("owner profile blocks send: %s", reason)
	}

	randomID, err := e.NewRandomID()
	if err != nil {
		return fmt.Errorf("%w: generate random id: %w", ErrSendQueuedForRetry, err)
	}
	ok, err := e.Store.BeginExecutingAgentAction(ctx, action.UserID, action.ID, randomID)
	if err != nil {
		return fmt.Errorf("%w: begin executing: %w", ErrSendQueuedForRetry, err)
	}
	if !ok {
		// Genuinely terminal, not a retry case: something else (a second
		// /mctl approve, a takeover, the TTL sweep) already moved this row
		// off `approved` between Approve()'s own CAS and this one — there
		// is nothing left to retry, the row is decided.
		return ErrLostRace
	}

	text := action.Payload
	if sep := policy.DisclosureSep; profile.DisclosureText != "" {
		text = text + sep + profile.DisclosureText
	}
	tgMessageID, err := e.Sender.SendWithRandomID(ctx, action.UserID, conv.PeerTGID, conv.PeerAccessHash, randomID, text)
	if err != nil {
		// Leave the row in executing with its random_id intact — RecoverStuck
		// will retry the identical send once the grace window elapses. Do NOT
		// revert to approved here: a revert could let a second, independent
		// send race this one with a DIFFERENT random_id, defeating the
		// dedup guarantee this whole design relies on. Wrapped in
		// ErrSendQueuedForRetry (not a bare error) so the owner-facing path
		// (control.Router.handleApprove) can tell "approval failed" apart
		// from "actually queued, will retry" — this is genuinely the latter.
		return fmt.Errorf("%w: %w", ErrSendQueuedForRetry, err)
	}
	ok, err = e.Store.RecordAgentActionSent(ctx, action.UserID, action.ID, action.ConversationID, tgMessageID, text)
	if err != nil {
		return fmt.Errorf("record executed: %w", err)
	}
	if !ok {
		// Lost the CAS: another goroutine (a concurrent RecoverStuck sweep
		// hitting the same row, or an overlapping call) already recorded this
		// action executed. The Telegram send above is real and already
		// happened either way — what matters is not double-counting its
		// side effects below.
		return nil
	}
	if e.m != nil && action.PolicyDecision == db.PolicyRequireApproval {
		// A Codex finding on #307 caught this observation running
		// unconditionally, including when send() is called from
		// ProcessApproved for guarded-mode PolicyAllow actions — those never
		// received an owner /mctl approve at all, so they have no
		// "approval" whose latency this histogram is supposed to measure;
		// counting them just pollutes it with proposal-to-sweep delays that
		// have nothing to do with how long an owner took to decide.
		e.m.AgentApprovalLatencySeconds.Observe(time.Since(action.UpdatedAt).Seconds())
	}
	return nil
}

// recentAgentSends returns the timestamps of this conversation's agent-sent
// messages since `since`, for policy.Input.RecentAgentSends — mirrors
// agentapi.Server.recentAgentSends exactly (same query, same
// DirectionAgentOutgoing filter) since both packages need identical
// send-history semantics to enforce the SAME MaxMsgsPerMinute limit, but
// this package must not import internal/agentapi (see Sender's doc comment
// for the equivalent internal/telegram rationale).
func (e *Executor) recentAgentSends(ctx context.Context, userID, conversationID int64, since time.Time) ([]time.Time, error) {
	msgs, err := e.Store.ListConversationMessages(ctx, userID, conversationID, 50)
	if err != nil {
		return nil, err
	}
	var out []time.Time
	for _, m := range msgs {
		if m.Direction == db.DirectionAgentOutgoing && m.CreatedAt.After(since) {
			out = append(out, m.CreatedAt)
		}
	}
	return out, nil
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
		e.stuckMu.Lock()
		e.stuckSeen = nil
		e.stuckMu.Unlock()
		return 0, nil
	}
	if e.m != nil {
		if newly := e.trackNewlyStuck(stuck); newly > 0 {
			e.m.AgentExecutorRestartsTotal.Add(float64(newly))
		}
	} else {
		e.trackNewlyStuck(stuck)
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

// trackNewlyStuck updates the executor's memory of which action IDs were
// already observed stuck in a prior sweep and returns how many of the
// current batch are being seen as stuck for the first time. A normal
// transient send error deliberately leaves an action in `executing` for
// recoverOne to retry (see its own doc comment) — without this tracking, a
// single action that keeps failing would re-count as a "restart" on every
// sweep it's found in, even though the process never actually restarted
// (Codex finding on #307). Actions that drop out of the stuck list
// (recovered or otherwise resolved) are forgotten, so the tracked set never
// grows unbounded.
func (e *Executor) trackNewlyStuck(stuck []db.AgentAction) int {
	e.stuckMu.Lock()
	defer e.stuckMu.Unlock()
	next := make(map[int64]struct{}, len(stuck))
	newly := 0
	for _, a := range stuck {
		next[a.ID] = struct{}{}
		if _, seen := e.stuckSeen[a.ID]; !seen {
			newly++
		}
	}
	e.stuckSeen = next
	return newly
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
	// Re-check policy and the restricted-field gate before retrying, exactly
	// like send() does before its first attempt — the crash that left this
	// row in executing may have happened BEFORE the original RPC ever
	// reached Telegram, so this retry can be the first real delivery, not a
	// dedup no-op. A takeover, autopilot pause, or kill-switch flip during
	// the grace window must be able to stop that first real delivery the
	// same way it would have stopped a fresh send. Denying here when the
	// original attempt actually DID land is a bookkeeping mismatch only —
	// nothing un-sends a message that already reached the peer — but that
	// mismatch is strictly safer than skipping the deny check and letting a
	// vetoed reply out through the recovery path alone. Same reasoning
	// extends to RecentAgentSends (a Codex finding on #307): a rate limit
	// that has been exceeded by OTHER sends since this one got stuck must
	// still stop the retry if the original RPC never actually reached
	// Telegram.
	recentSends, err := e.recentAgentSends(ctx, action.UserID, action.ConversationID, time.Now().Add(-time.Minute))
	if err != nil {
		return fmt.Errorf("load recent sends: %w", err)
	}
	result := policy.Evaluate(policy.Input{
		Profile:      *profile,
		Conversation: *conv,
		Action: policy.Action{
			Type: action.ActionType, Intent: action.Intent, Text: action.Payload, PeerTGID: conv.PeerTGID,
		},
		RecentAgentSends: recentSends,
		GlobalKill:       e.GlobalKill(),
		Now:              time.Now(),
	})
	// Mirrors send()'s requireApprovalBypassesUnreviewedAllow exactly: a
	// PolicyAllow action (guarded-mode auto-approved, no human ever reviewed
	// this exact draft) whose CURRENT re-evaluation now says RequireApproval
	// — e.g. the account switched to observe mode, the intent was delisted,
	// or the turn budget was exhausted during StuckGrace — has no human
	// decision to defer to and must not be sent by the recovery path either.
	// A Codex finding on #307 caught that recoverOne only checked for a hard
	// Deny, so this exact escalation path (present in send() since an
	// earlier round) was missing here, letting a crashed-then-recovered
	// guarded action bypass a newly-required approval that a fresh send
	// through send() would have caught.
	requireApprovalBypassesUnreviewedAllow := result.Decision == policy.RequireApproval && action.PolicyDecision == db.PolicyAllow
	if result.Decision == policy.Deny || requireApprovalBypassesUnreviewedAllow {
		if _, err := e.Store.UpdateAgentActionStatus(ctx, action.UserID, action.ID, db.ActionExecuting, db.ActionDenied); err != nil {
			return fmt.Errorf("deny stale approval during recovery: %w", err)
		}
		if requireApprovalBypassesUnreviewedAllow {
			return fmt.Errorf("policy now requires approval for this never-reviewed auto-approved action during recovery: %s", strings.Join(result.Reasons, "; "))
		}
		return fmt.Errorf("policy denies at recovery time: %s", strings.Join(result.Reasons, "; "))
	}
	reason, blocked, err := e.restrictedFieldBlocks(ctx, action)
	if err != nil {
		return fmt.Errorf("check restricted fields during recovery: %w", err)
	}
	if blocked {
		if _, err := e.Store.UpdateAgentActionStatus(ctx, action.UserID, action.ID, db.ActionExecuting, db.ActionDenied); err != nil {
			return fmt.Errorf("deny restricted-field payload during recovery: %w", err)
		}
		return fmt.Errorf("owner profile blocks recovery send: %s", reason)
	}
	text := action.Payload
	if profile.DisclosureText != "" {
		text = text + policy.DisclosureSep + profile.DisclosureText
	}
	tgMessageID, err := e.Sender.SendWithRandomID(ctx, action.UserID, conv.PeerTGID, conv.PeerAccessHash, action.SendRandomID, text)
	if err != nil {
		return fmt.Errorf("retry send: %w", err)
	}
	ok, err := e.Store.RecordAgentActionSent(ctx, action.UserID, action.ID, action.ConversationID, tgMessageID, text)
	if err != nil {
		return fmt.Errorf("record executed: %w", err)
	}
	if !ok {
		// Lost the CAS: another sweep or an overlapping send() call already
		// recorded this action executed. The retried send above is a real,
		// harmless MTProto dedup no-op either way — what matters is not
		// double-counting turns/latency below for a completion someone else
		// already recorded.
		return nil
	}
	// A recovery send IS the completion of a previously-approved action — it
	// should count the same way send()'s does, not be silently excluded.
	// Crashed sends are exactly the cases whose latency is most likely to be
	// anomalously high, so omitting them would bias the metric toward
	// looking healthier than it is.
	if e.m != nil && action.PolicyDecision == db.PolicyRequireApproval {
		// Same restriction as send() (a Codex finding on #307): only count
		// actions that actually went through a human /mctl approve.
		e.m.AgentApprovalLatencySeconds.Observe(time.Since(action.UpdatedAt).Seconds())
	}
	return nil
}

// restrictedFieldBlocks reports whether action's payload must be blocked by
// the owner's restricted-field markers (internal/agent/profile), which the
// DB-backed policy engine has no notion of. never_auto_send always blocks —
// not even an owner-approved reply may include it verbatim, only the owner
// typing it themselves satisfies that marker, and this executor never sends
// anything the owner typed directly. approval_required only blocks when the
// action never actually went through a human's /mctl approve: PolicyAllow
// means propose_reply's own policy auto-approved it in guarded mode with no
// owner ever seeing the draft; PolicyRequireApproval means it did.
func (e *Executor) restrictedFieldBlocks(ctx context.Context, action db.AgentAction) (reason string, blocked bool, err error) {
	if e.Profile == nil {
		return "", false, nil
	}
	if e.ProfileOwnerTGID != 0 {
		// AGENT_PROFILE_OWNER_TG_ID is a Telegram account id, while
		// action.UserID is the internal users.id — these are different ID
		// namespaces that normally never carry the same numeric value, so
		// comparing them directly (as an earlier version of this check did)
		// meant the scope check always evaluated as "not the owner" — even
		// for the configured owner's own actions — and silently disabled
		// restricted-field enforcement entirely rather than merely scoping
		// it (Codex finding on #307). Resolve the action owner's actual
		// Telegram id before comparing.
		ownerTGID, err := e.Store.GetTelegramID(ctx, action.UserID)
		if err != nil {
			return "", false, fmt.Errorf("resolve action owner telegram id: %w", err)
		}
		if ownerTGID != e.ProfileOwnerTGID {
			return "", false, nil
		}
	}
	key, neverAutoSend, approvalRequired, matched := e.Profile.MatchRestricted(action.Payload)
	if !matched {
		return "", false, nil
	}
	if neverAutoSend {
		return fmt.Sprintf("payload echoes never_auto_send restricted field %q", key), true, nil
	}
	if approvalRequired && action.PolicyDecision != db.PolicyRequireApproval {
		return fmt.Sprintf("payload echoes approval_required restricted field %q without owner review", key), true, nil
	}
	return "", false, nil
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
