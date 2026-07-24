package executor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// fakeSender records every call and lets tests control success/failure and
// inspect exactly which random_id was used — the load-bearing detail for
// every crash-recovery test in this file.
type fakeSender struct {
	mu        sync.Mutex
	calls     []sendCall
	failNext  int // fail this many upcoming calls, then succeed
	nextMsgID int64
}

type sendCall struct {
	userID, peerTGID, peerAccessHash, randomID int64
	text                                       string
}

func (f *fakeSender) SendWithRandomID(_ context.Context, userID, peerTGID, peerAccessHash, randomID int64, text string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, sendCall{userID, peerTGID, peerAccessHash, randomID, text})
	if f.failNext > 0 {
		f.failNext--
		return 0, errSendFailed
	}
	f.nextMsgID++
	return f.nextMsgID, nil
}

var errSendFailed = &sendErr{"send failed"}

type sendErr struct{ msg string }

func (e *sendErr) Error() string { return e.msg }

func testKey() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func newTestExecutor(t *testing.T) (*Executor, *fakeSender, *db.Store, int64, *db.Conversation) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	crypt, err := crypto.New(testKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	store := db.NewStore(conn, crypt)
	uid, err := store.EnsureUser(ctx, "owner", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: uid, Mode: db.AgentModeGuarded, DisclosureText: "I'm an AI assistant.",
	}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	conv, err := store.EnsureConversation(ctx, uid, 555, "peer", "Peer")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	sender := &fakeSender{}
	killed := false
	exec := New(store, sender, func() bool { return killed }, nil)
	exec.StuckGrace = 0 // tests want stuck actions eligible immediately
	return exec, sender, store, uid, conv
}

func seedPendingApproval(t *testing.T, store *db.Store, uid, convID int64, text string) (actionID int64, code string) {
	t.Helper()
	actionID, err := store.InsertAgentAction(context.Background(), db.AgentAction{
		ConversationID: convID, UserID: uid, ActionType: db.ActionTypeReply,
		Payload: text, PolicyDecision: db.PolicyRequireApproval, PolicyReasons: "observe mode",
		Status: db.ActionPendingApproval, ApprovalCode: "TESTCD",
	})
	if err != nil {
		t.Fatalf("seed pending action: %v", err)
	}
	return actionID, "TESTCD"
}

func TestExecutor_Approve_SendsAndMarksExecuted(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "Thanks for reaching out!")

	if err := exec.Approve(ctx, uid, code); err != nil {
		t.Fatalf("approve: %v", err)
	}

	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionExecuted {
		t.Fatalf("status = %q, want executed", action.Status)
	}
	if action.SendRandomID == 0 {
		t.Fatalf("send_random_id not persisted")
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want 1", len(sender.calls))
	}
	if sender.calls[0].randomID != action.SendRandomID {
		t.Fatalf("sent random_id = %d, want the persisted %d", sender.calls[0].randomID, action.SendRandomID)
	}
	if sender.calls[0].peerTGID != conv.PeerTGID {
		t.Fatalf("sent to peer %d, want %d", sender.calls[0].peerTGID, conv.PeerTGID)
	}
}

// TestExecutor_Approve_TransientSendFailureWrapsErrSendQueuedForRetry guards
// against a Codex finding on #307: the action is deliberately left
// `executing` for RecoverStuck to retry on a transient send error, so the
// error Approve returns must be distinguishable from a genuine failure —
// control.Router.handleApprove relies on errors.Is(err,
// ErrSendQueuedForRetry) to avoid telling the owner "could not approve" for
// something that's actually still in flight.
func TestExecutor_Approve_TransientSendFailureWrapsErrSendQueuedForRetry(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	_, code := seedPendingApproval(t, store, uid, conv.ID, "Thanks for reaching out!")
	sender.failNext = 1

	err := exec.Approve(ctx, uid, code)
	if err == nil {
		t.Fatal("expected an error from the transient send failure")
	}
	if !errors.Is(err, ErrSendQueuedForRetry) {
		t.Fatalf("err = %v, want it to wrap ErrSendQueuedForRetry", err)
	}
}

// TestExecutor_Approve_PreSendTransientFailureAlsoWrapsErrSendQueuedForRetry
// guards against a second Codex finding on #307: the first fix only wrapped
// the send-RPC failure in ErrSendQueuedForRetry, but a transient error
// loading the profile/conversation, generating the random_id, or the
// BeginExecutingAgentAction CAS call itself ALSO leaves the action
// untouched at `approved` — no CAS has run yet — so ProcessApproved's own
// periodic sweep picks it up and retries it exactly like RecoverStuck does
// for a row already `executing`. These earlier failures were left on the
// generic error path, so the owner was told "could not approve" for
// something that's genuinely the same "queued, will retry" case. Simulated
// here by deleting the profile row out from under an already-pending
// approval, forcing GetAgentProfile to fail.
func TestExecutor_Approve_PreSendTransientFailureAlsoWrapsErrSendQueuedForRetry(t *testing.T) {
	exec, _, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	_, code := seedPendingApproval(t, store, uid, conv.ID, "Thanks for reaching out!")
	if _, err := store.DB.ExecContext(ctx, `DELETE FROM agent_profiles WHERE user_id = ?`, uid); err != nil {
		t.Fatalf("orphan the profile: %v", err)
	}

	err := exec.Approve(ctx, uid, code)
	if err == nil {
		t.Fatal("expected an error from the missing profile")
	}
	if !errors.Is(err, ErrSendQueuedForRetry) {
		t.Fatalf("err = %v, want it to wrap ErrSendQueuedForRetry", err)
	}

	action, err := store.GetAgentActionByCode(ctx, uid, code)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionApproved {
		t.Fatalf("action status = %q, want still approved (untouched, for ProcessApproved's sweep to retry)", action.Status)
	}
}

func TestExecutor_Approve_WrongCodeReturnsNotFound(t *testing.T) {
	exec, _, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	seedPendingApproval(t, store, uid, conv.ID, "hi")

	if err := exec.Approve(ctx, uid, "BOGUS1"); err == nil {
		t.Fatal("expected error for unknown code")
	} else if err != ErrApprovalCodeNotFound {
		t.Fatalf("err = %v, want ErrApprovalCodeNotFound", err)
	}
}

func TestExecutor_Reject_TransitionsToRejected(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "hi")

	if err := exec.Reject(ctx, uid, code); err != nil {
		t.Fatalf("reject: %v", err)
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionRejected {
		t.Fatalf("status = %q, want rejected", action.Status)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0 (rejected must never send)", len(sender.calls))
	}
}

// TestExecutor_Approve_KillSwitchDeniesAtSendTime is the crash-recovery
// spec's "kill-switch flip mid-flow" case: approval and send are not
// atomic, so a kill switch engaged in that gap must stop the send, not just
// be checked once at approval time.
func TestExecutor_Approve_KillSwitchDeniesAtSendTime(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "hi")

	exec.GlobalKill = func() bool { return true }
	err := exec.Approve(ctx, uid, code)
	if err == nil {
		t.Fatal("expected policy-deny error")
	}
	action, gerr := store.GetAgentAction(ctx, uid, actionID)
	if gerr != nil {
		t.Fatalf("get action: %v", gerr)
	}
	if action.Status != db.ActionDenied {
		t.Fatalf("status = %q, want denied (stale approval must not bypass a kill switch engaged before send)", action.Status)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0", len(sender.calls))
	}
}

// TestExecutor_Approve_TakeoverDeniesAtSendTime is the "concurrent owner
// reply cancels pending" case: a takeover flips conversation state, which
// the re-check-before-send picks up even though it happened after approval.
func TestExecutor_Approve_TakeoverDeniesAtSendTime(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	_, code := seedPendingApproval(t, store, uid, conv.ID, "hi")

	if err := store.SetConversationState(ctx, uid, conv.ID, db.ConversationTakenOver); err != nil {
		t.Fatalf("set taken over: %v", err)
	}
	if err := exec.Approve(ctx, uid, code); err == nil {
		t.Fatal("expected policy-deny error after takeover")
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0 (must not send on top of a takeover)", len(sender.calls))
	}
}

// TestExecutor_RecoverStuck_RetriesWithSameRandomID is the core
// crash-recovery guarantee: an action stuck in executing (simulating a
// process death between BeginExecutingAgentAction and the send RPC, or
// between the RPC and SetAgentActionExecuted) is retried with the EXACT
// same random_id, never a fresh one.
func TestExecutor_RecoverStuck_RetriesWithSameRandomID(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "hi")

	// Get the action into `approved` first (skip the actual send), then
	// simulate the crash by hand: BeginExecutingAgentAction persists a
	// random_id and flips to executing, exactly like the real send path
	// does right before calling Sender — but we stop there, never calling
	// Sender, to model a process death at that exact point.
	if ok, err := store.UpdateAgentActionStatus(ctx, uid, actionID, db.ActionPendingApproval, db.ActionApproved); err != nil || !ok {
		t.Fatalf("approve transition: ok=%v err=%v", ok, err)
	}
	if ok, err := store.BeginExecutingAgentAction(ctx, uid, actionID, 424242); err != nil || !ok {
		t.Fatalf("begin executing: ok=%v err=%v", ok, err)
	}
	_ = code

	n, err := exec.RecoverStuck(ctx)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if n != 1 {
		t.Fatalf("recovered count = %d, want 1", n)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want 1", len(sender.calls))
	}
	if sender.calls[0].randomID != 424242 {
		t.Fatalf("retry random_id = %d, want the original 424242", sender.calls[0].randomID)
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionExecuted {
		t.Fatalf("status = %q, want executed", action.Status)
	}
}

// TestExecutor_RecoverStuck_RespectsGraceWindow ensures a genuinely
// in-flight send (updated_at very recent) is NOT retried out from under a
// concurrent goroutine still processing it.
func TestExecutor_RecoverStuck_RespectsGraceWindow(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, _ := seedPendingApproval(t, store, uid, conv.ID, "hi")
	exec.StuckGrace = time.Hour // nothing should look stuck within an hour

	if ok, err := store.UpdateAgentActionStatus(ctx, uid, actionID, db.ActionPendingApproval, db.ActionApproved); err != nil || !ok {
		t.Fatalf("approve transition: ok=%v err=%v", ok, err)
	}
	if ok, err := store.BeginExecutingAgentAction(ctx, uid, actionID, 1); err != nil || !ok {
		t.Fatalf("begin executing: ok=%v err=%v", ok, err)
	}

	n, err := exec.RecoverStuck(ctx)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if n != 0 {
		t.Fatalf("recovered count = %d, want 0 (within grace window)", n)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0", len(sender.calls))
	}
}

// fakeRestrictedChecker lets tests control MatchRestricted's outcome
// without needing a real profile.Provider/YAML file.
type fakeRestrictedChecker struct {
	key                             string
	neverAutoSend, approvalRequired bool
	matched                         bool
}

func (f *fakeRestrictedChecker) MatchRestricted(string) (string, bool, bool, bool) {
	return f.key, f.neverAutoSend, f.approvalRequired, f.matched
}

// TestExecutor_Approve_RecordsConversationHistory guards against the P1
// found in review: a successful send never called InsertConversationMessage,
// so recentAgentSends (the rate-limit input in internal/agentapi) always saw
// zero prior agent sends and max_msgs_per_minute never actually triggered.
// TestExecutor_Approve_PassesConversationPeerAccessHash guards against the
// P1 found in round-4 review: PEER_ID_INVALID on every executor send because
// the send path built a zero-access-hash InputPeerUser instead of using the
// conversation's stored one. The executor's job is done once it hands the
// conversation's PeerAccessHash to Sender — the pool/telegram-layer wiring
// that turns it into an actual InputPeerUser is verified separately in
// internal/telegram.
func TestExecutor_Approve_PassesConversationPeerAccessHash(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	if err := store.SetConversationPeerAccessHash(ctx, uid, conv.PeerTGID, 987654321); err != nil {
		t.Fatalf("set access hash: %v", err)
	}
	_, code := seedPendingApproval(t, store, uid, conv.ID, "hi")

	if err := exec.Approve(ctx, uid, code); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want 1", len(sender.calls))
	}
	if sender.calls[0].peerAccessHash != 987654321 {
		t.Fatalf("peerAccessHash = %d, want 987654321 (the conversation's stored hash)", sender.calls[0].peerAccessHash)
	}
}

func TestExecutor_Approve_RecordsConversationHistory(t *testing.T) {
	exec, _, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	_, code := seedPendingApproval(t, store, uid, conv.ID, "Thanks for reaching out!")

	if err := exec.Approve(ctx, uid, code); err != nil {
		t.Fatalf("approve: %v", err)
	}
	msgs, err := store.ListConversationMessages(ctx, uid, conv.ID, 10)
	if err != nil {
		t.Fatalf("list conversation messages: %v", err)
	}
	var found bool
	for _, m := range msgs {
		if m.Direction == db.DirectionAgentOutgoing {
			found = true
			if m.TGMessageID == 0 {
				t.Fatalf("recorded message has no tg_message_id: %+v", m)
			}
		}
	}
	if !found {
		t.Fatal("no agent_outgoing conversation_messages row recorded after a successful send")
	}
}

// TestExecutor_Approve_CodeIsCaseNormalized guards against the P2 found in
// review: approval codes are always minted uppercase, but GetAgentActionByCode
// matches case-sensitively — an owner's lowercase-autocapitalized paste must
// still resolve.
func TestExecutor_Approve_CodeIsCaseNormalized(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	_, code := seedPendingApproval(t, store, uid, conv.ID, "hi")

	if err := exec.Approve(ctx, uid, strings.ToLower(code)); err != nil {
		t.Fatalf("approve with lowercase code: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want 1", len(sender.calls))
	}
}

// TestExecutor_Approve_NeverAutoSendRestrictedFieldBlocksSend guards against
// the P1 found in review: RestrictedField/MatchRestricted had no production
// caller, so a never_auto_send value could be auto-sent (guarded mode) or
// sent after a routine approval, despite the marker's documented meaning
// that only the owner typing it themselves satisfies it.
func TestExecutor_Approve_NeverAutoSendRestrictedFieldBlocksSend(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	exec.Profile = &fakeRestrictedChecker{key: "references", neverAutoSend: true, matched: true}
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "here are my references")

	if err := exec.Approve(ctx, uid, code); err == nil {
		t.Fatal("expected owner-profile-blocks error")
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0", len(sender.calls))
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionDenied {
		t.Fatalf("status = %q, want denied", action.Status)
	}
}

// TestExecutor_Approve_RestrictedFieldScopedToProfileOwner covers a Codex
// finding on #307: restrictedFieldBlocks had no notion of which account
// Profile's restricted section actually belongs to, so in a multi-tenant
// deployment EVERY user's action was checked against the one configured
// owner's private restricted values. A second account's reply that happened
// to textually match must NOT be blocked once ProfileOwnerTGID scopes the
// check to the account the profile actually belongs to — only that
// account's own matching action should still be denied.
func TestExecutor_Approve_RestrictedFieldScopedToProfileOwner(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	exec.Profile = &fakeRestrictedChecker{key: "references", neverAutoSend: true, matched: true}
	exec.ProfileOwnerTGID = uid

	otherUID, err := store.EnsureUser(ctx, "other-owner", "", "test")
	if err != nil {
		t.Fatalf("ensure other user: %v", err)
	}
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: otherUID, Mode: db.AgentModeGuarded, DisclosureText: "I'm an AI assistant.",
	}); err != nil {
		t.Fatalf("seed other profile: %v", err)
	}
	otherConv, err := store.EnsureConversation(ctx, otherUID, 556, "peer2", "Peer2")
	if err != nil {
		t.Fatalf("ensure other conversation: %v", err)
	}
	_, otherCode := seedPendingApproval(t, store, otherUID, otherConv.ID, "here are my references")
	if err := exec.Approve(ctx, otherUID, otherCode); err != nil {
		t.Fatalf("approve for the unrelated account should succeed (not this profile's owner): %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls for unrelated account = %d, want 1", len(sender.calls))
	}

	// The actual profile owner's matching action must still be blocked.
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "here are my references")
	if err := exec.Approve(ctx, uid, code); err == nil {
		t.Fatal("expected owner-profile-blocks error for the profile's actual owner")
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionDenied {
		t.Fatalf("status = %q, want denied", action.Status)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls after the owner's blocked attempt = %d, want still 1", len(sender.calls))
	}
}

// TestExecutor_ProcessApproved_ApprovalRequiredFieldBlocksAutoSend covers the
// guarded-mode half of the same restricted-field gate: an approval_required
// value must not go out through the auto-approved (no human review) path.
func TestExecutor_ProcessApproved_ApprovalRequiredFieldBlocksAutoSend(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	exec.Profile = &fakeRestrictedChecker{key: "current_salary", approvalRequired: true, matched: true}
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply,
		Payload: "my current salary is 145000", PolicyDecision: db.PolicyAllow,
		Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatalf("seed approved action: %v", err)
	}

	if _, err := exec.ProcessApproved(ctx); err != nil {
		t.Fatalf("process approved: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0 (approval_required field must not auto-send)", len(sender.calls))
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionDenied {
		t.Fatalf("status = %q, want denied", action.Status)
	}
}

// TestExecutor_RecoverStuck_KillSwitchDeniesInsteadOfRetrying is the
// crash-recovery counterpart of TestExecutor_Approve_KillSwitchDeniesAtSendTime:
// P1 found in review — recoverOne never re-checked policy, so a kill switch
// or takeover during the crash grace window did not stop the retry.
func TestExecutor_RecoverStuck_KillSwitchDeniesInsteadOfRetrying(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, _ := seedPendingApproval(t, store, uid, conv.ID, "hi")
	if ok, err := store.UpdateAgentActionStatus(ctx, uid, actionID, db.ActionPendingApproval, db.ActionApproved); err != nil || !ok {
		t.Fatalf("approve transition: ok=%v err=%v", ok, err)
	}
	if ok, err := store.BeginExecutingAgentAction(ctx, uid, actionID, 99); err != nil || !ok {
		t.Fatalf("begin executing: ok=%v err=%v", ok, err)
	}

	killed := true
	exec.GlobalKill = func() bool { return killed }
	n, err := exec.RecoverStuck(ctx)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if n != 1 {
		t.Fatalf("recovered count = %d, want 1", n)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0 (kill switch must stop recovery too)", len(sender.calls))
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionDenied {
		t.Fatalf("status = %q, want denied", action.Status)
	}
}

func TestExecutor_ProcessApproved_SendsGuardedModeActions(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply,
		Payload: "Happy to chat about the role.", PolicyDecision: db.PolicyAllow,
		Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatalf("seed approved action: %v", err)
	}

	n, err := exec.ProcessApproved(ctx)
	if err != nil {
		t.Fatalf("process approved: %v", err)
	}
	if n != 1 {
		t.Fatalf("processed = %d, want 1", n)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want 1", len(sender.calls))
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionExecuted {
		t.Fatalf("status = %q, want executed", action.Status)
	}
}
