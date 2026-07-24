package executor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
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

// TestExecutor_Approve_PostSendPersistenceFailureWrapsErrSendQueuedForRetry
// covers a Codex finding on #307: if the Telegram RPC already succeeded but
// RecordAgentActionSent then fails (a transient DB error), the reply
// genuinely reached the recruiter — the row is left `executing` (the whole
// transaction rolls back) for RecoverStuck to safely retry via the same
// persisted random_id. The old bare error told the owner "could not
// approve" for a message that had already sent, which could prompt a
// confusing manual duplicate reply. Forced here with a trigger that fails
// only the conversation_messages INSERT inside RecordAgentActionSent's
// transaction — renaming the whole table would also break
// recentAgentSends' SELECT against it earlier in send(), before the RPC
// this test needs to actually happen.
func TestExecutor_Approve_PostSendPersistenceFailureWrapsErrSendQueuedForRetry(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "Thanks for reaching out!")
	if _, err := store.DB.ExecContext(ctx,
		`CREATE TRIGGER fail_conv_msg_insert BEFORE INSERT ON conversation_messages BEGIN SELECT RAISE(ABORT, 'forced failure'); END`,
	); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}
	t.Cleanup(func() {
		_, _ = store.DB.ExecContext(context.Background(), `DROP TRIGGER fail_conv_msg_insert`)
	})

	err := exec.Approve(ctx, uid, code)
	if !errors.Is(err, ErrSendQueuedForRetry) {
		t.Fatalf("err = %v, want it to wrap ErrSendQueuedForRetry", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want 1 (the RPC must have actually been attempted)", len(sender.calls))
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionExecuting {
		t.Fatalf("action status = %q, want executing (left for RecoverStuck, bookkeeping rolled back)", action.Status)
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

// TestExecutor_Approve_RejectsExpiredCodeEvenBeforeSweeperRuns covers a
// Codex finding on #307: Approve() had no TTL check of its own, relying
// entirely on the async ExpireStaleAgentActions sweeper (which runs on its
// own minute-scale interval, or could simply be failing) to catch a stale
// pending_approval row. A code past ApprovalTTL must be rejected — and the
// row transitioned to expired — even if the sweeper hasn't reached it yet.
func TestExecutor_Approve_RejectsExpiredCodeEvenBeforeSweeperRuns(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	exec.ApprovalTTL = time.Hour
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "hi")
	if _, err := store.DB.ExecContext(ctx,
		`UPDATE agent_actions SET updated_at = ? WHERE id = ?`,
		time.Now().Add(-2*time.Hour).UTC(), actionID,
	); err != nil {
		t.Fatalf("backdate updated_at: %v", err)
	}

	err := exec.Approve(ctx, uid, code)
	if !errors.Is(err, ErrApprovalExpired) {
		t.Fatalf("err = %v, want ErrApprovalExpired", err)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0 (an expired draft must never send)", len(sender.calls))
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionExpired {
		t.Fatalf("status = %q, want expired", action.Status)
	}
	if action.ApprovalCode != "" {
		t.Fatalf("approval code = %q, want cleared on expiry", action.ApprovalCode)
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

// fakeSendGate lets tests control SendAllowed's outcome without needing a
// real db.Store.IsSendEnabled/ALLOW_SEND wiring.
type fakeSendGate struct {
	allowed bool
	reason  string
	err     error
}

func (f *fakeSendGate) SendAllowed(context.Context, int64) (bool, string, error) {
	return f.allowed, f.reason, f.err
}

// TestExecutor_Approve_SendGateBlocksSend covers a Codex finding on #307:
// the executor had no equivalent of internal/mcp's evaluateSendGate
// (ALLOW_SEND / per-account send_enabled) at all — poolSender went straight
// to the Telegram RPC regardless, contradicting internal/web/security.html's
// published guarantee that enabling the listener does not bypass those
// gates. A blocked gate must stop the send exactly like a hard policy Deny.
func TestExecutor_Approve_SendGateBlocksSend(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	exec.SendGate = &fakeSendGate{allowed: false, reason: "server flag ALLOW_SEND=false"}
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "Thanks for reaching out!")

	err := exec.Approve(ctx, uid, code)
	if err == nil {
		t.Fatal("expected an error when the send gate blocks the send")
	}
	if errors.Is(err, ErrSendQueuedForRetry) {
		t.Fatalf("err = %v, want a hard deny, not a retryable ErrSendQueuedForRetry (ALLOW_SEND=false won't fix itself on retry)", err)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0 — the gate must block the RPC entirely", len(sender.calls))
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionDenied {
		t.Fatalf("status = %q, want denied", action.Status)
	}
}

// TestExecutor_RecoverStuck_SendGateBlocksRecoverySend is the crash-recovery
// counterpart: a gate that closed during the grace window must also stop
// recoverOne from retrying the send.
func TestExecutor_RecoverStuck_SendGateBlocksRecoverySend(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "hi")
	if err := exec.Approve(ctx, uid, code); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := store.DB.ExecContext(ctx,
		`UPDATE agent_actions SET status = ?, updated_at = ? WHERE id = ?`,
		db.ActionExecuting, time.Now().Add(-time.Hour).UTC(), actionID,
	); err != nil {
		t.Fatalf("force stuck: %v", err)
	}
	exec.SendGate = &fakeSendGate{allowed: false, reason: "per-account send_enabled=false"}

	if _, err := exec.RecoverStuck(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want 1 (only the original Approve send, no recovery retry)", len(sender.calls))
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionDenied {
		t.Fatalf("status = %q, want denied", action.Status)
	}
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
//
// ProfileOwnerTGID is a Telegram account id, not an internal users.id — a
// real telegram_accounts row is seeded here (via SaveSession) so the test
// exercises the actual GetTelegramID resolution path instead of the two ID
// namespaces coincidentally matching, which is exactly what a Codex finding
// on #307 caught: an earlier version of this test set ProfileOwnerTGID
// directly to the internal uid, which meant restrictedFieldBlocks' scope
// check (comparing a Telegram id against an internal id) could never
// actually match anything, silently disabling enforcement for every
// account including the real owner's.
func TestExecutor_Approve_RestrictedFieldScopedToProfileOwner(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	exec.Profile = &fakeRestrictedChecker{key: "references", neverAutoSend: true, matched: true}
	const ownerTGID = int64(999888777)
	if err := store.SaveSession(ctx, uid, []byte("session-bytes"), ownerTGID, "Owner", "owner"); err != nil {
		t.Fatalf("seed owner telegram account: %v", err)
	}
	exec.ProfileOwnerTGID = ownerTGID

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

// TestExecutor_RecoverStuck_RestartCounterOnlyCountsNewlyStuckActions guards
// against a Codex finding on #307: AgentExecutorRestartsTotal is documented
// as a proxy for "the executor process restarted mid-send", but a normal
// transient send failure deliberately leaves an action in `executing` for
// the next sweep to retry — before this fix, every sweep that still found
// the SAME persistently-failing action re-incremented the counter, so one
// stuck action could inflate it far past the number of actual restarts.
func TestExecutor_RecoverStuck_RestartCounterOnlyCountsNewlyStuckActions(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	exec.m = metrics.New()
	ctx := context.Background()
	actionID, _ := seedPendingApproval(t, store, uid, conv.ID, "hi")
	if ok, err := store.UpdateAgentActionStatus(ctx, uid, actionID, db.ActionPendingApproval, db.ActionApproved); err != nil || !ok {
		t.Fatalf("approve transition: ok=%v err=%v", ok, err)
	}
	if ok, err := store.BeginExecutingAgentAction(ctx, uid, actionID, 777); err != nil || !ok {
		t.Fatalf("begin executing: ok=%v err=%v", ok, err)
	}
	// Every retry keeps failing, so the action never leaves `executing`.
	sender.failNext = 10

	for i := 0; i < 3; i++ {
		if _, err := exec.RecoverStuck(ctx); err != nil {
			t.Fatalf("recover sweep %d: %v", i, err)
		}
	}
	if got := testutil.ToFloat64(exec.m.AgentExecutorRestartsTotal); got != 1 {
		t.Fatalf("restarts counter = %v after 3 sweeps of the same still-stuck action, want 1", got)
	}

	// A genuinely new stuck action must still be counted.
	actionID2, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply,
		Payload: "hi again", PolicyDecision: db.PolicyRequireApproval, PolicyReasons: "observe mode",
		Status: db.ActionPendingApproval, ApprovalCode: "TESTCD2",
	})
	if err != nil {
		t.Fatalf("seed second pending action: %v", err)
	}
	if ok, err := store.UpdateAgentActionStatus(ctx, uid, actionID2, db.ActionPendingApproval, db.ActionApproved); err != nil || !ok {
		t.Fatalf("approve transition 2: ok=%v err=%v", ok, err)
	}
	if ok, err := store.BeginExecutingAgentAction(ctx, uid, actionID2, 778); err != nil || !ok {
		t.Fatalf("begin executing 2: ok=%v err=%v", ok, err)
	}
	if _, err := exec.RecoverStuck(ctx); err != nil {
		t.Fatalf("recover sweep 4: %v", err)
	}
	if got := testutil.ToFloat64(exec.m.AgentExecutorRestartsTotal); got != 2 {
		t.Fatalf("restarts counter = %v after a second distinct action got stuck, want 2", got)
	}
}

// TestExecutor_ApprovalLatency_OnlyObservedForHumanApprovedActions covers a
// Codex finding on #307: AgentApprovalLatencySeconds was observed
// unconditionally, including for guarded-mode PolicyAllow actions sent via
// ProcessApproved that never received an owner /mctl approve at all — those
// have no "approval" whose latency this histogram is supposed to measure,
// so counting them polluted it with proposal-to-sweep delays. Only a
// PolicyRequireApproval action (one that actually went through /mctl
// approve) should be observed.
func TestExecutor_ApprovalLatency_OnlyObservedForHumanApprovedActions(t *testing.T) {
	exec, _, store, uid, conv := newTestExecutor(t)
	exec.m = metrics.New()
	ctx := context.Background()

	// Guarded-mode auto-approval: never human-reviewed.
	if _, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply, Intent: "discovery",
		Payload: "Happy to chat about the role.", PolicyDecision: db.PolicyAllow,
		Status: db.ActionApproved,
	}); err != nil {
		t.Fatalf("seed guarded approved action: %v", err)
	}
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: uid, Mode: db.AgentModeGuarded, DisclosureText: "I'm an AI assistant.",
		IntentAllowlist: "discovery",
	}); err != nil {
		t.Fatalf("seed profile allowing discovery: %v", err)
	}
	if _, err := exec.ProcessApproved(ctx); err != nil {
		t.Fatalf("process approved: %v", err)
	}
	if got := histogramSampleCount(t, exec.m, "mctl_agent_approval_latency_seconds"); got != 0 {
		t.Fatalf("latency histogram sample count after a guarded auto-send = %d, want 0 (never human-approved)", got)
	}

	// A genuine owner /mctl approve must still be observed.
	_, code := seedPendingApproval(t, store, uid, conv.ID, "Thanks for reaching out!")
	if err := exec.Approve(ctx, uid, code); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got := histogramSampleCount(t, exec.m, "mctl_agent_approval_latency_seconds"); got != 1 {
		t.Fatalf("latency histogram sample count after a human /mctl approve = %d, want 1", got)
	}
}

func histogramSampleCount(t *testing.T, m *metrics.Registry, name string) uint64 {
	t.Helper()
	mfs, err := m.Prometheus.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			var total uint64
			for _, metric := range mf.GetMetric() {
				total += metric.GetHistogram().GetSampleCount()
			}
			return total
		}
	}
	return 0
}

// TestExecutor_ProcessApproved_EnforcesRateLimitAcrossSends covers a Codex
// finding on #307: send() never passed RecentAgentSends to policy.Evaluate,
// so overRate always saw an empty slice and MaxMsgsPerMinute was
// unenforced at send time — only propose_reply's initial check
// (internal/agentapi) ever saw real history. With MaxMsgsPerMinute=1 and
// two guarded actions queued, the first send must go through and the
// second must now be denied (its own re-evaluation should see the first
// send and trip the rate limit), not silently sent within the same minute.
func TestExecutor_ProcessApproved_EnforcesRateLimitAcrossSends(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: uid, Mode: db.AgentModeGuarded, DisclosureText: "I'm an AI assistant.",
		MaxMsgsPerMinute: 1, IntentAllowlist: "discovery",
	}); err != nil {
		t.Fatalf("seed profile with rate limit 1/min: %v", err)
	}
	firstID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply, Intent: "discovery",
		Payload: "Happy to chat about the role.", PolicyDecision: db.PolicyAllow,
		Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatalf("seed first approved action: %v", err)
	}
	secondID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply, Intent: "discovery",
		Payload: "Sure, let's set up a call.", PolicyDecision: db.PolicyAllow,
		Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatalf("seed second approved action: %v", err)
	}

	n, err := exec.ProcessApproved(ctx)
	if err != nil {
		t.Fatalf("process approved: %v", err)
	}
	if n != 2 {
		t.Fatalf("processed = %d, want 2", n)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want exactly 1 (the second must be rate-limited, not sent within the same minute)", len(sender.calls))
	}

	first, err := store.GetAgentAction(ctx, uid, firstID)
	if err != nil {
		t.Fatalf("get first action: %v", err)
	}
	if first.Status != db.ActionExecuted {
		t.Fatalf("first status = %q, want executed", first.Status)
	}
	second, err := store.GetAgentAction(ctx, uid, secondID)
	if err != nil {
		t.Fatalf("get second action: %v", err)
	}
	if second.Status != db.ActionDenied {
		t.Fatalf("second status = %q, want denied (rate limit exceeded by the first send)", second.Status)
	}
}

// TestExecutor_ProcessApproved_StopsUnreviewedActionWhenBudgetExhausted
// covers a Codex finding on #307: send() only ever stopped for a hard Deny,
// so RequireApproval was silently ignored even for an action NO human ever
// reviewed (PolicyDecision == PolicyAllow, guarded-mode auto-approval). With
// a one-turn budget and two such actions queued, the first send exhausts
// the budget and the second re-evaluation correctly returns
// RequireApproval — but the old code sent it anyway, bypassing the turn
// limit it exists to enforce. The second action must be denied, not sent.
func TestExecutor_ProcessApproved_StopsUnreviewedActionWhenBudgetExhausted(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: uid, Mode: db.AgentModeGuarded, DisclosureText: "I'm an AI assistant.",
		MaxAutonomousTurns: 1, IntentAllowlist: "discovery",
	}); err != nil {
		t.Fatalf("seed profile with turn budget 1: %v", err)
	}
	firstID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply, Intent: "discovery",
		Payload: "Happy to chat about the role.", PolicyDecision: db.PolicyAllow,
		Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatalf("seed first approved action: %v", err)
	}
	secondID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply, Intent: "discovery",
		Payload: "Sure, let's set up a call.", PolicyDecision: db.PolicyAllow,
		Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatalf("seed second approved action: %v", err)
	}

	n, err := exec.ProcessApproved(ctx)
	if err != nil {
		t.Fatalf("process approved: %v", err)
	}
	if n != 2 {
		t.Fatalf("processed = %d, want 2", n)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want exactly 1 (the second must be denied, not sent, once the turn budget is exhausted)", len(sender.calls))
	}

	first, err := store.GetAgentAction(ctx, uid, firstID)
	if err != nil {
		t.Fatalf("get first action: %v", err)
	}
	if first.Status != db.ActionExecuted {
		t.Fatalf("first status = %q, want executed", first.Status)
	}
	second, err := store.GetAgentAction(ctx, uid, secondID)
	if err != nil {
		t.Fatalf("get second action: %v", err)
	}
	if second.Status != db.ActionDenied {
		t.Fatalf("second status = %q, want denied (no human ever reviewed it, and the budget is now exhausted)", second.Status)
	}
}

// TestExecutor_RecoverStuck_StopsUnreviewedActionWhenApprovalNowRequired is
// the recovery-path counterpart of
// TestExecutor_ProcessApproved_StopsUnreviewedActionWhenBudgetExhausted: a
// Codex finding on #307 caught that recoverOne only stopped a retry for a
// hard Deny, missing the same requireApprovalBypassesUnreviewedAllow
// escalation send() has — so a guarded auto-approved (PolicyAllow) action
// that crashed mid-send and got picked up by RecoverStuck could still go out
// even after the turn budget was exhausted by another send during the grace
// window, bypassing a guard a fresh send() call would have enforced.
func TestExecutor_RecoverStuck_StopsUnreviewedActionWhenApprovalNowRequired(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: uid, Mode: db.AgentModeGuarded, DisclosureText: "I'm an AI assistant.",
		MaxAutonomousTurns: 1, IntentAllowlist: "discovery",
	}); err != nil {
		t.Fatalf("seed profile with turn budget 1: %v", err)
	}
	// Consume the one-turn budget with an unrelated already-executed send —
	// mirrors what a sibling ProcessApproved call would have done during the
	// grace window while this action was stuck.
	if err := store.IncrementAutonomousTurns(ctx, uid, conv.ID); err != nil {
		t.Fatalf("consume turn budget: %v", err)
	}

	stuckID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply, Intent: "discovery",
		Payload: "Sure, let's set up a call.", PolicyDecision: db.PolicyAllow,
		Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatalf("seed stuck-to-be action: %v", err)
	}
	if ok, err := store.BeginExecutingAgentAction(ctx, uid, stuckID, 4242); err != nil || !ok {
		t.Fatalf("begin executing: ok=%v err=%v", ok, err)
	}

	n, err := exec.RecoverStuck(ctx)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if n != 1 {
		t.Fatalf("recovered count = %d, want 1", n)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0 (budget exhausted, no human ever reviewed this draft)", len(sender.calls))
	}
	action, err := store.GetAgentAction(ctx, uid, stuckID)
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
	// IntentAllowlist must actually allow this action's Intent: since
	// requireApprovalBypassesUnreviewedAllow (added alongside a Codex fix
	// on #307) now re-derives the send-time decision for real instead of
	// trusting the stored PolicyDecision blindly, the re-evaluation has to
	// legitimately agree this is Allow, not RequireApproval, for the send to
	// go through.
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: uid, Mode: db.AgentModeGuarded, DisclosureText: "I'm an AI assistant.",
		IntentAllowlist: "discovery",
	}); err != nil {
		t.Fatalf("seed profile with intent allowlist: %v", err)
	}
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply, Intent: "discovery",
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
