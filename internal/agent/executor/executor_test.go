package executor

import (
	"context"
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
	userID, peerTGID, randomID int64
	text                       string
}

func (f *fakeSender) SendWithRandomID(_ context.Context, userID, peerTGID, randomID int64, text string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, sendCall{userID, peerTGID, randomID, text})
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
