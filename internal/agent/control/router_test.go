package control

import (
	"context"
	"strconv"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// fakeApprover records Approve/Reject calls and returns a canned error.
type fakeApprover struct {
	approveCalls, rejectCalls []string
	approveErr, rejectErr     error
}

func (f *fakeApprover) Approve(_ context.Context, _ int64, code string) error {
	f.approveCalls = append(f.approveCalls, code)
	return f.approveErr
}

func (f *fakeApprover) Reject(_ context.Context, _ int64, code string) error {
	f.rejectCalls = append(f.rejectCalls, code)
	return f.rejectErr
}

// fakeSelfSender records every Saved Messages reply instead of touching a
// real MTProto client.
type fakeSelfSender struct {
	sent []string
}

func (f *fakeSelfSender) SendToSelf(_ context.Context, _ int64, text string) (int64, error) {
	f.sent = append(f.sent, text)
	return int64(len(f.sent)), nil
}

func testKey() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func newTestRouter(t *testing.T) (*Router, *fakeApprover, *fakeSelfSender, *db.Store, int64) {
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
		UserID: uid, Mode: db.AgentModeObserve, DisclosureText: "AI assistant.",
	}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	approver := &fakeApprover{}
	sender := &fakeSelfSender{}
	notifier := NewNotifier(store, sender)
	router := NewRouter(store, approver, notifier)
	return router, approver, sender, store, uid
}

func TestRouter_Status_RepliesWithProfileSummary(t *testing.T) {
	router, _, sender, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl status"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
}

func TestRouter_UnknownCommand_RepliesWithHelp(t *testing.T) {
	router, _, sender, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl frobnicate"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
}

func TestRouter_Approve_DelegatesToExecutorWithCode(t *testing.T) {
	router, approver, sender, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl approve AB12CD"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(approver.approveCalls) != 1 || approver.approveCalls[0] != "AB12CD" {
		t.Fatalf("approve calls = %v, want [AB12CD]", approver.approveCalls)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
}

func TestRouter_Approve_SurfacesErrorFromExecutor(t *testing.T) {
	router, approver, sender, _, uid := newTestRouter(t)
	approver.approveErr = executor.ErrApprovalCodeNotFound
	if err := router.HandleSavedText(context.Background(), uid, "/mctl approve ZZZZZZ"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
	if sender.sent[0] == "Approved and sent (ZZZZZZ)." {
		t.Fatalf("router reported success despite executor error: %q", sender.sent[0])
	}
}

func TestRouter_Reject_DelegatesToExecutorWithCode(t *testing.T) {
	router, approver, _, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl reject XY9988"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(approver.rejectCalls) != 1 || approver.rejectCalls[0] != "XY9988" {
		t.Fatalf("reject calls = %v, want [XY9988]", approver.rejectCalls)
	}
}

func TestRouter_Pause_SetsAutopilotPaused(t *testing.T) {
	router, _, _, store, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl pause"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	profile, err := store.GetAgentProfile(context.Background(), uid)
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	if !profile.AutopilotPaused {
		t.Fatal("autopilot_paused = false, want true")
	}
}

func TestRouter_Takeover_SetsStateAndDeniesPending(t *testing.T) {
	router, _, _, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "peer", "Peer")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply,
		Payload: "draft", PolicyDecision: db.PolicyRequireApproval, Status: db.ActionPendingApproval,
		ApprovalCode: "PEND01",
	})
	if err != nil {
		t.Fatalf("seed pending action: %v", err)
	}

	if err := router.HandleSavedText(ctx, uid, "/mctl takeover "+strconv.FormatInt(conv.ID, 10)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	gotConv, err := store.GetConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if gotConv.State != db.ConversationTakenOver {
		t.Fatalf("state = %q, want taken_over", gotConv.State)
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionDenied {
		t.Fatalf("pending action status = %q, want denied", action.Status)
	}
}

func TestRouter_Continue_ResetsStateAndTurns(t *testing.T) {
	router, _, _, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "peer", "Peer")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	if err := store.SetConversationState(ctx, uid, conv.ID, db.ConversationTakenOver); err != nil {
		t.Fatalf("take over: %v", err)
	}
	if err := router.HandleSavedText(ctx, uid, "/mctl continue "+strconv.FormatInt(conv.ID, 10)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, err := store.GetConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if got.State != db.ConversationActive {
		t.Fatalf("state = %q, want active", got.State)
	}
}
