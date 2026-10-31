package executor

import (
	"context"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/profile"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// disclosureProfile is a synthetic owner profile: identity.company is
// after_owner_engaged by default, identity.education is marked never.
const disclosureProfile = `{
	"identity":{"name":"Alice Example","role":"Backend Engineer","company":"Nordbank GmbH","education":"Example University"},
	"disclosure":{"identity.education":"never"}
}`

// newDisclosureExecutor wires the real tenant provider so these tests run
// the same match the server runs, with a guarded profile whose allowlist
// lets a discovery reply auto-send.
func newDisclosureExecutor(t *testing.T) (*Executor, *fakeSender, *db.Store, int64, *db.Conversation) {
	t.Helper()
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: uid, Mode: db.AgentModeGuarded, DisclosureText: "I'm an AI assistant.",
		IntentAllowlist: "discovery",
	}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if err := store.SetAgentOwnerProfile(ctx, uid, []byte(disclosureProfile)); err != nil {
		t.Fatalf("seed owner profile: %v", err)
	}
	exec.Profile = profile.NewTenantProvider(store)
	return exec, sender, store, uid, conv
}

func seedGuardedAction(t *testing.T, store *db.Store, uid, convID int64, text string) int64 {
	t.Helper()
	id, err := store.InsertAgentAction(context.Background(), db.AgentAction{
		ConversationID: convID, UserID: uid, ActionType: db.ActionTypeReply, Intent: "discovery",
		Payload: text, PolicyDecision: db.PolicyAllow, Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatalf("seed approved action: %v", err)
	}
	return id
}

func actionStatus(t *testing.T, store *db.Store, uid, id int64) string {
	t.Helper()
	a, err := store.GetAgentAction(context.Background(), uid, id)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	return a.Status
}

func conversationEngaged(t *testing.T, store *db.Store, uid, convID int64) bool {
	t.Helper()
	c, err := store.GetConversation(context.Background(), uid, convID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	return c.OwnerEngaged(time.Now())
}

// TestExecutor_Disclosure_BlocksUnreviewedProtectedValueAtSend: an
// auto-approved reply that echoes an after_owner_engaged value before the
// owner engaged is stopped by the executor's own re-check, whatever the
// propose-time check decided.
func TestExecutor_Disclosure_BlocksUnreviewedProtectedValueAtSend(t *testing.T) {
	exec, sender, store, uid, conv := newDisclosureExecutor(t)
	id := seedGuardedAction(t, store, uid, conv.ID, "I work at Nordbank GmbH.")
	if _, err := exec.ProcessApproved(context.Background()); err != nil {
		t.Fatalf("process approved: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0", len(sender.calls))
	}
	if got := actionStatus(t, store, uid, id); got != db.ActionDenied {
		t.Fatalf("status = %q, want denied", got)
	}
}

// TestExecutor_Disclosure_EngagedConversationSendsProtectedValue: the same
// draft goes out once the owner engaged within the window.
func TestExecutor_Disclosure_EngagedConversationSendsProtectedValue(t *testing.T) {
	exec, sender, store, uid, conv := newDisclosureExecutor(t)
	ctx := context.Background()
	if err := store.MarkConversationOwnerEngaged(ctx, uid, conv.PeerTGID, time.Now().Add(-29*24*time.Hour)); err != nil {
		t.Fatalf("mark engaged: %v", err)
	}
	id := seedGuardedAction(t, store, uid, conv.ID, "I work at Nordbank GmbH.")
	if _, err := exec.ProcessApproved(ctx); err != nil {
		t.Fatalf("process approved: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want 1", len(sender.calls))
	}
	if got := actionStatus(t, store, uid, id); got != db.ActionExecuted {
		t.Fatalf("status = %q, want executed", got)
	}
}

// TestExecutor_Disclosure_SenderWordsSendBeforeEngagement pins #992 at send
// time: the executor's re-check reads the turn's inbound text from the
// action's job, so a draft repeating the peer's own words is not stopped.
func TestExecutor_Disclosure_SenderWordsSendBeforeEngagement(t *testing.T) {
	exec, sender, store, uid, conv := newDisclosureExecutor(t)
	ctx := context.Background()
	if _, ok, err := store.InsertEventEnqueueJobAndTouch(ctx, db.IncomingEvent{
		EventID: "evt:v1:1:555:20", UserID: uid, Kind: db.EventKindPrivateMessage,
		ChatTGID: 555, SenderTGID: 555, MessageID: 20, Body: "Hi, I hire for Nordbank GmbH. Open to a chat?",
	}, conv.ID); err != nil || !ok {
		t.Fatalf("ingest: ok=%v err=%v", ok, err)
	}
	jobs, err := store.ClaimAgentJobs(ctx, "r", uid, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: %d jobs, err=%v", len(jobs), err)
	}
	id, err := store.InsertAgentAction(ctx, db.AgentAction{
		JobID: jobs[0].ID, Attempt: jobs[0].Attempts, ConversationID: conv.ID, UserID: uid,
		ActionType: db.ActionTypeReply, Intent: "discovery", Payload: "Happy to hear more about Nordbank GmbH.",
		PolicyDecision: db.PolicyAllow, Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatalf("insert action: %v", err)
	}
	if _, err := exec.ProcessApproved(ctx); err != nil {
		t.Fatalf("process approved: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want 1 for the sender's own words", len(sender.calls))
	}
	if got := actionStatus(t, store, uid, id); got != db.ActionExecuted {
		t.Fatalf("status = %q, want executed", got)
	}
}

// TestExecutor_Disclosure_LapsedEngagementBlocksAgain: engagement older than
// the window no longer releases the field.
func TestExecutor_Disclosure_LapsedEngagementBlocksAgain(t *testing.T) {
	exec, sender, store, uid, conv := newDisclosureExecutor(t)
	ctx := context.Background()
	if err := store.MarkConversationOwnerEngaged(ctx, uid, conv.PeerTGID, time.Now().Add(-db.OwnerEngagementWindow-time.Hour)); err != nil {
		t.Fatalf("mark engaged: %v", err)
	}
	id := seedGuardedAction(t, store, uid, conv.ID, "I work at Nordbank GmbH.")
	if _, err := exec.ProcessApproved(ctx); err != nil {
		t.Fatalf("process approved: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0 after the window lapsed", len(sender.calls))
	}
	if got := actionStatus(t, store, uid, id); got != db.ActionDenied {
		t.Fatalf("status = %q, want denied", got)
	}
}

// TestExecutor_Disclosure_ApprovalReleasesAndEngages: the owner approving
// the exact draft is what releases an after_owner_engaged value, with no
// second approval, and the executed send engages the conversation.
func TestExecutor_Disclosure_ApprovalReleasesAndEngages(t *testing.T) {
	exec, sender, store, uid, conv := newDisclosureExecutor(t)
	ctx := context.Background()
	id, code := seedPendingApproval(t, store, uid, conv.ID, "I work at Nordbank GmbH.")
	if err := exec.Approve(ctx, uid, code); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want 1", len(sender.calls))
	}
	if got := actionStatus(t, store, uid, id); got != db.ActionExecuted {
		t.Fatalf("status = %q, want executed", got)
	}
	if !conversationEngaged(t, store, uid, conv.ID) {
		t.Fatal("executed approved reply did not engage the conversation")
	}
}

// TestExecutor_Disclosure_FailedApprovedSendDoesNotEngage: an approval whose
// send does not complete leaves the conversation unengaged.
func TestExecutor_Disclosure_FailedApprovedSendDoesNotEngage(t *testing.T) {
	exec, sender, store, uid, conv := newDisclosureExecutor(t)
	ctx := context.Background()
	_, code := seedPendingApproval(t, store, uid, conv.ID, "I work at Nordbank GmbH.")
	sender.failNext = 1
	if err := exec.Approve(ctx, uid, code); err == nil {
		t.Fatal("approve succeeded despite the send failure")
	}
	if conversationEngaged(t, store, uid, conv.ID) {
		t.Fatal("approval without a successful send engaged the conversation")
	}
}

// TestExecutor_Disclosure_NeverFieldBlockedEvenWhenApproved: approval cannot
// unblock a never field, engaged or not.
func TestExecutor_Disclosure_NeverFieldBlockedEvenWhenApproved(t *testing.T) {
	exec, sender, store, uid, conv := newDisclosureExecutor(t)
	ctx := context.Background()
	if err := store.MarkConversationOwnerEngaged(ctx, uid, conv.PeerTGID, time.Now()); err != nil {
		t.Fatalf("mark engaged: %v", err)
	}
	id, code := seedPendingApproval(t, store, uid, conv.ID, "I studied at Example University.")
	if err := exec.Approve(ctx, uid, code); err == nil {
		t.Fatal("approve of a never field succeeded")
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0", len(sender.calls))
	}
	if got := actionStatus(t, store, uid, id); got != db.ActionDenied {
		t.Fatalf("status = %q, want denied", got)
	}
}
