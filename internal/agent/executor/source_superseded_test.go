package executor

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// seedJobDraft ingests Alice's message 10, claims its job and stores a
// pending-approval draft under it, as a worker's propose_reply would.
func seedJobDraft(t *testing.T, store *db.Store, uid int64, conv *db.Conversation) (actionID int64, code string) {
	t.Helper()
	ctx := context.Background()
	if _, ok, err := store.InsertEventEnqueueJobAndTouch(ctx, db.IncomingEvent{
		EventID: "evt:v1:1:555:10", UserID: uid, Kind: db.EventKindPrivateMessage,
		ChatTGID: 555, SenderTGID: 555, MessageID: 10, Body: "Can you do Thursday?",
	}, conv.ID); err != nil || !ok {
		t.Fatalf("ingest: ok=%v err=%v", ok, err)
	}
	jobs, err := store.ClaimAgentJobs(ctx, "r", uid, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: %d jobs, err=%v", len(jobs), err)
	}
	actionID, err = store.InsertAgentAction(ctx, db.AgentAction{
		JobID: jobs[0].ID, Attempt: jobs[0].Attempts, ConversationID: conv.ID, UserID: uid,
		ActionType: db.ActionTypeReply, Payload: "Thursday works.",
		PolicyDecision: db.PolicyRequireApproval, PolicyReasons: "observe mode",
		Status: db.ActionPendingApproval, ApprovalCode: "SUPRCD",
	})
	if err != nil {
		t.Fatalf("insert draft: %v", err)
	}
	return actionID, "SUPRCD"
}

func editAliceMessage(t *testing.T, store *db.Store, uid int64, conv *db.Conversation) {
	t.Helper()
	if _, ok, err := store.InsertEventEnqueueJobAndTouch(context.Background(), db.IncomingEvent{
		EventID: "evt:v1:1:555:10:e100:aa", UserID: uid, Kind: db.EventKindMessageEdit,
		ChatTGID: 555, SenderTGID: 555, MessageID: 10, Body: "Only Friday, not Thursday",
	}, conv.ID); err != nil || !ok {
		t.Fatalf("ingest edit: ok=%v err=%v", ok, err)
	}
}

func assertSupersededDenial(t *testing.T, exec *Executor, sender *fakeSender, store *db.Store, uid, actionID int64, err error, wantReason string, counterBefore float64) {
	t.Helper()
	if !errors.Is(err, ErrSourceSuperseded) {
		t.Fatalf("approve err = %v, want ErrSourceSuperseded", err)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send calls = %d, want 0", len(sender.calls))
	}
	a, gerr := store.GetAgentAction(context.Background(), uid, actionID)
	if gerr != nil {
		t.Fatalf("get action: %v", gerr)
	}
	if a.Status != db.ActionDenied || a.PolicyReasons != wantReason {
		t.Fatalf("action = %s %q, want denied %q", a.Status, a.PolicyReasons, wantReason)
	}
	after := testutil.ToFloat64(exec.m.AgentPolicyDenialsTotal.WithLabelValues(
		string(policy.DenySourceSuperseded), metrics.PolicySurfaceExecutorSend))
	if after != counterBefore+1 {
		t.Fatalf("source_message_superseded denials = %v, want %v", after, counterBefore+1)
	}
}

// TestExecutor_Approve_SourceEditedBeforeApproval: the sender edits the
// message while the draft waits for the owner; approving it must not send
// the stale answer (#950).
func TestExecutor_Approve_SourceEditedBeforeApproval(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	exec.m = metrics.New()
	actionID, code := seedJobDraft(t, store, uid, conv)
	editAliceMessage(t, store, uid, conv)

	before := testutil.ToFloat64(exec.m.AgentPolicyDenialsTotal.WithLabelValues(
		string(policy.DenySourceSuperseded), metrics.PolicySurfaceExecutorSend))
	err := exec.Approve(context.Background(), uid, code)
	assertSupersededDenial(t, exec, sender, store, uid, actionID, err, db.ReasonSourceEdited, before)
}

// TestExecutor_Approve_SourceDeletedDuringSend lands the delete after the
// pre-send policy check has passed, from inside the send gate, so only the
// reservation's own check under the conversation lock can stop it (#949).
func TestExecutor_Approve_SourceDeletedDuringSend(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	exec.m = metrics.New()
	actionID, code := seedJobDraft(t, store, uid, conv)
	exec.SendGate = func(ctx context.Context, userID, _ int64) error {
		_, err := store.RecordMessageDelete(ctx, userID, 1, 10)
		return err
	}

	before := testutil.ToFloat64(exec.m.AgentPolicyDenialsTotal.WithLabelValues(
		string(policy.DenySourceSuperseded), metrics.PolicySurfaceExecutorSend))
	err := exec.Approve(context.Background(), uid, code)
	assertSupersededDenial(t, exec, sender, store, uid, actionID, err, db.ReasonSourceDeleted, before)
}

// TestExecutor_Approve_UnrelatedEditStillSends: an edit of a different
// message in the same chat does not withdraw the draft.
func TestExecutor_Approve_UnrelatedEditStillSends(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	actionID, code := seedJobDraft(t, store, uid, conv)
	if _, ok, err := store.InsertEventEnqueueJobAndTouch(context.Background(), db.IncomingEvent{
		EventID: "evt:v1:1:555:11:e100:aa", UserID: uid, Kind: db.EventKindMessageEdit,
		ChatTGID: 555, SenderTGID: 555, MessageID: 11, Body: "typo fix",
	}, conv.ID); err != nil || !ok {
		t.Fatalf("ingest edit: ok=%v err=%v", ok, err)
	}
	if err := exec.Approve(context.Background(), uid, code); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want 1", len(sender.calls))
	}
	if a, _ := store.GetAgentAction(context.Background(), uid, actionID); a.Status != db.ActionExecuted {
		t.Fatalf("action = %s, want executed", a.Status)
	}
}

// TestExecutor_Approve_SourceEditedDuringSend models the listener's edit
// path, which denies existing drafts and only then records the edit event:
// an edit event committed after the pre-send check, with no deny of this
// row, must still be caught by the reservation (#950).
func TestExecutor_Approve_SourceEditedDuringSend(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	exec.m = metrics.New()
	actionID, code := seedJobDraft(t, store, uid, conv)
	exec.SendGate = func(context.Context, int64, int64) error {
		editAliceMessage(t, store, uid, conv)
		return nil
	}

	before := testutil.ToFloat64(exec.m.AgentPolicyDenialsTotal.WithLabelValues(
		string(policy.DenySourceSuperseded), metrics.PolicySurfaceExecutorSend))
	err := exec.Approve(context.Background(), uid, code)
	assertSupersededDenial(t, exec, sender, store, uid, actionID, err, db.ReasonSourceEdited, before)
}
