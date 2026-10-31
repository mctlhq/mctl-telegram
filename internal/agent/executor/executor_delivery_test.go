package executor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Tests for ambiguous send outcomes (#1029): the attempt bound, the
// delivery_unknown terminal state and its owner alert, and the message id
// lookup after a duplicate.

const recoveryBody = "hi" + policy.DisclosureSep + "I'm an AI assistant."

func approvedForRecovery(t *testing.T, store *db.Store, uid, convID, randomID int64) int64 {
	t.Helper()
	ctx := context.Background()
	actionID, _ := seedPendingApproval(t, store, uid, convID, "hi")
	if ok, err := store.UpdateAgentActionStatus(ctx, uid, actionID, db.ActionPendingApproval, db.ActionApproved); err != nil || !ok {
		t.Fatalf("approve transition: ok=%v err=%v", ok, err)
	}
	reserveActionForRecovery(t, store, uid, actionID, randomID, recoveryBody)
	return actionID
}

func deliveryUnknownAlerts(t *testing.T, store *db.Store, uid int64) int {
	t.Helper()
	var n int
	if err := store.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM owner_notifications WHERE user_id = $1 AND kind = $2`,
		uid, db.NotificationDeliveryUnknown,
	).Scan(&n); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	return n
}

func setSendAttempts(t *testing.T, store *db.Store, uid, actionID int64, n int) {
	t.Helper()
	if _, err := store.DB.ExecContext(context.Background(),
		`UPDATE agent_actions SET send_attempts = $1 WHERE id = $2 AND user_id = $3`, n, actionID, uid,
	); err != nil {
		t.Fatalf("set send attempts: %v", err)
	}
}

func mustAction(t *testing.T, store *db.Store, uid, actionID int64) *db.AgentAction {
	t.Helper()
	a, err := store.GetAgentAction(context.Background(), uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	return a
}

// TestExecutor_LostAnswerThenDuplicateEndsExecutedOnce is the issue's first
// acceptance case through the real send path: the first attempt lands but
// the RPC answers with a transport error, so send() leaves the row
// executing with one counted attempt; the recovery retry is refused as a
// duplicate, and the action ends executed with the id the history lookup
// found. One message, no further retries.
func TestExecutor_LostAnswerThenDuplicateEndsExecutedOnce(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "hi")
	sender.landThenFail = 1
	sender.locateID = 4242

	if err := exec.Approve(ctx, uid, code); !errors.Is(err, ErrSendQueuedForRetry) {
		t.Fatalf("approve: err=%v, want ErrSendQueuedForRetry", err)
	}
	if a := mustAction(t, store, uid, actionID); a.Status != db.ActionExecuting || a.SendAttempts != 1 {
		t.Fatalf("after the lost answer: status=%q attempts=%d, want executing and 1", a.Status, a.SendAttempts)
	}
	if n, err := exec.RecoverStuck(ctx); err != nil || n != 1 {
		t.Fatalf("first sweep: n=%d err=%v", n, err)
	}
	a := mustAction(t, store, uid, actionID)
	if a.Status != db.ActionExecuted {
		t.Fatalf("status = %q, want executed", a.Status)
	}
	if a.ExecutedTGMessageID != 4242 {
		t.Fatalf("executed message id = %d, want the located 4242", a.ExecutedTGMessageID)
	}
	if n, err := exec.RecoverStuck(ctx); err != nil || n != 0 {
		t.Fatalf("second sweep: n=%d err=%v, want nothing stuck", n, err)
	}
	if len(sender.calls) != 2 {
		t.Fatalf("send RPCs = %d, want 2 (the lost one and the refused retry)", len(sender.calls))
	}
	if got := deliveryUnknownAlerts(t, store, uid); got != 0 {
		t.Fatalf("delivery-unknown alerts = %d, want 0 for a proven delivery", got)
	}
}

// TestExecutor_RecoverStuck_TransientPastBoundEndsDeliveryUnknown is the
// issue's second acceptance case: a retry that keeps failing transiently is
// stopped at the attempt bound, ends delivery_unknown, the owner is alerted
// once, and later sweeps neither send nor alert again.
func TestExecutor_RecoverStuck_TransientPastBoundEndsDeliveryUnknown(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	exec.MaxSendAttempts = 3
	actionID := approvedForRecovery(t, store, uid, conv.ID, 616161)
	sender.failNext = 100

	for i := 0; i < 3; i++ {
		if n, err := exec.RecoverStuck(ctx); err != nil || n != 1 {
			t.Fatalf("sweep %d: n=%d err=%v", i+1, n, err)
		}
	}
	a := mustAction(t, store, uid, actionID)
	if a.Status != db.ActionDeliveryUnknown {
		t.Fatalf("status = %q, want delivery_unknown after %d attempts", a.Status, a.SendAttempts)
	}
	for i := 0; i < 2; i++ {
		if n, err := exec.RecoverStuck(ctx); err != nil || n != 0 {
			t.Fatalf("later sweep: n=%d err=%v, want nothing stuck", n, err)
		}
	}
	if len(sender.calls) != 3 {
		t.Fatalf("send RPCs = %d, want 3", len(sender.calls))
	}
	if got := deliveryUnknownAlerts(t, store, uid); got != 1 {
		t.Fatalf("delivery-unknown alerts = %d, want exactly 1", got)
	}
}

// TestExecutor_RecoverStuck_SpentBudgetDoesNotSendAgain covers a row whose
// attempt budget was spent before this sweep (a crash right after the last
// counted attempt): recovery must stop without another RPC.
func TestExecutor_RecoverStuck_SpentBudgetDoesNotSendAgain(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	exec.MaxSendAttempts = 2
	actionID := approvedForRecovery(t, store, uid, conv.ID, 626262)
	setSendAttempts(t, store, uid, actionID, 2)

	if _, err := exec.RecoverStuck(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send RPCs = %d, want 0 once the budget is spent", len(sender.calls))
	}
	if a := mustAction(t, store, uid, actionID); a.Status != db.ActionDeliveryUnknown {
		t.Fatalf("status = %q, want delivery_unknown", a.Status)
	}
}

// TestExecutor_RecoverStuck_DenyAfterAttemptIsDeliveryUnknown: a takeover
// during the grace window stops the retry either way, but after an RPC was
// already attempted the action may have been delivered, so it must not be
// recorded as denied. Before any attempt, denied stays correct (the
// existing kill-switch test covers that edge).
func TestExecutor_RecoverStuck_DenyAfterAttemptIsDeliveryUnknown(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID := approvedForRecovery(t, store, uid, conv.ID, 636363)
	setSendAttempts(t, store, uid, actionID, 1)
	if err := store.SetConversationState(ctx, uid, conv.ID, db.ConversationTakenOver); err != nil {
		t.Fatalf("take over: %v", err)
	}

	if _, err := exec.RecoverStuck(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send RPCs = %d, want 0 (policy still stops the retry)", len(sender.calls))
	}
	if a := mustAction(t, store, uid, actionID); a.Status != db.ActionDeliveryUnknown {
		t.Fatalf("status = %q, want delivery_unknown", a.Status)
	}
	if got := deliveryUnknownAlerts(t, store, uid); got != 1 {
		t.Fatalf("delivery-unknown alerts = %d, want 1", got)
	}
}

// TestExecutor_RecoverStuck_RestrictedBlockAfterAttemptIsDeliveryUnknown is
// the restricted-field counterpart of the policy case above.
func TestExecutor_RecoverStuck_RestrictedBlockAfterAttemptIsDeliveryUnknown(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	exec.Profile = &fakeRestrictedChecker{key: "salary", value: "hi", neverAutoSend: true, matched: true}
	actionID := approvedForRecovery(t, store, uid, conv.ID, 646464)
	setSendAttempts(t, store, uid, actionID, 1)

	if _, err := exec.RecoverStuck(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send RPCs = %d, want 0", len(sender.calls))
	}
	if a := mustAction(t, store, uid, actionID); a.Status != db.ActionDeliveryUnknown {
		t.Fatalf("status = %q, want delivery_unknown", a.Status)
	}
}

// TestExecutor_Approve_DuplicateOnFirstAttemptIsDelivered: a duplicate on
// the first attempt (a transport-level resend of the same RPC) is a
// delivery, recorded at once rather than reported as queued for retry.
func TestExecutor_Approve_DuplicateOnFirstAttemptIsDelivered(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "hi")
	exec.NewRandomID = func() (int64, error) { return 656565, nil }
	sender.delivered = map[int64]bool{656565: true}
	sender.locateID = 5151

	if err := exec.Approve(ctx, uid, code); err != nil {
		t.Fatalf("approve: %v, want a recorded delivery", err)
	}
	if a := mustAction(t, store, uid, actionID); a.Status != db.ActionExecuted || a.ExecutedTGMessageID != 5151 {
		t.Fatalf("status=%q id=%d, want executed with 5151", a.Status, a.ExecutedTGMessageID)
	}
}

// TestExecutor_RecoverStuck_NotedEchoIsRecordedDespiteDeny: the listener
// matched the echo of a send whose answer was lost and noted its id, so
// delivery is proven. A policy refusal at recovery (here a takeover) must
// not turn that into delivery_unknown and a false alert, and no RPC is
// needed.
func TestExecutor_RecoverStuck_NotedEchoIsRecordedDespiteDeny(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID := approvedForRecovery(t, store, uid, conv.ID, 666666)
	setSendAttempts(t, store, uid, actionID, 1)
	if ok, err := store.MatchUnconfirmedAgentSend(ctx, uid, conv.PeerTGID, 7070, recoveryBody, time.Now().Add(-time.Hour)); err != nil || !ok {
		t.Fatalf("echo match: ok=%v err=%v", ok, err)
	}
	if err := store.SetConversationState(ctx, uid, conv.ID, db.ConversationTakenOver); err != nil {
		t.Fatalf("take over: %v", err)
	}

	if _, err := exec.RecoverStuck(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if len(sender.calls) != 0 {
		t.Fatalf("send RPCs = %d, want 0", len(sender.calls))
	}
	if a := mustAction(t, store, uid, actionID); a.Status != db.ActionExecuted || a.ExecutedTGMessageID != 7070 {
		t.Fatalf("status=%q id=%d, want executed with the echoed 7070", a.Status, a.ExecutedTGMessageID)
	}
	if got := deliveryUnknownAlerts(t, store, uid); got != 0 {
		t.Fatalf("delivery-unknown alerts = %d, want 0", got)
	}
}

// TestExecutor_RecoverStuck_EchoDuringLastRetryIsRecordedNextSweep: the
// listener notes the echo while the last allowed retry is failing, so the
// delivery_unknown compare-and-set loses. The error says so cleanly (no
// wrapped nil), no alert is queued, and the next sweep records the proven
// delivery without another RPC.
func TestExecutor_RecoverStuck_EchoDuringLastRetryIsRecordedNextSweep(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	exec.MaxSendAttempts = 1
	actionID := approvedForRecovery(t, store, uid, conv.ID, 676767)
	sender.failNext = 1
	sender.onSend = func() {
		if ok, err := store.MatchUnconfirmedAgentSend(ctx, uid, conv.PeerTGID, 7171, recoveryBody, time.Now().Add(-time.Hour)); err != nil || !ok {
			t.Errorf("echo match: ok=%v err=%v", ok, err)
		}
	}
	stuck, err := store.ListStuckExecutingActions(ctx, 0)
	if err != nil || len(stuck) != 1 {
		t.Fatalf("list stuck: n=%d err=%v", len(stuck), err)
	}
	err = exec.recoverOne(ctx, stuck[0])
	if err == nil || errors.Is(err, ErrDeliveryUnknown) || strings.Contains(err.Error(), "%!") {
		t.Fatalf("recoverOne err = %v, want a plain retry error", err)
	}
	if got := deliveryUnknownAlerts(t, store, uid); got != 0 {
		t.Fatalf("delivery-unknown alerts = %d, want 0", got)
	}
	sender.onSend = nil
	if _, err := exec.RecoverStuck(ctx); err != nil {
		t.Fatalf("next sweep: %v", err)
	}
	if a := mustAction(t, store, uid, actionID); a.Status != db.ActionExecuted || a.ExecutedTGMessageID != 7171 {
		t.Fatalf("status=%q id=%d, want executed with 7171", a.Status, a.ExecutedTGMessageID)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send RPCs = %d, want 1", len(sender.calls))
	}
}

// TestExecutor_LocateDelivered_SearchesFromTheReservation: the history
// lookup after a duplicate starts at the reservation, not at the draft's
// creation, so an identical message sent while the draft waited for
// approval cannot make it ambiguous.
func TestExecutor_LocateDelivered_SearchesFromTheReservation(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID := approvedForRecovery(t, store, uid, conv.ID, 686868)
	if _, err := store.DB.ExecContext(ctx, `UPDATE agent_actions SET created_at = $1 WHERE id = $2`,
		time.Now().UTC().Add(-20*time.Hour), actionID); err != nil {
		t.Fatalf("backdate draft: %v", err)
	}
	sender.delivered = map[int64]bool{686868: true}
	sender.locateID = 8686

	if _, err := exec.RecoverStuck(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if sender.locateCalls != 1 || time.Since(sender.locateSince) > time.Hour {
		t.Fatalf("lookup calls=%d since=%v, want one lookup from the reservation", sender.locateCalls, sender.locateSince)
	}
}
