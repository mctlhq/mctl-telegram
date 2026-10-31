package executor

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Tests for #1055: definitive refusals, FLOOD_WAIT, and gate-held recovery.

func refused(class string) error {
	return fmt.Errorf("fake send: %w", &SendRefusedError{Class: class})
}

func floodWait(d time.Duration) error {
	return fmt.Errorf("fake send: %w", &FloodWaitError{Wait: d})
}

// TestExecutor_Approve_RefusalOnFirstAttemptIsDenied: USER_IS_BLOCKED on
// the first attempt proves nothing was sent, and no earlier attempt
// exists, so the action is denied with the class as its reason and never
// retried.
func TestExecutor_Approve_RefusalOnFirstAttemptIsDenied(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "hi")
	sender.errs = []error{refused("USER_IS_BLOCKED")}

	if err := exec.Approve(ctx, uid, code); !errors.Is(err, ErrSendRefused) {
		t.Fatalf("approve: err=%v, want ErrSendRefused", err)
	}
	a := mustAction(t, store, uid, actionID)
	if a.Status != db.ActionDenied || a.PolicyReasons != "send refused by Telegram: USER_IS_BLOCKED" || a.SendAttempts != 0 {
		t.Fatalf("status=%q reasons=%q attempts=%d, want denied with the class and 0 attempts", a.Status, a.PolicyReasons, a.SendAttempts)
	}
	if n, err := exec.RecoverStuck(ctx); err != nil || n != 0 {
		t.Fatalf("sweep: n=%d err=%v, want nothing stuck", n, err)
	}
	if got := deliveryUnknownAlerts(t, store, uid); got != 0 {
		t.Fatalf("alerts = %d, want 0", got)
	}
}

// TestExecutor_RecoverStuck_RefusalAfterAmbiguousAttemptIsDeliveryUnknown:
// the refusal proves only that the retry sent nothing. The earlier attempt
// (answer lost) may have landed, so the action ends delivery_unknown, with
// one alert, and is not retried.
func TestExecutor_RecoverStuck_RefusalAfterAmbiguousAttemptIsDeliveryUnknown(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID := approvedForRecovery(t, store, uid, conv.ID, 717171)
	setSendAttempts(t, store, uid, actionID, 1)
	sender.errs = []error{refused("USER_IS_BLOCKED")}

	if _, err := exec.RecoverStuck(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if a := mustAction(t, store, uid, actionID); a.Status != db.ActionDeliveryUnknown {
		t.Fatalf("status = %q, want delivery_unknown", a.Status)
	}
	if got := deliveryUnknownAlerts(t, store, uid); got != 1 {
		t.Fatalf("alerts = %d, want 1", got)
	}
	if n, _ := exec.RecoverStuck(ctx); n != 0 || len(sender.calls) != 1 {
		t.Fatalf("later sweep: stuck=%d sends=%d, want 0 and 1", n, len(sender.calls))
	}
}

// TestExecutor_RecoverStuck_RefusalWithNoEarlierAttemptIsDenied: a crash
// before the first RPC, then a refused retry: nothing was ever sent.
func TestExecutor_RecoverStuck_RefusalWithNoEarlierAttemptIsDenied(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID := approvedForRecovery(t, store, uid, conv.ID, 727272)
	sender.errs = []error{refused("PEER_ID_INVALID")}

	if _, err := exec.RecoverStuck(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if a := mustAction(t, store, uid, actionID); a.Status != db.ActionDenied || a.PolicyReasons != "send refused by Telegram: PEER_ID_INVALID" {
		t.Fatalf("status=%q reasons=%q, want denied with the class", a.Status, a.PolicyReasons)
	}
}

// TestExecutor_RecoverStuck_FloodWaitIsNotAnAttempt: FLOOD_WAIT sent
// nothing, so it does not use up the bound, and recovery waits as told
// instead of retrying on the next sweep.
func TestExecutor_RecoverStuck_FloodWaitIsNotAnAttempt(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	exec.MaxSendAttempts = 1
	actionID := approvedForRecovery(t, store, uid, conv.ID, 737373)
	sender.errs = []error{floodWait(time.Hour)}

	if _, err := exec.RecoverStuck(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	a := mustAction(t, store, uid, actionID)
	if a.Status != db.ActionExecuting || a.SendAttempts != 0 {
		t.Fatalf("status=%q attempts=%d, want executing with 0 attempts", a.Status, a.SendAttempts)
	}
	if n, err := exec.RecoverStuck(ctx); err != nil || n != 0 {
		t.Fatalf("sweep inside the wait: n=%d err=%v, want nothing listed", n, err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send RPCs = %d, want 1", len(sender.calls))
	}
	// Once the wait is over the retry goes out and succeeds.
	if _, err := store.DB.ExecContext(ctx, `UPDATE agent_actions SET retry_not_before = $1 WHERE id = $2`,
		time.Now().UTC().Add(-time.Second), actionID); err != nil {
		t.Fatalf("end the wait: %v", err)
	}
	if n, err := exec.RecoverStuck(ctx); err != nil || n != 1 {
		t.Fatalf("sweep after the wait: n=%d err=%v", n, err)
	}
	if a := mustAction(t, store, uid, actionID); a.Status != db.ActionExecuted {
		t.Fatalf("status = %q, want executed", a.Status)
	}
}

func backdateReservation(t *testing.T, store *db.Store, uid, actionID int64, age time.Duration) {
	t.Helper()
	if _, err := store.DB.ExecContext(context.Background(),
		`UPDATE agent_actions SET updated_at = $1 WHERE id = $2 AND user_id = $3`,
		time.Now().UTC().Add(-age), actionID, uid,
	); err != nil {
		t.Fatalf("backdate reservation: %v", err)
	}
}

// TestExecutor_RecoverStuck_GateHeldPastTTL: a retry the send gate holds
// waits while it is younger than the approval TTL. Past it, with no attempt
// made it is denied ("send gate closed"); after an attempt it ends
// delivery_unknown with one alert.
func TestExecutor_RecoverStuck_GateHeldPastTTL(t *testing.T) {
	cases := []struct {
		name       string
		attempts   int
		age        time.Duration
		wantStatus string
		wantAlerts int
	}{
		{"within the TTL keeps waiting", 0, 30 * time.Minute, db.ActionExecuting, 0},
		{"no attempt past the TTL is denied", 0, 2 * time.Hour, db.ActionDenied, 0},
		{"an attempt past the TTL is delivery unknown", 1, 2 * time.Hour, db.ActionDeliveryUnknown, 1},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec, sender, store, uid, conv := newTestExecutor(t)
			ctx := context.Background()
			exec.ApprovalTTL = time.Hour
			exec.SendGate = func(context.Context, int64, int64) error { return errGateDenied }
			before := deliveryUnknownAlerts(t, store, uid)
			actionID := approvedForRecovery(t, store, uid, conv.ID, int64(747470+i))
			setSendAttempts(t, store, uid, actionID, tc.attempts)
			backdateReservation(t, store, uid, actionID, tc.age)

			if _, err := exec.RecoverStuck(ctx); err != nil {
				t.Fatalf("recover: %v", err)
			}
			a := mustAction(t, store, uid, actionID)
			if a.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", a.Status, tc.wantStatus)
			}
			if tc.wantStatus == db.ActionDenied && a.PolicyReasons != ReasonSendGateClosed {
				t.Fatalf("reasons = %q, want %q", a.PolicyReasons, ReasonSendGateClosed)
			}
			if got := deliveryUnknownAlerts(t, store, uid) - before; got != tc.wantAlerts {
				t.Fatalf("new alerts = %d, want %d", got, tc.wantAlerts)
			}
			if len(sender.calls) != 0 {
				t.Fatalf("send RPCs = %d, want 0 while the gate is closed", len(sender.calls))
			}
		})
	}
}

// TestExecutor_Approve_FloodWaitIsQueuedForRetry: a FLOOD_WAIT on the first
// send leaves the row executing, uncounted, with the wait recorded, and the
// owner is told it is queued.
func TestExecutor_Approve_FloodWaitIsQueuedForRetry(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "hi")
	sender.errs = []error{floodWait(time.Hour)}

	if err := exec.Approve(ctx, uid, code); !errors.Is(err, ErrSendQueuedForRetry) {
		t.Fatalf("approve: err=%v, want ErrSendQueuedForRetry", err)
	}
	a := mustAction(t, store, uid, actionID)
	if a.Status != db.ActionExecuting || a.SendAttempts != 0 {
		t.Fatalf("status=%q attempts=%d, want executing with 0 attempts", a.Status, a.SendAttempts)
	}
	var waiting int
	if err := store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM agent_actions WHERE id = $1 AND retry_not_before > $2`, actionID, time.Now().UTC(),
	).Scan(&waiting); err != nil || waiting != 1 {
		t.Fatalf("retry_not_before set: %d err=%v, want 1", waiting, err)
	}
}

// TestExecutor_FloodWaitOnADecidedRowIsLostRace: the row was decided
// elsewhere while the RPC was in flight. A flood wait then must not claim
// the send is queued (fresh send), and recovery treats it as decided.
func TestExecutor_FloodWaitOnADecidedRowIsLostRace(t *testing.T) {
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "hi")
	sender.errs = []error{floodWait(time.Hour)}
	sender.onSend = func() {
		if ok, err := store.UpdateAgentActionStatus(ctx, uid, actionID, db.ActionExecuting, db.ActionDenied); err != nil || !ok {
			t.Errorf("decide elsewhere: ok=%v err=%v", ok, err)
		}
	}
	if err := exec.Approve(ctx, uid, code); !errors.Is(err, ErrLostRace) {
		t.Fatalf("approve: err=%v, want ErrLostRace", err)
	}

	recID := approvedForRecovery(t, store, uid, conv.ID, 757575)
	sender.errs = []error{floodWait(time.Hour)}
	sender.onSend = func() {
		if ok, err := store.UpdateAgentActionStatus(ctx, uid, recID, db.ActionExecuting, db.ActionDenied); err != nil || !ok {
			t.Errorf("decide elsewhere: ok=%v err=%v", ok, err)
		}
	}
	stuck, err := store.ListStuckExecutingActions(ctx, 0)
	if err != nil {
		t.Fatalf("list stuck: %v", err)
	}
	for _, a := range stuck {
		if a.ID == recID {
			if err := exec.recoverOne(ctx, a); err != nil {
				t.Fatalf("recoverOne: %v, want nil for a row decided elsewhere", err)
			}
			return
		}
	}
	t.Fatal("reserved row not listed as stuck")
}

// TestExecutor_RecoverStuck_FloodWaitPastTTL: flood waits are not
// attempts, so the approval TTL from the reservation is what ends a row
// Telegram keeps throttling: denied with no attempt that could have
// landed, delivery_unknown after one.
func TestExecutor_RecoverStuck_FloodWaitPastTTL(t *testing.T) {
	cases := []struct {
		name       string
		attempts   int
		wantStatus string
	}{
		{"no attempt is denied", 0, db.ActionDenied},
		{"an earlier attempt is delivery unknown", 1, db.ActionDeliveryUnknown},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec, sender, store, uid, conv := newTestExecutor(t)
			ctx := context.Background()
			exec.ApprovalTTL = time.Hour
			actionID := approvedForRecovery(t, store, uid, conv.ID, int64(767670+i))
			setSendAttempts(t, store, uid, actionID, tc.attempts)
			backdateReservation(t, store, uid, actionID, 2*time.Hour)
			sender.errs = []error{floodWait(time.Minute)}

			if _, err := exec.RecoverStuck(ctx); err != nil {
				t.Fatalf("recover: %v", err)
			}
			a := mustAction(t, store, uid, actionID)
			if a.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", a.Status, tc.wantStatus)
			}
			if tc.wantStatus == db.ActionDenied && a.PolicyReasons != ReasonFloodWaitOutlasted {
				t.Fatalf("reasons = %q, want %q", a.PolicyReasons, ReasonFloodWaitOutlasted)
			}
		})
	}
}

// TestExecutor_DenyOnADecidedRowReportsTheRace sweeps the discarded-ok
// class: a deny whose compare-and-set finds the row already decided must
// report that, not the denial it did not make. Fresh send: the gate check
// runs while the owner rejects the draft. Recovery: the kill switch flips
// while the row is decided elsewhere.
func TestExecutor_DenyOnADecidedRowReportsTheRace(t *testing.T) {
	exec, _, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	actionID, code := seedPendingApproval(t, store, uid, conv.ID, "hi")
	exec.SendGate = func(context.Context, int64, int64) error {
		if ok, err := store.UpdateAgentActionStatus(ctx, uid, actionID, db.ActionApproved, db.ActionDenied); err != nil || !ok {
			t.Errorf("decide elsewhere: ok=%v err=%v", ok, err)
		}
		return errGateDenied
	}
	if err := exec.Approve(ctx, uid, code); !errors.Is(err, ErrLostRace) {
		t.Fatalf("approve: err=%v, want ErrLostRace", err)
	}

	exec.SendGate = nil
	recID := approvedForRecovery(t, store, uid, conv.ID, 777001)
	exec.GlobalKill = func() bool {
		if ok, err := store.UpdateAgentActionStatus(ctx, uid, recID, db.ActionExecuting, db.ActionDenied); err != nil || !ok {
			t.Errorf("decide elsewhere: ok=%v err=%v", ok, err)
		}
		return true
	}
	stuck, err := store.ListStuckExecutingActions(ctx, 0)
	if err != nil {
		t.Fatalf("list stuck: %v", err)
	}
	for _, a := range stuck {
		if a.ID == recID {
			if err := exec.recoverOne(ctx, a); err != nil {
				t.Fatalf("recoverOne: %v, want nil for a row decided elsewhere", err)
			}
			return
		}
	}
	t.Fatal("reserved row not listed as stuck")
}
