//go:build l2finance

package control

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func l2Deliver(t *testing.T, h *l2NotifierHarness) (int, int) {
	t.Helper()
	d, f, err := h.notifier.DeliverPending(context.Background())
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	return d, f
}

func l2Must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestL2Finance_T1_NotifierSelfOnly(t *testing.T) {
	h := l2NewNotifierHarness(t, true)
	h.queue(t, h.alice, "summary for alice")
	l2Deliver(t, h)
	l2Must(t, l2CheckOnlyOwnUser(h, map[string]int64{"summary for alice": h.alice}))
	l2Must(t, l2CheckNoPeerSink(h))
	if s := h.sink.snapshot(); len(s) != 1 || !s[0].viaRandomID {
		t.Fatalf("sends = %+v, want one random_id send", s)
	}
	l2Record(t, "T1.notifier_self_only", l2Pass, "one random_id send to owner; peer sink empty")
}

func TestL2Finance_T3_PerUser(t *testing.T) {
	h := l2NewNotifierHarness(t, true)
	h.queue(t, h.alice, "summary for alice")
	h.queue(t, h.carol, "summary for carol")
	l2Deliver(t, h)
	l2Must(t, l2CheckOnlyOwnUser(h, map[string]int64{
		"summary for alice": h.alice, "summary for carol": h.carol,
	}))
	l2Record(t, "T3.per_user", l2Pass, "each text delivered only under its own user id")
}

func TestL2Finance_T3_FinanceSource(t *testing.T) {
	typ := reflect.TypeOf(db.OwnerNotification{})
	for i := 0; i < typ.NumField(); i++ {
		if n := strings.ToLower(typ.Field(i).Name); strings.Contains(n, "source") || strings.Contains(n, "finance") {
			t.Fatalf("OwnerNotification gained field %s; update rubric via reviewed PR", typ.Field(i).Name)
		}
	}
	l2Record(t, "T3.finance_source", l2NotImplemented, "no finance-source field on owner notifications")
}

func TestL2Finance_T5_2_RandomID(t *testing.T) {
	h := l2NewNotifierHarness(t, true)
	id := h.queue(t, h.alice, "summary for alice")
	h.sink.failNext, h.sink.recordOnFail = 1, true
	if _, f := l2Deliver(t, h); f != 1 {
		t.Fatalf("first sweep failed = %d, want 1", f)
	}
	_, err := h.store.DB.Exec(`UPDATE owner_notifications SET claimed_until = $1 WHERE id = $2`,
		time.Now().UTC().Add(-time.Minute), id)
	l2Must(t, err)
	l2Deliver(t, h)
	if got := h.status(t, id); got != db.NotificationSent {
		t.Fatalf("status = %q, want sent", got)
	}
	ids := map[int64]bool{}
	for _, s := range h.sink.snapshot() {
		ids[s.randomID] = true
	}
	if len(ids) != 1 || len(h.sink.seenIDs) != 1 {
		t.Fatalf("distinct random ids = %d, want 1", len(ids))
	}
	l2Record(t, "T5.2.random_id", l2Pass, "retry reused the persisted random_id; duplicate treated as delivered; row sent")
}

func TestL2Finance_T8_Kill(t *testing.T) {
	h := l2NewNotifierHarness(t, true)
	id := h.queue(t, h.alice, "summary for alice")
	h.killOn.Store(true)
	l2Deliver(t, h)
	l2Must(t, l2CheckNoSend(h))
	if got := h.status(t, id); got != db.NotificationPending {
		t.Fatalf("status under kill = %q, want pending", got)
	}
	h.killOn.Store(false)
	l2Deliver(t, h)
	l2Must(t, l2CheckOnlyOwnUser(h, map[string]int64{"summary for alice": h.alice}))
	l2Record(t, "T8.kill", l2Pass, "0 sends and row pending under kill; delivered once after clear")
}

func TestL2Finance_T8_ModeOffAfterQueue(t *testing.T) {
	h := l2NewNotifierHarness(t, true)
	h.queue(t, h.alice, "queued while observe")
	h.setMode(t, h.alice, db.AgentModeOff)
	l2Deliver(t, h)
	expectGap(t, "T8.mode_off_after_queue", len(h.sink.snapshot()) == 1,
		"DeliverPending sent after mode=off; no delivery-time mode check")
}

func TestL2Finance_T8_ModeOffBeforeQueueDelivery(t *testing.T) {
	h := l2NewNotifierHarness(t, true)
	h.setMode(t, h.alice, db.AgentModeOff)
	h.queue(t, h.alice, "inserted while off")
	l2Deliver(t, h)
	expectGap(t, "T8.mode_off_before_queue.delivery", len(h.sink.snapshot()) == 1,
		"row inserted directly while mode=off was delivered; queue-time refusal is the policy package's row and is not claimed here")
}

func TestL2Finance_T8_RevokedAfterQueue(t *testing.T) {
	h := l2NewNotifierHarness(t, true)
	ctx := context.Background()
	l2Must(t, h.store.SaveSession(ctx, h.alice, []byte("synthetic-session"), 100, "Alice", "alice_tg"))
	h.queue(t, h.alice, "queued before revoke")
	revoked, err := h.store.RevokeActiveSession(ctx, h.alice, "l2finance")
	l2Must(t, err)
	if !revoked {
		t.Fatal("RevokeActiveSession revoked nothing; fixture session missing")
	}
	l2Deliver(t, h)
	expectGap(t, "T8.revoked_after_queue", len(h.sink.snapshot()) == 1,
		"Notifier called the sender after session revocation; no Notifier-level fence")
}

func TestL2Finance_T8_RevokedPoolFence(t *testing.T) {
	l2Record(t, "T8.revoked_pool_fence", l2CannotObserve,
		"production fence is ClientPool.Borrow -> Store.CheckSessionValid beneath the SelfSender; a fake sender bypasses it")
}

func TestL2Finance_T8_ReplyKill(t *testing.T) {
	h := l2NewNotifierHarness(t, true)
	h.killOn.Store(true)
	l2Must(t, h.router.HandleSavedText(context.Background(), SavedMeta{UserID: h.alice}, "/mctl status"))
	expectGap(t, "T8.reply_kill", len(h.sink.snapshot()) == 1,
		"Reply sent while GlobalKill is true; Reply is not gated by the kill switch")
}

// M2: the kill hook is omitted although the switch is on. The T8.kill helper
// must detect the resulting send.
func TestL2Finance_M2_KillHookOmitted(t *testing.T) {
	h := l2NewNotifierHarness(t, false)
	h.killOn.Store(true)
	h.queue(t, h.alice, "summary for alice")
	l2Deliver(t, h)
	if l2CheckNoSend(h) == nil {
		t.Fatal("negative control M2 not detected")
	}
	l2Record(t, "M2", l2Pass, "detected")
}

// M3: a sender that also copies to a peer. The peer helper must detect it.
func TestL2Finance_M3_PeerLeak(t *testing.T) {
	h := l2NewNotifierHarness(t, true)
	h.setSender(&l2LeakySink{inner: h.sink, peer: h.peer}, true)
	h.queue(t, h.alice, "summary for alice")
	l2Deliver(t, h)
	if l2CheckNoPeerSink(h) == nil {
		t.Fatal("negative control M3 not detected")
	}
	l2Record(t, "M3", l2Pass, "detected")
}
