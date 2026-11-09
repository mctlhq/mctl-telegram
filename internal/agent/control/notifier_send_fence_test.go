package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Default (untagged) regressions for the notifier send-time fence
// (#1268 mode=off, #1269 Reply under GlobalKill, #1270 revoked session).
// Fake sender and in-memory SQLite only; synthetic personas Alice and Bob.

// seedSession gives uid a synthetic active, authorized session row, the state
// the real ClientPool.Borrow also requires before any queued send.
func seedSession(t *testing.T, store *db.Store, uid int64) {
	t.Helper()
	if err := store.SaveSession(context.Background(), uid, []byte("synthetic-session"), 9000000+uid, "Alice", "alice_tg"); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func fenceSetMode(t *testing.T, store *db.Store, uid int64, mode string) {
	t.Helper()
	p, err := store.GetAgentProfile(context.Background(), uid)
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	p.Mode = mode
	if err := store.UpsertAgentProfile(context.Background(), *p); err != nil {
		t.Fatalf("set mode: %v", err)
	}
}

func fenceQueue(t *testing.T, store *db.Store, uid int64, kind, body string) int64 {
	t.Helper()
	id, err := store.InsertOwnerNotification(context.Background(), db.OwnerNotification{UserID: uid, Kind: kind, Body: body})
	if err != nil {
		t.Fatalf("queue: %v", err)
	}
	return id
}

func fenceExpireClaim(t *testing.T, store *db.Store, id int64) {
	t.Helper()
	if _, err := store.DB.Exec(`UPDATE owner_notifications SET claimed_until = $1 WHERE id = $2`,
		time.Now().UTC().Add(-time.Minute), id); err != nil {
		t.Fatalf("expire claim: %v", err)
	}
}

func fenceDeliver(t *testing.T, n *Notifier) (int, int) {
	t.Helper()
	d, f, err := n.DeliverPending(context.Background())
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	return d, f
}

func fenceStatus(t *testing.T, store *db.Store, id int64) string {
	t.Helper()
	s, _ := notificationRow(t, store, id)
	return s
}

func TestSendFence_ModeOffAfterQueueStaysPendingThenResumes(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	seedSession(t, store, uid)
	id := fenceQueue(t, store, uid, db.NotificationSummary, "queued while observe")
	fenceSetMode(t, store, uid, db.AgentModeOff)
	n := NewNotifier(store, sender)

	if d, f := fenceDeliver(t, n); d != 0 || f != 0 {
		t.Fatalf("delivered=%d failed=%d, want 0/0 under mode off", d, f)
	}
	if len(sender.sent) != 0 || fenceStatus(t, store, id) != db.NotificationPending {
		t.Fatalf("sent=%d status=%q, want no send and pending", len(sender.sent), fenceStatus(t, store, id))
	}
	for _, mode := range []string{db.AgentModeObserve, db.AgentModeGuarded} {
		fenceSetMode(t, store, uid, mode)
		d, _ := fenceDeliver(t, n)
		if d != 1 || len(sender.sent) != 1 || fenceStatus(t, store, id) != db.NotificationSent {
			t.Fatalf("mode %s: delivered=%d sent=%d status=%q, want one sent", mode, d, len(sender.sent), fenceStatus(t, store, id))
		}
		// Reset for the next positive mode.
		if _, err := store.DB.Exec(`UPDATE owner_notifications SET status = 'pending', claimed_until = NULL WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		sender.sent, sender.randomIDs = nil, nil
	}
}

func TestSendFence_ModeOffDirectlyInsertedRowNotSent(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	seedSession(t, store, uid)
	fenceSetMode(t, store, uid, db.AgentModeOff)
	id := fenceQueue(t, store, uid, db.NotificationApproval, "inserted while off")
	fenceDeliver(t, NewNotifier(store, sender))
	if len(sender.sent) != 0 || fenceStatus(t, store, id) != db.NotificationPending {
		t.Fatalf("sent=%d status=%q, want none and pending", len(sender.sent), fenceStatus(t, store, id))
	}
}

func TestSendFence_MissingProfileBlocksAgentKindsOnly(t *testing.T) {
	_, _, sender, store, _ := newTestRouter(t)
	bob, err := store.EnsureUser(context.Background(), "bob", "", "test")
	if err != nil {
		t.Fatal(err)
	}
	seedSession(t, store, bob)
	sum := fenceQueue(t, store, bob, db.NotificationSummary, "summary for Bob")
	hi := fenceQueue(t, store, bob, db.NotificationHumanInput, "human input for Bob")
	fenceDeliver(t, NewNotifier(store, sender))
	if fenceStatus(t, store, sum) != db.NotificationPending {
		t.Fatal("agent kind without profile must fail closed and stay pending")
	}
	if fenceStatus(t, store, hi) != db.NotificationSent || len(sender.sent) != 1 || sender.sent[0] != "human input for Bob" {
		t.Fatalf("human_input is profile-independent: status=%q sent=%v", fenceStatus(t, store, hi), sender.sent)
	}
}

func TestSendFence_HumanInputExemptFromModeNotFromKillOrSession(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	fenceSetMode(t, store, uid, db.AgentModeOff)
	id := fenceQueue(t, store, uid, db.NotificationHumanInput, "need input")
	n := NewNotifier(store, sender)

	fenceDeliver(t, n) // mode off but no session: blocked by the session fence
	if len(sender.sent) != 0 {
		t.Fatal("human_input sent without a session")
	}
	seedSession(t, store, uid)
	killed := true
	n.GlobalKill = func() bool { return killed }
	fenceDeliver(t, n)
	if len(sender.sent) != 0 {
		t.Fatal("human_input sent under kill")
	}
	killed = false
	if d, _ := fenceDeliver(t, n); d != 1 || fenceStatus(t, store, id) != db.NotificationSent {
		t.Fatalf("human_input under mode off with session and no kill must send once, delivered=%d", d)
	}
}

func TestSendFence_RevokedSessionAfterQueueNotSentAndResumes(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	seedSession(t, store, uid)
	id := fenceQueue(t, store, uid, db.NotificationSummary, "queued before revoke")
	if ok, err := store.RevokeActiveSession(context.Background(), uid, "test"); err != nil || !ok {
		t.Fatalf("revoke: ok=%v err=%v", ok, err)
	}
	n := NewNotifier(store, sender)
	fenceDeliver(t, n)
	if len(sender.sent) != 0 || fenceStatus(t, store, id) != db.NotificationPending {
		t.Fatalf("sent=%d status=%q, want none and pending", len(sender.sent), fenceStatus(t, store, id))
	}
	seedSession(t, store, uid) // reconnect
	if d, _ := fenceDeliver(t, n); d != 1 || len(sender.sent) != 1 {
		t.Fatalf("after reconnect delivered=%d sent=%d, want 1", d, len(sender.sent))
	}
}

func TestSendFence_NoSessionAtAllNotSent(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	id := fenceQueue(t, store, uid, db.NotificationSummary, "no session")
	fenceDeliver(t, NewNotifier(store, sender))
	if len(sender.sent) != 0 || fenceStatus(t, store, id) != db.NotificationPending {
		t.Fatal("a missing session must not pass the fence")
	}
}

// Unreadable authorization state fails closed. The profile table is dropped
// to force a non-NotFound read error.
func TestSendFence_UnreadableStateFailsClosed(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	seedSession(t, store, uid)
	id := fenceQueue(t, store, uid, db.NotificationSummary, "x")
	if _, err := store.DB.Exec(`ALTER TABLE agent_profiles RENAME TO agent_profiles_gone`); err != nil {
		t.Skipf("cannot break profile table: %v", err)
	}
	d, f := fenceDeliver(t, NewNotifier(store, sender))
	if d != 0 || f != 1 || len(sender.sent) != 0 || fenceStatus(t, store, id) != db.NotificationPending {
		t.Fatalf("delivered=%d failed=%d sent=%d status=%q, want 0/1/0/pending", d, f, len(sender.sent), fenceStatus(t, store, id))
	}
}

func TestSendFence_TwoUsersOneBlockedOneValid(t *testing.T) {
	_, _, sender, store, alice := newTestRouter(t)
	bob, err := store.EnsureUser(context.Background(), "bob", "", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAgentProfile(context.Background(), db.AgentProfile{UserID: bob, Mode: db.AgentModeObserve}); err != nil {
		t.Fatal(err)
	}
	seedSession(t, store, alice)
	seedSession(t, store, bob)
	a := fenceQueue(t, store, alice, db.NotificationSummary, "for Alice")
	b := fenceQueue(t, store, bob, db.NotificationSummary, "for Bob")
	fenceSetMode(t, store, alice, db.AgentModeOff)
	if d, _ := fenceDeliver(t, NewNotifier(store, sender)); d != 1 {
		t.Fatalf("delivered=%d, want 1", d)
	}
	if fenceStatus(t, store, a) != db.NotificationPending || fenceStatus(t, store, b) != db.NotificationSent {
		t.Fatalf("alice=%q bob=%q, want pending/sent", fenceStatus(t, store, a), fenceStatus(t, store, b))
	}
	if len(sender.sent) != 1 || sender.sent[0] != "for Bob" {
		t.Fatalf("sent=%v, want only Bob's", sender.sent)
	}
}

// Mid-batch flip: the kill switch turns on after the first notification is
// sent, while the sweep is already running. The entry check passed, so only
// the per-notification fence can stop the second one.
func TestSendFence_MidBatchKillStopsLaterNotifications(t *testing.T) {
	_, _, base, store, uid := newTestRouter(t)
	seedSession(t, store, uid)
	first := fenceQueue(t, store, uid, db.NotificationSummary, "first")
	second := fenceQueue(t, store, uid, db.NotificationSummary, "second")
	killed := false
	sender := &killAfterSender{inner: base, onFirst: func() { killed = true }}
	n := NewNotifier(store, sender)
	n.GlobalKill = func() bool { return killed }

	d, _ := fenceDeliver(t, n)
	if d != 1 || len(base.sent) != 1 || base.sent[0] != "first" {
		t.Fatalf("delivered=%d sent=%v, want only first", d, base.sent)
	}
	if fenceStatus(t, store, first) != db.NotificationSent || fenceStatus(t, store, second) != db.NotificationPending {
		t.Fatalf("first=%q second=%q", fenceStatus(t, store, first), fenceStatus(t, store, second))
	}
	killed = false
	if d, _ := fenceDeliver(t, n); d != 1 || len(base.sent) != 2 {
		t.Fatalf("resume: delivered=%d sent=%v, want second once", d, base.sent)
	}
}

// Mid-batch mode flip, same shape as the kill test.
func TestSendFence_MidBatchModeOffStopsLaterNotifications(t *testing.T) {
	_, _, base, store, uid := newTestRouter(t)
	seedSession(t, store, uid)
	fenceQueue(t, store, uid, db.NotificationSummary, "first")
	second := fenceQueue(t, store, uid, db.NotificationSummary, "second")
	sender := &killAfterSender{inner: base, onFirst: func() { fenceSetMode(t, store, uid, db.AgentModeOff) }}
	fenceDeliver(t, NewNotifier(store, sender))
	if len(base.sent) != 1 || fenceStatus(t, store, second) != db.NotificationPending {
		t.Fatalf("sent=%v second=%q, want only first", base.sent, fenceStatus(t, store, second))
	}
}

// Mid-batch revoke.
func TestSendFence_MidBatchRevokeStopsLaterNotifications(t *testing.T) {
	_, _, base, store, uid := newTestRouter(t)
	seedSession(t, store, uid)
	fenceQueue(t, store, uid, db.NotificationSummary, "first")
	second := fenceQueue(t, store, uid, db.NotificationSummary, "second")
	sender := &killAfterSender{inner: base, onFirst: func() {
		if _, err := store.RevokeActiveSession(context.Background(), uid, "test"); err != nil {
			t.Error(err)
		}
	}}
	fenceDeliver(t, NewNotifier(store, sender))
	if len(base.sent) != 1 || fenceStatus(t, store, second) != db.NotificationPending {
		t.Fatalf("sent=%v second=%q, want only first", base.sent, fenceStatus(t, store, second))
	}
}

// The final boundary guard: a flip BETWEEN the pre-claim check and the send
// (here, during format-time lookups is not injectable, so the flip happens in
// the claimed-row window through the Store read of the first send). The state
// is asserted through the persisted random_id: a row blocked at the final
// boundary is claimed with its id persisted, and resumes with the SAME id.
func TestSendFence_FinalBoundaryBlockKeepsClaimAndRandomID(t *testing.T) {
	_, _, base, store, uid := newTestRouter(t)
	seedSession(t, store, uid)
	id := fenceQueue(t, store, uid, db.NotificationSummary, "x")
	calls := 0
	n := NewNotifier(store, base)
	// The kill hook is evaluated at: sweep entry (1), pre-claim fence (2),
	// final fence (3). Flip it on at the third read so only the final
	// boundary check can stop the send.
	n.GlobalKill = func() bool { calls++; return calls == 3 }
	fenceDeliver(t, n)
	if len(base.sent) != 0 {
		t.Fatalf("sent=%v, want no send when the final check blocks", base.sent)
	}
	var rid int64
	if err := store.DB.QueryRow(`SELECT random_id FROM owner_notifications WHERE id = $1`, id).Scan(&rid); err != nil || rid == 0 {
		t.Fatalf("random_id=%d err=%v, want persisted by the claim", rid, err)
	}
	if fenceStatus(t, store, id) != db.NotificationPending {
		t.Fatal("blocked row must stay pending")
	}
	fenceExpireClaim(t, store, id)
	fenceDeliver(t, n)
	if len(base.randomIDs) != 1 || base.randomIDs[0] != rid {
		t.Fatalf("resume random ids=%v, want the persisted %d reused", base.randomIDs, rid)
	}
}

func TestSendFence_ReplyUnderKillIsDeniedWithoutSend(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	killed := true
	n := NewNotifier(store, sender)
	n.GlobalKill = func() bool { return killed }
	err := n.Reply(context.Background(), uid, "hello")
	if !errors.Is(err, ErrSendBlocked) {
		t.Fatalf("err = %v, want ErrSendBlocked", err)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("sent=%v, want none", sender.sent)
	}
	killed = false
	if err := n.Reply(context.Background(), uid, "hello"); err != nil || len(sender.sent) != 1 {
		t.Fatalf("after kill clears: err=%v sent=%v, want one reply", err, sender.sent)
	}
}

// Owner command replies are not gated by mode or session.
func TestSendFence_ReplyIgnoresModeAndSession(t *testing.T) {
	_, _, sender, store, uid := newTestRouter(t)
	fenceSetMode(t, store, uid, db.AgentModeOff)
	if err := NewNotifier(store, sender).Reply(context.Background(), uid, "status"); err != nil || len(sender.sent) != 1 {
		t.Fatalf("err=%v sent=%v, want a reply while mode is off and no session", err, sender.sent)
	}
}

// killAfterSender runs onFirst once after the first successful send.
type killAfterSender struct {
	inner   *fakeSelfSender
	onFirst func()
	fired   bool
}

func (k *killAfterSender) SendToSelf(ctx context.Context, userID int64, text string) (int64, error) {
	return k.inner.SendToSelf(ctx, userID, text)
}

func (k *killAfterSender) SendToSelfWithRandomID(ctx context.Context, userID, randomID int64, text string) (int64, error) {
	id, err := k.inner.SendToSelfWithRandomID(ctx, userID, randomID, text)
	if !k.fired {
		k.fired = true
		k.onFirst()
	}
	return id, err
}
