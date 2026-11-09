package control

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
		fenceExpireClaim(t, store, id) // the blocked row was deferred by lease
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
	fenceExpireClaim(t, store, id) // session-blocked sweep deferred the row by lease
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
	fenceExpireClaim(t, store, id)
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
	fenceExpireClaim(t, store, second) // blocked mid-batch: deferred by lease
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

// fenceAge backdates a row's created_at with a synthetic timestamp so ordering
// and MaxPendingAge are deterministic without sleeping.
func fenceAge(t *testing.T, store *db.Store, id int64, age time.Duration) {
	t.Helper()
	if _, err := store.DB.Exec(`UPDATE owner_notifications SET created_at = $1 WHERE id = $2`,
		time.Now().UTC().Add(-age), id); err != nil {
		t.Fatalf("age row: %v", err)
	}
}

// fenceLease reports the persisted claim state of a row.
func fenceLease(t *testing.T, store *db.Store, id int64) (randomID int64, leased bool) {
	t.Helper()
	var rid sql.NullInt64
	var until sql.NullTime
	if err := store.DB.QueryRow(`SELECT random_id, claimed_until FROM owner_notifications WHERE id = $1`, id).Scan(&rid, &until); err != nil {
		t.Fatalf("read lease: %v", err)
	}
	return rid.Int64, until.Valid && until.Time.After(time.Now().UTC())
}

// fenceUser creates a synthetic persona with an observe profile and session.
func fenceUser(t *testing.T, store *db.Store, name string) int64 {
	t.Helper()
	uid, err := store.EnsureUser(context.Background(), name, "", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertAgentProfile(context.Background(), db.AgentProfile{UserID: uid, Mode: db.AgentModeObserve}); err != nil {
		t.Fatal(err)
	}
	seedSession(t, store, uid)
	return uid
}

// Reviewed starvation blocker: more than 50 older notifications for a blocked
// user used to fill the oldest-50 batch on every sweep, unclaimed, so a newer
// healthy user's notification was never reached. A blocked row is now claimed
// with the existing lease and not sent, which takes it out of the pending
// listing until the lease expires.
func TestSendFence_BlockedOldest50DoesNotStarveHealthyUser(t *testing.T) {
	_, _, sender, store, alice := newTestRouter(t)
	bob := fenceUser(t, store, "bob")
	seedSession(t, store, alice)
	const blocked = 51
	ids := make([]int64, 0, blocked)
	for i := 0; i < blocked; i++ {
		id := fenceQueue(t, store, alice, db.NotificationSummary, fmt.Sprintf("alice-%d", i))
		fenceAge(t, store, id, time.Hour+time.Duration(blocked-i)*time.Minute) // older than bob's, oldest first
		ids = append(ids, id)
	}
	bobID := fenceQueue(t, store, bob, db.NotificationSummary, "bob-1")
	fenceAge(t, store, bobID, time.Minute)
	fenceSetMode(t, store, alice, db.AgentModeOff)
	n := NewNotifier(store, sender)

	delivered := 0
	for sweep := 0; sweep < 3 && fenceStatus(t, store, bobID) != db.NotificationSent; sweep++ {
		d, _ := fenceDeliver(t, n)
		delivered += d
	}
	if fenceStatus(t, store, bobID) != db.NotificationSent || delivered != 1 {
		t.Fatalf("healthy user starved: bob status=%q delivered=%d sent=%v", fenceStatus(t, store, bobID), delivered, sender.sent)
	}
	if len(sender.sent) != 1 || sender.sent[0] != "bob-1" {
		t.Fatalf("sent=%v, want only bob-1 and zero blocked-user sends", sender.sent)
	}
	rids := map[int64]int64{}
	for _, id := range ids {
		rid, leased := fenceLease(t, store, id)
		if fenceStatus(t, store, id) != db.NotificationPending || !leased || rid == 0 {
			t.Fatalf("row %d: status=%q leased=%v random_id=%d, want pending, leased, id persisted", id, fenceStatus(t, store, id), leased, rid)
		}
		rids[id] = rid
	}

	// Lease expiry and resume: the same persisted random_ids are reused.
	for _, id := range ids {
		fenceExpireClaim(t, store, id)
	}
	fenceSetMode(t, store, alice, db.AgentModeObserve)
	for sweep := 0; sweep < 3 && len(sender.sent) < 1+blocked; sweep++ {
		fenceDeliver(t, n)
	}
	if len(sender.sent) != 1+blocked {
		t.Fatalf("after resume sent=%d, want %d", len(sender.sent), 1+blocked)
	}
	want := map[int64]bool{}
	for _, rid := range rids {
		want[rid] = true
	}
	for _, rid := range sender.randomIDs[1:] { // [0] is bob's
		if !want[rid] {
			t.Fatalf("resumed send used random_id %d not persisted at block time", rid)
		}
		delete(want, rid)
	}
	if len(want) != 0 {
		t.Fatalf("persisted random ids never reused: %v", want)
	}
}

// MaxPendingAge applies to blocked rows as it did to failing sends: too-old
// rows are retired (status failed, never sent), not-too-old rows stay pending
// and leased, and another user's healthy queue progresses. The returned failed
// count here is retirements; an aged-out row is not a delivered message.
func TestSendFence_BlockedRowsAgeOutByMaxPendingAge(t *testing.T) {
	_, _, sender, store, alice := newTestRouter(t) // alice: mode off
	carol := fenceUser(t, store, "carol")          // carol: session revoked
	bob := fenceUser(t, store, "bob")              // bob: healthy
	seedSession(t, store, alice)
	fenceSetMode(t, store, alice, db.AgentModeOff)
	if ok, err := store.RevokeActiveSession(context.Background(), carol, "test"); err != nil || !ok {
		t.Fatalf("revoke: ok=%v err=%v", ok, err)
	}
	var old, young []int64
	for _, uid := range []int64{alice, carol} {
		o := fenceQueue(t, store, uid, db.NotificationSummary, "old")
		fenceAge(t, store, o, 25*time.Hour)
		y := fenceQueue(t, store, uid, db.NotificationSummary, "young")
		fenceAge(t, store, y, time.Hour)
		old, young = append(old, o), append(young, y)
	}
	b := fenceQueue(t, store, bob, db.NotificationSummary, "bob-1")
	fenceAge(t, store, b, time.Minute)

	n := NewNotifier(store, sender) // MaxPendingAge 24h
	d, f := fenceDeliver(t, n)
	if d != 1 || f != 2 {
		t.Fatalf("delivered=%d failed=%d, want 1 delivered (bob) and 2 retired", d, f)
	}
	if len(sender.sent) != 1 || sender.sent[0] != "bob-1" || fenceStatus(t, store, b) != db.NotificationSent {
		t.Fatalf("sent=%v: only the healthy user may be sent", sender.sent)
	}
	for _, id := range old {
		if got := fenceStatus(t, store, id); got != db.NotificationFailed {
			t.Fatalf("old blocked row %d status=%q, want failed (aged out, not sent)", id, got)
		}
	}
	for _, id := range young {
		rid, leased := fenceLease(t, store, id)
		if fenceStatus(t, store, id) != db.NotificationPending || !leased || rid == 0 {
			t.Fatalf("young blocked row %d: status=%q leased=%v rid=%d, want pending and leased", id, fenceStatus(t, store, id), leased, rid)
		}
	}
}

// MaxPendingAge <= 0 keeps its existing meaning: no age limit.
func TestSendFence_BlockedRowsNeverAgeOutWithoutMaxPendingAge(t *testing.T) {
	_, _, sender, store, alice := newTestRouter(t)
	seedSession(t, store, alice)
	fenceSetMode(t, store, alice, db.AgentModeOff)
	id := fenceQueue(t, store, alice, db.NotificationSummary, "ancient")
	fenceAge(t, store, id, 1000*time.Hour)
	n := NewNotifier(store, sender)
	n.MaxPendingAge = 0
	if d, f := fenceDeliver(t, n); d != 0 || f != 0 {
		t.Fatalf("delivered=%d failed=%d, want 0/0", d, f)
	}
	if _, leased := fenceLease(t, store, id); fenceStatus(t, store, id) != db.NotificationPending || !leased || len(sender.sent) != 0 {
		t.Fatalf("status=%q leased=%v sent=%v, want pending, leased, unsent", fenceStatus(t, store, id), leased, sender.sent)
	}
}

// Final send boundary, isolated: the pre-claim fence PASSES, then the state
// flips as a side effect of the claim itself (a SQLite trigger fires on the
// claim UPDATE, standing in for a flip that lands between the pre-claim check
// and the send). Only the final boundary fence can stop the send. The
// assertion is the forbidden effect, not a call count: the fake sender must
// record no send and the row must not become sent. Removing the final
// sendFence call makes the sender record a send and the row go sent.
func TestSendFence_FinalBoundaryFlipAfterClaimIsNeverSent(t *testing.T) {
	flips := map[string]struct {
		trigger string
		kill    bool
	}{
		"mode_off": {trigger: `UPDATE agent_profiles SET mode = 'off' WHERE user_id = NEW.user_id;`},
		"session_revoked": {trigger: `UPDATE telegram_accounts SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = NEW.user_id AND revoked_at IS NULL;`},
		"global_kill": {kill: true},
	}
	for name, flip := range flips {
		t.Run(name, func(t *testing.T) {
			_, _, sender, store, uid := newTestRouter(t)
			seedSession(t, store, uid)
			id := fenceQueue(t, store, uid, db.NotificationSummary, "must not leave")
			n := NewNotifier(store, sender)
			if flip.trigger != "" {
				if _, err := store.DB.Exec(`CREATE TRIGGER fence_flip AFTER UPDATE OF claimed_until ON owner_notifications
					WHEN NEW.claimed_until IS NOT NULL BEGIN ` + flip.trigger + ` END`); err != nil {
					t.Fatalf("create flip trigger: %v", err)
				}
			}
			if flip.kill {
				// Kill turns on exactly when the row is claimed; reads state, not a call count.
				n.GlobalKill = func() bool {
					var c int
					_ = store.DB.QueryRow(`SELECT COUNT(*) FROM owner_notifications WHERE id = $1 AND claimed_until IS NOT NULL`, id).Scan(&c)
					return c > 0
				}
			}
			fenceDeliver(t, n)
			if len(sender.sent) != 0 || len(sender.randomIDs) != 0 {
				t.Fatalf("unauthorized send reached the sender after the flip: %v", sender.sent)
			}
			if got := fenceStatus(t, store, id); got != db.NotificationPending {
				t.Fatalf("row status=%q, want pending (a denied send must never mark sent)", got)
			}
			if rid, leased := fenceLease(t, store, id); rid == 0 || !leased {
				t.Fatalf("random_id=%d leased=%v, want claimed row with persisted id", rid, leased)
			}
		})
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
