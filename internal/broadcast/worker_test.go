package broadcast

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// fakeSender scripts per-chat results and records every send. before, when
// set, runs just before a send is recorded -- the seam for races such as an
// unsubscribe or a cancel landing mid-batch.
type fakeSender struct {
	mu      sync.Mutex
	results map[int64][]error
	sent    []sent
	before  func(chatID int64)
}

type sent struct {
	chatID int64
	text   string
}

func (f *fakeSender) SendMessage(_ context.Context, chatID int64, text string) error {
	if f.before != nil {
		f.before(chatID)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sent{chatID, text})
	if q := f.results[chatID]; len(q) > 0 {
		err := q[0]
		if len(q) > 1 {
			f.results[chatID] = q[1:]
		}
		return err
	}
	return nil
}

func (f *fakeSender) count(chatID int64) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, s := range f.sent {
		if s.chatID == chatID {
			n++
		}
	}
	return n
}

type wenv struct {
	*env
	sender *fakeSender
	worker *Worker
}

func newWorkerEnv(t *testing.T, mutate ...func(*WorkerConfig)) *wenv {
	t.Helper()
	e := newEnv(t)
	cfg := WorkerConfig{Policy: e.svc.cfg.Policy, RatePerSecond: 1000, BatchSize: 50, MaxAttempts: 3,
		BaseBackoff: time.Minute, MaxBackoff: 10 * time.Minute, Lease: 2 * time.Minute}
	for _, m := range mutate {
		m(&cfg)
	}
	s := &fakeSender{results: map[int64][]error{}}
	return &wenv{env: e, sender: s, worker: NewWorker(e.store, s, cfg, func() time.Time { return e.now })}
}

// approved prepares and approves a maintenance campaign.
func (w *wenv) approved(text string) *Preview {
	w.t.Helper()
	p := w.prepare(Selector{Category: "maintenance"}, text)
	if err := w.svc.Approve(context.Background(), w.op, p.CampaignID, p.ContentHash, p.SelectorHash); err != nil {
		w.t.Fatalf("approve: %v", err)
	}
	return p
}

func (w *wenv) tick() {
	w.t.Helper()
	if err := w.worker.Tick(context.Background()); err != nil {
		w.t.Fatalf("tick: %v", err)
	}
}

// delivery returns (status, reason, attempts) for one recipient.
func (w *wenv) delivery(campaignID string, userID int64) (string, string, int) {
	w.t.Helper()
	var st, reason string
	var attempts int
	err := w.store.DB.QueryRow(`SELECT status, reason, attempts FROM broadcast_deliveries WHERE campaign_id = $1 AND user_id = $2`,
		campaignID, userID).Scan(&st, &reason, &attempts)
	if err != nil {
		return "", "", 0
	}
	return st, reason, attempts
}

func (w *wenv) reach(userID int64) string {
	w.t.Helper()
	f, err := w.store.GetBroadcastRecipientFacts(context.Background(), userID, w.now)
	if err != nil || f == nil {
		w.t.Fatalf("facts: %v", err)
	}
	return f.Reachability
}

func TestWorker_DeliversApprovedCampaignExactlyOnce(t *testing.T) {
	w := newWorkerEnv(t)
	a := w.user(123450001, db.TierClient)
	b := w.user(123450002, db.TierClient)
	p := w.approved("Maintenance tonight 22:00 UTC.")

	w.tick()
	for _, u := range []int64{a, b} {
		if st, _, n := w.delivery(p.CampaignID, u); st != db.DeliveryDelivered || n != 1 {
			t.Fatalf("user %d: status=%s attempts=%d", u, st, n)
		}
		if got := w.reach(u); got != notify.StateReachable {
			t.Fatalf("user %d reachability = %q, want reachable", u, got)
		}
	}
	for _, s := range w.sender.sent {
		if s.text != "Maintenance tonight 22:00 UTC." {
			t.Fatalf("sent text %q differs from the approved text", s.text)
		}
	}
	if got := w.state(p.CampaignID); got != db.CampaignCompleted {
		t.Fatalf("campaign state = %s, want completed", got)
	}
	w.tick()
	w.tick()
	if len(w.sender.sent) != 2 {
		t.Fatalf("sent %d messages over three ticks, want exactly 2", len(w.sender.sent))
	}
}

func TestWorker_NeverSendsWithoutApproval(t *testing.T) {
	w := newWorkerEnv(t)
	w.user(123450001, db.TierClient)
	p := w.prepare(Selector{Category: "maintenance"}, "Not approved.")
	w.tick()
	if len(w.sender.sent) != 0 {
		t.Fatalf("a prepared campaign was sent: %+v", w.sender.sent)
	}
	if got := w.state(p.CampaignID); got != db.CampaignPrepared {
		t.Fatalf("state = %s", got)
	}
}

func TestWorker_UnsubscribeBetweenApprovalAndStartIsNotQueued(t *testing.T) {
	w := newWorkerEnv(t)
	stay := w.user(123450001, db.TierClient)
	leave := w.user(123450002, db.TierClient)
	p := w.approved("Hello.")
	if err := w.store.SetNotificationPrefs(context.Background(), leave, map[string]string{"maintenance": db.PrefUnsubscribed}, "test"); err != nil {
		t.Fatal(err)
	}
	w.tick()
	if st, _, _ := w.delivery(p.CampaignID, leave); st != "" {
		t.Fatalf("unsubscribed user was queued with status %s", st)
	}
	if w.sender.count(123450002) != 0 {
		t.Fatal("unsubscribed user was sent to")
	}
	if st, _, _ := w.delivery(p.CampaignID, stay); st != db.DeliveryDelivered {
		t.Fatalf("remaining user status = %s", st)
	}
}

func TestWorker_ConsentRecheckedImmediatelyBeforeEachSend(t *testing.T) {
	w := newWorkerEnv(t)
	first := w.user(123450001, db.TierClient)
	second := w.user(123450002, db.TierClient)
	p := w.approved("Hello.")
	// The unsubscribe lands after both recipients were queued, while the
	// batch is already running: the second send must not happen.
	w.sender.before = func(chatID int64) {
		if chatID == 123450001 {
			if err := w.store.SetNotificationPrefs(context.Background(), second, map[string]string{"maintenance": db.PrefUnsubscribed}, "test"); err != nil {
				t.Error(err)
			}
		}
	}
	w.tick()
	if st, _, _ := w.delivery(p.CampaignID, first); st != db.DeliveryDelivered {
		t.Fatalf("first = %s", st)
	}
	if st, reason, _ := w.delivery(p.CampaignID, second); st != db.DeliverySkipped || reason != string(SkipUnsubscribed) {
		t.Fatalf("second = %s/%s, want skipped/unsubscribed", st, reason)
	}
	if w.sender.count(123450002) != 0 {
		t.Fatal("sent to a client who unsubscribed mid-batch")
	}
}

func TestWorker_PermanentFailureUpdatesReachability(t *testing.T) {
	w := newWorkerEnv(t)
	blocked := w.user(123450001, db.TierClient)
	never := w.user(123450002, db.TierClient)
	w.sender.results[123450001] = []error{&notify.APIError{StatusCode: 403, Description: "Forbidden: bot was blocked by the user"}}
	w.sender.results[123450002] = []error{&notify.APIError{StatusCode: 403, Description: "Forbidden: bot can't initiate conversation with a user"}}
	p := w.approved("Hello.")
	w.tick()
	if st, reason, _ := w.delivery(p.CampaignID, blocked); st != db.DeliveryFailed || reason != "bot_blocked" {
		t.Fatalf("blocked = %s/%s", st, reason)
	}
	if st, reason, _ := w.delivery(p.CampaignID, never); st != db.DeliveryFailed || reason != "cannot_initiate_conversation" {
		t.Fatalf("never = %s/%s", st, reason)
	}
	if w.reach(blocked) != notify.StateBlocked || w.reach(never) != notify.StateCannotInitiate {
		t.Fatalf("reachability not updated: %s, %s", w.reach(blocked), w.reach(never))
	}
	if w.sender.count(123450001) != 1 {
		t.Fatal("a permanent failure was retried")
	}
	// The next campaign skips them up front.
	w.user(123450003, db.TierClient)
	next := w.prepare(Selector{Category: "maintenance"}, "Next.")
	if next.Counts.Skipped[string(SkipUnreachable)] != 2 {
		t.Fatalf("next preview skipped %+v, want 2 unreachable", next.Counts.Skipped)
	}
}

func TestWorker_TransientFailureRetriesWithBackoffAndRetryAfter(t *testing.T) {
	w := newWorkerEnv(t)
	u := w.user(123450001, db.TierClient)
	w.sender.results[123450001] = []error{
		&notify.APIError{StatusCode: 429, Description: "Too Many Requests", RetryAfter: 5 * time.Minute},
		nil,
	}
	p := w.approved("Hello.")
	w.tick()
	st, reason, n := w.delivery(p.CampaignID, u)
	if st != db.DeliveryPending || reason != ReasonTransient || n != 1 {
		t.Fatalf("after 429: %s/%s/%d", st, reason, n)
	}
	if got := w.reach(u); got != "" {
		t.Fatalf("a 429 changed reachability to %q", got)
	}
	// retry_after (5m) beats the 1m base backoff: not due at +4m.
	w.now = w.now.Add(4 * time.Minute)
	w.tick()
	if w.sender.count(123450001) != 1 {
		t.Fatal("retried before retry_after elapsed")
	}
	w.now = w.now.Add(2 * time.Minute)
	w.tick()
	if st, _, n := w.delivery(p.CampaignID, u); st != db.DeliveryDelivered || n != 2 {
		t.Fatalf("after retry: %s/%d", st, n)
	}
	if got := w.state(p.CampaignID); got != db.CampaignCompleted {
		t.Fatalf("state = %s", got)
	}
}

func TestWorker_RetriesAreBounded(t *testing.T) {
	w := newWorkerEnv(t) // MaxAttempts 3
	u := w.user(123450001, db.TierClient)
	e500 := &notify.APIError{StatusCode: 502, Description: "Bad Gateway"}
	w.sender.results[123450001] = []error{e500, e500, e500, e500, e500}
	p := w.approved("Hello.")
	for i := 0; i < 10; i++ {
		w.tick()
		w.now = w.now.Add(time.Hour)
	}
	if got := w.sender.count(123450001); got != 3 {
		t.Fatalf("sent %d times, want MaxAttempts=3", got)
	}
	if st, reason, _ := w.delivery(p.CampaignID, u); st != db.DeliveryFailed || reason != ReasonRetriesExhausted {
		t.Fatalf("final = %s/%s", st, reason)
	}
	if got := w.state(p.CampaignID); got != db.CampaignCompleted {
		t.Fatalf("state = %s", got)
	}
}

func TestWorker_AmbiguousTransportErrorIsNeverResent(t *testing.T) {
	w := newWorkerEnv(t)
	u := w.user(123450001, db.TierClient)
	d := w.user(123450002, db.TierClient)
	w.sender.results[123450001] = []error{context.DeadlineExceeded}
	w.sender.results[123450002] = []error{&net.OpError{Op: "dial", Err: errors.New("connection refused")}, nil}
	p := w.approved("Hello.")
	for i := 0; i < 4; i++ {
		w.tick()
		w.now = w.now.Add(time.Hour)
	}
	if got := w.sender.count(123450001); got != 1 {
		t.Fatalf("a send with unknown outcome was repeated %d times", got)
	}
	if st, reason, _ := w.delivery(p.CampaignID, u); st != db.DeliveryFailed || reason != db.ReasonOutcomeUnknown {
		t.Fatalf("timeout = %s/%s", st, reason)
	}
	// A dial failure never reached Telegram, so it is retried.
	if st, _, n := w.delivery(p.CampaignID, d); st != db.DeliveryDelivered || n != 2 {
		t.Fatalf("dial failure = %s/%d, want delivered on retry", st, n)
	}
}

func TestWorker_OtherClientErrorIsPermanentWithoutReachabilityWrite(t *testing.T) {
	w := newWorkerEnv(t)
	u := w.user(123450001, db.TierClient)
	w.sender.results[123450001] = []error{&notify.APIError{StatusCode: 400, Description: "Bad Request: message is too long"}}
	p := w.approved("Hello.")
	w.tick()
	w.now = w.now.Add(time.Hour)
	w.tick()
	if st, reason, _ := w.delivery(p.CampaignID, u); st != db.DeliveryFailed || reason != "rejected_400" {
		t.Fatalf("got %s/%s", st, reason)
	}
	if w.sender.count(123450001) != 1 || w.reach(u) != "" {
		t.Fatal("a non-recipient 4xx was retried or recorded as reachability")
	}
}

func TestWorker_CancelStopsUnsentWork(t *testing.T) {
	w := newWorkerEnv(t)
	var users []int64
	for i := int64(1); i <= 4; i++ {
		users = append(users, w.user(123450000+i, db.TierClient))
	}
	p := w.approved("Hello.")
	w.sender.before = func(chatID int64) {
		if chatID == 123450001 {
			if err := w.svc.Cancel(context.Background(), w.op, p.CampaignID); err != nil {
				t.Error(err)
			}
		}
	}
	w.tick()
	w.tick()
	if st, _, _ := w.delivery(p.CampaignID, users[0]); st != db.DeliveryDelivered {
		t.Fatalf("the in-flight send must be recorded as delivered, got %s", st)
	}
	for _, u := range users[1:] {
		if st, reason, _ := w.delivery(p.CampaignID, u); st != db.DeliverySkipped || reason != db.ReasonCancelled {
			t.Fatalf("user %d = %s/%s, want skipped/cancelled", u, st, reason)
		}
	}
	if len(w.sender.sent) != 1 {
		t.Fatalf("sent %d after cancel, want 1", len(w.sender.sent))
	}
	if got := w.state(p.CampaignID); got != db.CampaignCancelled {
		t.Fatalf("cancelled campaign became %s", got)
	}
}

func TestWorker_StaleInFlightRowIsClosedNotResent(t *testing.T) {
	w := newWorkerEnv(t)
	u := w.user(123450001, db.TierClient)
	p := w.approved("Hello.")
	// Start the campaign and claim the row as a crashed worker would have.
	if err := w.worker.startApproved(context.Background(), w.now); err != nil {
		t.Fatal(err)
	}
	if got, err := w.store.ClaimBroadcastDeliveries(context.Background(), 10, w.now); err != nil || len(got) != 1 {
		t.Fatalf("claim: %v %v", got, err)
	}
	w.now = w.now.Add(3 * time.Minute) // past the 2m lease
	w.tick()
	if len(w.sender.sent) != 0 {
		t.Fatal("a row whose send outcome is unknown was sent again")
	}
	if st, reason, _ := w.delivery(p.CampaignID, u); st != db.DeliveryFailed || reason != db.ReasonOutcomeUnknown {
		t.Fatalf("got %s/%s", st, reason)
	}
}

func TestWorker_AudienceOverLimitAtStartIsCancelled(t *testing.T) {
	w := newWorkerEnv(t)
	w.user(123450001, db.TierClient)
	p := w.approved("Hello.")
	if _, err := w.store.DB.Exec(`UPDATE broadcast_campaigns SET recipient_limit = 0 WHERE id = $1`, p.CampaignID); err != nil {
		t.Fatal(err)
	}
	w.tick()
	c, _ := w.store.GetBroadcastCampaign(context.Background(), p.CampaignID)
	if c.State != db.CampaignCancelled || c.EndReason != EndRecipientLimit || len(w.sender.sent) != 0 {
		t.Fatalf("state=%s reason=%s sent=%d", c.State, c.EndReason, len(w.sender.sent))
	}
}

func TestWorker_ContentAlteredAfterApprovalIsNeverSent(t *testing.T) {
	w := newWorkerEnv(t)
	w.user(123450001, db.TierClient)
	p := w.approved("Approved text.")
	if _, err := w.store.DB.Exec(`UPDATE broadcast_campaigns SET content = 'Swapped.' WHERE id = $1`, p.CampaignID); err != nil {
		t.Fatal(err)
	}
	w.tick()
	c, _ := w.store.GetBroadcastCampaign(context.Background(), p.CampaignID)
	if len(w.sender.sent) != 0 || c.State != db.CampaignCancelled || c.EndReason != EndIntegrity {
		t.Fatalf("sent=%d state=%s reason=%s", len(w.sender.sent), c.State, c.EndReason)
	}
}

func TestWorker_RateLimited(t *testing.T) {
	w := newWorkerEnv(t, func(c *WorkerConfig) { c.RatePerSecond = 20 })
	for i := int64(1); i <= 5; i++ {
		w.user(123450000+i, db.TierClient)
	}
	w.approved("Hello.")
	start := time.Now()
	w.tick()
	// burst 1 at 20/s: five sends need at least four 50ms intervals.
	if elapsed := time.Since(start); elapsed < 190*time.Millisecond {
		t.Fatalf("5 sends took %v; the rate limit was not applied", elapsed)
	}
	if len(w.sender.sent) != 5 {
		t.Fatalf("sent %d", len(w.sender.sent))
	}
}

func TestWorkerBackoff(t *testing.T) {
	w := NewWorker(nil, nil, WorkerConfig{BaseBackoff: time.Minute, MaxBackoff: 5 * time.Minute}, nil)
	for _, c := range []struct {
		attempts   int
		retryAfter time.Duration
		want       time.Duration
	}{
		{1, 0, time.Minute},
		{2, 0, 2 * time.Minute},
		{3, 0, 4 * time.Minute},
		{4, 0, 5 * time.Minute},
		{40, 0, 5 * time.Minute},
		{1, 3 * time.Minute, 3 * time.Minute},
	} {
		if got := w.backoff(c.attempts, c.retryAfter); got != c.want {
			t.Errorf("backoff(%d,%v) = %v, want %v", c.attempts, c.retryAfter, got, c.want)
		}
	}
}

func TestReport_AggregatesOutcomesWithoutRecipients(t *testing.T) {
	w := newWorkerEnv(t)
	for i := int64(1); i <= 5; i++ {
		w.user(123450000+i, db.TierClient)
	}
	w.sender.results[123450002] = []error{&notify.APIError{StatusCode: 403, Description: "Forbidden: bot was blocked by the user"}}
	w.sender.results[123450003] = []error{&notify.APIError{StatusCode: 500, Description: "x"}, &notify.APIError{StatusCode: 500, Description: "x"}, &notify.APIError{StatusCode: 500, Description: "x"}}
	w.sender.results[123450004] = []error{context.DeadlineExceeded}
	p := w.approved("Hello.")
	w.sender.before = func(chatID int64) {
		if chatID == 123450001 {
			uid, _ := w.store.UserIDByTelegramID(context.Background(), 123450005)
			_ = w.store.SetNotificationPrefs(context.Background(), uid, map[string]string{"maintenance": db.PrefUnsubscribed}, "test")
		}
	}
	for i := 0; i < 6; i++ {
		w.tick()
		w.now = w.now.Add(time.Hour)
	}
	r, err := BuildReport(context.Background(), w.store, p.CampaignID)
	if err != nil {
		t.Fatal(err)
	}
	if r.State != db.CampaignCompleted || r.Queued != 5 || r.Delivered != 1 || r.Skipped["unsubscribed"] != 1 ||
		r.PermanentFailure["bot_blocked"] != 1 || r.TransientFailure != 1 || r.OutcomeUnknown != 1 || r.Pending != 0 {
		t.Fatalf("report = %+v", r)
	}
	if r.ApprovedBy == nil || *r.ApprovedBy != w.op.UserID {
		t.Fatalf("report must identify the approver: %+v", r.ApprovedBy)
	}
}

// failingFacts fails the recipient lookup for one user: a store error in the
// middle of a batch.
type failingFacts struct {
	WorkerStore
	failUser int64
}

func (f *failingFacts) GetBroadcastRecipientFacts(ctx context.Context, userID int64, now time.Time) (*db.BroadcastRecipientFacts, error) {
	if userID == f.failUser {
		return nil, errors.New("db unavailable")
	}
	return f.WorkerStore.GetBroadcastRecipientFacts(ctx, userID, now)
}

func TestWorker_StoreErrorMidBatchReleasesUnattemptedRows(t *testing.T) {
	// A store error while checking one row: that row keeps its counted
	// attempt and backs off; the rows behind it were never attempted and go
	// back uncounted.
	w := newWorkerEnv(t)
	var users []int64
	for i := int64(1); i <= 3; i++ {
		users = append(users, w.user(123450000+i, db.TierClient))
	}
	p := w.approved("Hello.")
	cfg := w.worker.cfg
	broken := NewWorker(&failingFacts{WorkerStore: w.store, failUser: users[1]}, w.sender, cfg, func() time.Time { return w.now })
	if err := broken.Tick(context.Background()); err == nil {
		t.Fatal("tick swallowed the store error")
	}
	if st, _, _ := w.delivery(p.CampaignID, users[0]); st != db.DeliveryDelivered {
		t.Fatalf("first recipient = %s", st)
	}
	if st, _, n := w.delivery(p.CampaignID, users[1]); st != db.DeliveryPending || n != 1 {
		t.Fatalf("failing row = %s attempts=%d, want pending/1 (backed off)", st, n)
	}
	if st, _, n := w.delivery(p.CampaignID, users[2]); st != db.DeliveryPending || n != 0 {
		t.Fatalf("unattempted row = %s attempts=%d, want pending/0 (released, not burned)", st, n)
	}
	// A later lease expiry must not turn the released rows into unknowns.
	w.now = w.now.Add(10 * time.Minute)
	w.tick()
	for _, u := range users {
		if st, _, _ := w.delivery(p.CampaignID, u); st != db.DeliveryDelivered {
			t.Fatalf("user %d = %s after recovery", u, st)
		}
	}
	if len(w.sender.sent) != 3 {
		t.Fatalf("sent %d, want exactly 3", len(w.sender.sent))
	}
}

func TestWorker_ShutdownMidBatchReleasesWithoutBurningAttempts(t *testing.T) {
	w := newWorkerEnv(t, func(c *WorkerConfig) { c.RatePerSecond = 0.1 })
	var users []int64
	for i := int64(1); i <= 3; i++ {
		users = append(users, w.user(123450000+i, db.TierClient))
	}
	p := w.approved("Hello.")
	// The deadline is far enough for the store calls but far shorter than
	// the limiter's next slot, so the limiter is what stops the batch --
	// exactly as a shutdown does while a send waits for its turn.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := w.worker.Tick(ctx); err == nil {
		t.Fatal("tick did not report the interrupted batch")
	}
	if len(w.sender.sent) != 1 {
		t.Fatalf("sent %d, want 1 before shutdown", len(w.sender.sent))
	}
	for _, u := range users[1:] {
		if st, _, n := w.delivery(p.CampaignID, u); st != db.DeliveryPending || n != 0 {
			t.Fatalf("user %d = %s attempts=%d, want pending/0", u, st, n)
		}
	}
}

func TestWorker_IntegrityMismatchMidSendHaltsCampaign(t *testing.T) {
	w := newWorkerEnv(t)
	var users []int64
	for i := int64(1); i <= 3; i++ {
		users = append(users, w.user(123450000+i, db.TierClient))
	}
	p := w.approved("Approved text.")
	w.sender.before = func(chatID int64) {
		if chatID == 123450001 {
			if _, err := w.store.DB.Exec(`UPDATE broadcast_campaigns SET content = 'Swapped.' WHERE id = $1`, p.CampaignID); err != nil {
				t.Error(err)
			}
		}
	}
	w.tick()
	w.tick()
	if len(w.sender.sent) != 1 {
		t.Fatalf("sent %d, want only the send that preceded the tamper", len(w.sender.sent))
	}
	c, _ := w.store.GetBroadcastCampaign(context.Background(), p.CampaignID)
	if c.State != db.CampaignCancelled || c.EndReason != EndIntegrity {
		t.Fatalf("campaign = %s/%s, want cancelled/%s", c.State, c.EndReason, EndIntegrity)
	}
	for _, u := range users[1:] {
		if st, reason, _ := w.delivery(p.CampaignID, u); st != db.DeliverySkipped || reason != db.ReasonCancelled {
			t.Fatalf("user %d = %s/%s", u, st, reason)
		}
	}
}

func TestWorker_NoSendStartsTooCloseToLeaseExpiry(t *testing.T) {
	w := newWorkerEnv(t)
	var users []int64
	for i := int64(1); i <= 3; i++ {
		users = append(users, w.user(123450000+i, db.TierClient))
	}
	p := w.approved("Hello.")
	// The first send is slow: by the time it returns, the rest of the batch
	// could not finish inside the lease.
	w.sender.before = func(int64) { w.now = w.now.Add(w.worker.cfg.Lease) }
	waits := 0
	w.worker.limiter = slowWait(func() { waits++ })
	w.tick()
	if len(w.sender.sent) != 1 {
		t.Fatalf("sent %d, want 1", len(w.sender.sent))
	}
	// The exhausted batch stops before queueing on the limiter again.
	if waits != 1 {
		t.Fatalf("limiter waited %d times, want 1", waits)
	}
	for _, u := range users[1:] {
		if st, _, n := w.delivery(p.CampaignID, u); st != db.DeliveryPending || n != 0 {
			t.Fatalf("user %d = %s attempts=%d, want released", u, st, n)
		}
	}
	w.sender.before = nil
	w.tick()
	for _, u := range users {
		if st, _, _ := w.delivery(p.CampaignID, u); st != db.DeliveryDelivered {
			t.Fatalf("user %d = %s after the next tick", u, st)
		}
	}
	if len(w.sender.sent) != 3 {
		t.Fatalf("sent %d, want 3", len(w.sender.sent))
	}
}

// slowWait stands in for a limiter wait that takes a while.
type slowWait func()

func (f slowWait) Wait(context.Context) error { f(); return nil }

// The lease is re-checked AFTER the limiter wait: the wait itself can use up
// the lease, and a send started then could be swept as outcome_unknown.
func TestWorker_LeaseSpentInRateLimiterWaitStopsTheSend(t *testing.T) {
	w := newWorkerEnv(t)
	u := w.user(123450001, db.TierClient)
	p := w.approved("Hello.")
	w.worker.limiter = slowWait(func() { w.now = w.now.Add(w.worker.cfg.Lease) })
	w.tick()
	if len(w.sender.sent) != 0 {
		t.Fatal("sent after the lease ran out during the limiter wait")
	}
	if st, _, n := w.delivery(p.CampaignID, u); st != db.DeliveryPending || n != 0 {
		t.Fatalf("row = %s attempts=%d, want released", st, n)
	}
}

// A row whose store lookup fails every time must not hold its campaign open:
// it backs off (the rest of the queue drains past it) and ends as
// retries_exhausted once MaxAttempts is spent.
func TestWorker_PersistentStoreFaultDoesNotStallTheCampaign(t *testing.T) {
	w := newWorkerEnv(t)
	var users []int64
	for i := int64(1); i <= 3; i++ {
		users = append(users, w.user(123450000+i, db.TierClient))
	}
	p := w.approved("Hello.")
	broken := NewWorker(&failingFacts{WorkerStore: w.store, failUser: users[0]}, w.sender, w.worker.cfg, func() time.Time { return w.now })
	for i := 0; i < 10 && w.state(p.CampaignID) != db.CampaignCompleted; i++ {
		_ = broken.Tick(context.Background())
		w.now = w.now.Add(w.worker.cfg.MaxBackoff)
	}
	if got := w.state(p.CampaignID); got != db.CampaignCompleted {
		t.Fatalf("campaign = %s, stalled behind the failing row", got)
	}
	if st, reason, _ := w.delivery(p.CampaignID, users[0]); st != db.DeliveryFailed || reason != ReasonRetriesExhausted {
		t.Fatalf("failing row = %s/%s", st, reason)
	}
	for _, u := range users[1:] {
		if st, _, _ := w.delivery(p.CampaignID, u); st != db.DeliveryDelivered {
			t.Fatalf("user %d = %s", u, st)
		}
	}
}

func TestWorkerConfig_BatchFitsTheLease(t *testing.T) {
	c := WorkerConfig{RatePerSecond: 1, BatchSize: 200, Lease: 2 * time.Minute}.withDefaults()
	if want := int((2*time.Minute - sendTimeout).Seconds()); c.BatchSize != want {
		t.Fatalf("BatchSize = %d, want %d", c.BatchSize, want)
	}
	if c := (WorkerConfig{RatePerSecond: 0.001, BatchSize: 5}).withDefaults(); c.BatchSize != 1 {
		t.Fatalf("BatchSize = %d, want at least 1", c.BatchSize)
	}
	if c := (WorkerConfig{RatePerSecond: 10, BatchSize: 20}).withDefaults(); c.BatchSize != 20 {
		t.Fatalf("a batch that fits was changed to %d", c.BatchSize)
	}
}

// cancellingSender is a send during which shutdown arrives: it cancels the
// worker's context and then reports whatever its own context says.
type cancellingSender struct {
	cancel context.CancelFunc
	sent   int
}

func (c *cancellingSender) SendMessage(ctx context.Context, _ int64, _ string) error {
	c.cancel()
	c.sent++
	return ctx.Err()
}

// A send already under way is not aborted by shutdown: an aborted request
// may still have been delivered and could only be recorded as unknown.
func TestWorker_ShutdownDoesNotAbortAnInFlightSend(t *testing.T) {
	w := newWorkerEnv(t)
	u := w.user(123450001, db.TierClient)
	p := w.approved("Hello.")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &cancellingSender{cancel: cancel}
	worker := NewWorker(w.store, s, w.worker.cfg, func() time.Time { return w.now })
	_ = worker.Tick(ctx)
	if st, reason, _ := w.delivery(p.CampaignID, u); st != db.DeliveryDelivered {
		t.Fatalf("in-flight send at shutdown = %s/%s, want delivered", st, reason)
	}
}
