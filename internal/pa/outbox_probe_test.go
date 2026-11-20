package pa

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// Probes of the outbox send-once rules (issue #1313 slice d2, round 2):
// a row's lease covers its own send only, request paths answer before they
// deliver, a send is never cut off by the caller going away, a retry
// resumes after the delivered parts, and every guard of the deliverer is
// pinned. The lease and request-path probes also run on Postgres.

// newPostgresStore opens a fresh schema on TEST_DATABASE_URL, dropped when
// the test ends, so the run loop's global claims see this test's rows only.
func newPostgresStore(t *testing.T) *db.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := db.Open(ctx, dsn, 2, 1)
	if err != nil {
		t.Fatalf("postgres: %v", err)
	}
	schema := fmt.Sprintf("pa_rl_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		_ = admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DROP SCHEMA `+schema+` CASCADE`)
		_ = admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	conn, err := db.Open(ctx, u.String(), 5, 2)
	if err != nil {
		t.Fatalf("postgres: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.NewStore(conn, nil)
}

// onDialects runs probe on SQLite and, with TEST_DATABASE_URL, Postgres.
func onDialects(t *testing.T, probe func(t *testing.T, store func(*testing.T) *db.Store)) {
	t.Run("sqlite", func(t *testing.T) { probe(t, newStore) })
	t.Run("postgres", func(t *testing.T) { probe(t, newPostgresStore) })
}

func (h *runLoopHarness) enqueueNotice(p, job int64, k jobs.OutboxKind) {
	h.t.Helper()
	tx, err := h.convoHarness.store.DB.Begin()
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := h.store.EnqueuePAOutbox(context.Background(), tx, jobs.OutboxItem{Principal: p, JobID: job, Kind: k}, h.now); err != nil {
		h.t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatal(err)
	}
}

func (h *runLoopHarness) outboxRow(p int64, kind jobs.OutboxKind) (status string, parts int) {
	h.t.Helper()
	err := h.convoHarness.store.DB.QueryRow(`SELECT status, sent_parts FROM pa_outbox WHERE principal = $1 AND kind = $2 ORDER BY id DESC LIMIT 1`,
		p, string(kind)).Scan(&status, &parts)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		h.t.Fatal(err)
	}
	return status, parts
}

func (h *runLoopHarness) setBefore(f func(ctx context.Context, chat int64, part int) error) {
	h.sender.mu.Lock()
	h.sender.before = f
	h.sender.mu.Unlock()
}

// serve is post without waiting for the delivery the route starts.
func (h *runLoopHarness) serve(ctx context.Context, route, token string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, route, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	h.loop.Mount(mux)
	mux.ServeHTTP(w, req)
	return w
}

// TestOutbox_LeaseCoversOneSend (P2-1): Alice's send hangs past the lease
// and Bob's request path delivers meanwhile. Bob's row was never claimed
// with Alice's, so it is not marked unknown before its send: its first
// send meets a flood wait, is retried, and Bob gets his notice once.
// Alice's own row did outlive its lease: it is unknown, and her late
// completion is stale.
func TestOutbox_LeaseCoversOneSend(t *testing.T) {
	onDialects(t, func(t *testing.T, store func(*testing.T) *db.Store) {
		counts := &lockedCounts{m: outboxCounts{}}
		h := newRunLoopHarnessOn(t, store(t), func(c *RunLoopConfig, _ *runLoopHarness) { c.Metrics = counts })
		h.enqueueNotice(aliceID, 1, jobs.OutboxRunFailed)
		h.enqueueNotice(bobID, 2, jobs.OutboxRunFailed)
		blocked, release := make(chan struct{}), make(chan struct{})
		bobFails := 1
		h.setBefore(func(_ context.Context, chat int64, _ int) error {
			switch chat {
			case aliceID:
				close(blocked)
				<-release
			case bobID:
				if bobFails > 0 {
					bobFails--
					return floodWait
				}
			}
			return nil
		})
		done := make(chan struct{})
		go func() {
			defer close(done)
			h.loop.deliver(context.Background(), 0)
		}()
		<-blocked
		h.now = h.now.Add(jobs.OutboxLease + time.Second)
		h.loop.deliver(context.Background(), bobID)
		close(release)
		<-done
		h.now = h.now.Add(jobs.OutboxBackoff(1))
		h.loop.deliver(context.Background(), 0)
		if sent := h.sender.to(bobID); len(sent) != 1 || sent[0] != safetext.ServerText(safetext.TextRunFailed).String() {
			t.Fatalf("Bob got %q, want his notice once", sent)
		}
		if st, _ := h.outboxRow(bobID, jobs.OutboxRunFailed); st != "sent" {
			t.Fatalf("Bob's row %s, want sent", st)
		}
		if st, _ := h.outboxRow(aliceID, jobs.OutboxRunFailed); st != "unknown" {
			t.Fatalf("Alice's row %s, want unknown", st)
		}
		if got := counts.get(); got[OutboxOutcomeStale] != 1 || got[OutboxOutcomeUnknown] != 1 || got[OutboxOutcomeRetry] != 1 {
			t.Fatalf("counts %v", got)
		}
	})
}

type lockedCounts struct {
	mu sync.Mutex
	m  outboxCounts
}

func (c *lockedCounts) CountPAOutbox(o string) {
	c.mu.Lock()
	c.m[o]++
	c.mu.Unlock()
}

func (c *lockedCounts) get() outboxCounts {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := outboxCounts{}
	for k, v := range c.m {
		out[k] = v
	}
	return out
}

// TestOutbox_ClaimAnswersBeforeDelivery (P2-3): the claim that expires
// Alice's job and hands out Bob's answers while the notice it owes Alice
// is stuck in a Telegram send. The token is never held up by Telegram.
func TestOutbox_ClaimAnswersBeforeDelivery(t *testing.T) {
	onDialects(t, func(t *testing.T, store func(*testing.T) *db.Store) {
		h := newRunLoopHarnessOn(t, store(t))
		h.consent(aliceID)
		h.consent(bobID)
		h.text(aliceID, "hello")
		h.mustClaim()
		h.now = h.now.Add(jobs.DefaultLease + time.Second)
		h.text(bobID, "hi")
		release := make(chan struct{})
		h.setBefore(func(context.Context, int64, int) error {
			<-release
			return nil
		})
		resp := make(chan *httptest.ResponseRecorder, 1)
		go func() { resp <- h.serve(context.Background(), RouteClaim, h.pool, "") }()
		select {
		case w := <-resp:
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"token"`) {
				t.Fatalf("claim: %d %s", w.Code, w.Body)
			}
		case <-time.After(10 * time.Second):
			close(release)
			t.Fatal("the claim response waited on a Telegram send")
		}
		close(release)
		if sent := h.sentTo(aliceID); len(sent) != 1 || sent[0] != safetext.ServerText(safetext.TextRunFailed).String() {
			t.Fatalf("Alice got %q, want the run-failed notice", sent)
		}
	})
}

// TestOutbox_ReplyAnswersBeforeDelivery (P2-3, P2-2c): the reply answers
// while the send hangs, and the worker hanging up afterwards does not
// cancel the send: the answer is delivered and recorded sent.
func TestOutbox_ReplyAnswersBeforeDelivery(t *testing.T) {
	onDialects(t, func(t *testing.T, store func(*testing.T) *db.Store) {
		h := newRunLoopHarnessOn(t, store(t))
		h.consent(aliceID)
		h.text(aliceID, "hello")
		c := h.mustClaim()
		release := make(chan struct{})
		var sendErr error
		h.setBefore(func(ctx context.Context, _ int64, _ int) error {
			<-release
			sendErr = ctx.Err()
			return nil
		})
		ctx, hangUp := context.WithCancel(context.Background())
		resp := make(chan *httptest.ResponseRecorder, 1)
		go func() { resp <- h.serve(ctx, RouteReply, c.Token, `{"text":"an answer"}`) }()
		select {
		case w := <-resp:
			if w.Code != http.StatusOK {
				t.Fatalf("reply: %d %s", w.Code, w.Body)
			}
		case <-time.After(10 * time.Second):
			close(release)
			t.Fatal("the reply response waited on a Telegram send")
		}
		hangUp()
		close(release)
		h.loop.WaitDeliveries()
		if sendErr != nil {
			t.Fatalf("the send ran on the worker's request context: %v", sendErr)
		}
		if sent := h.sender.to(aliceID); len(sent) != 1 || sent[0] != "an answer" {
			t.Fatalf("sent %q", sent)
		}
		if st, _ := h.outboxRow(aliceID, jobs.OutboxReply); st != "sent" {
			t.Fatalf("reply row %s, want sent", st)
		}
	})
}

// TestOutbox_DeliverAfterIsDetached: a delivery a request path starts runs
// even when that request is already gone.
func TestOutbox_DeliverAfterIsDetached(t *testing.T) {
	h := newRunLoopHarness(t)
	h.enqueueNotice(aliceID, 1, jobs.OutboxRequestDropped)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.loop.deliverAfter(ctx, aliceID, aliceID)
	if sent := h.sentTo(aliceID); len(sent) != 1 {
		t.Fatalf("sent %q, want the notice once", sent)
	}
}

// TestOutbox_UnknownOutcomeIsNotResent (P2-2b): a send cut off after its
// request was written may have been delivered: the row is unknown at once
// and never sent again.
func TestOutbox_UnknownOutcomeIsNotResent(t *testing.T) {
	counts := outboxCounts{}
	h := newRunLoopHarness(t, withOutboxCounter(counts))
	h.enqueueNotice(aliceID, 1, jobs.OutboxRunFailed)
	h.failSends(cutOff)
	h.loop.deliver(context.Background(), 0)
	h.failSends(nil)
	for range 3 {
		h.now = h.now.Add(time.Hour)
		h.loop.deliver(context.Background(), 0)
	}
	if st, _ := h.outboxRow(aliceID, jobs.OutboxRunFailed); st != "unknown" || len(h.sender.to(aliceID)) != 0 || counts[OutboxOutcomeUnknown] != 1 {
		t.Fatalf("status %s sent %q counts %v", st, h.sender.to(aliceID), counts)
	}
}

// TestOutbox_RetryResumesAfterDeliveredParts (P2-2a): part 3 of a reply
// meets a flood wait; the retry sends part 3 only.
func TestOutbox_RetryResumesAfterDeliveredParts(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	answer := strings.TrimSpace(strings.Repeat("word ", 2000))
	want, err := safetext.Render(answer, safetext.AllowFromUserText("hello"))
	if err != nil || want.Parts() != 3 {
		t.Fatalf("render: %d parts, %v; the probe needs 3", want.Parts(), err)
	}
	h.sender.mu.Lock()
	h.sender.fail, h.sender.failAt = floodWait, 3
	h.sender.mu.Unlock()
	if w := h.post(RouteReply, c.Token, replyRequest{Text: answer}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	if st, parts := h.outboxRow(aliceID, jobs.OutboxReply); st != "pending" || parts != 2 {
		t.Fatalf("after part 3 failed: %s with %d parts, want pending with 2", st, parts)
	}
	h.failSends(nil)
	h.now = h.now.Add(jobs.OutboxBackoff(1))
	h.loop.deliver(context.Background(), 0)
	got := h.sender.partsTo(aliceID)
	if len(got) != 3 || strings.Join(got, "") != want.String() {
		t.Fatalf("delivered %d parts; want each of the 3 parts once, in order", len(got))
	}
	if st, parts := h.outboxRow(aliceID, jobs.OutboxReply); st != "sent" || parts != 3 {
		t.Fatalf("row %s with %d parts, want sent with 3", st, parts)
	}
}

// faultyStore fails the fragment read or the parts record on demand.
type faultyStore struct {
	*db.Store
	mu         sync.Mutex
	loadFault  bool
	partsFault bool
}

func (s *faultyStore) set(load, parts bool) {
	s.mu.Lock()
	s.loadFault, s.partsFault = load, parts
	s.mu.Unlock()
}

func (s *faultyStore) LoadPAFragments(ctx context.Context, principal int64, conversationID string, now time.Time) ([]convo.SealedFragment, error) {
	s.mu.Lock()
	fault := s.loadFault
	s.mu.Unlock()
	if fault {
		return nil, fmt.Errorf("%w: fragments unreadable", convo.ErrStoreFault)
	}
	return s.Store.LoadPAFragments(ctx, principal, conversationID, now)
}

func (s *faultyStore) RecordPAOutboxParts(ctx context.Context, item jobs.OutboxItem, parts int, now time.Time) error {
	s.mu.Lock()
	fault := s.partsFault
	s.mu.Unlock()
	if fault {
		return errors.New("store down")
	}
	return s.Store.RecordPAOutboxParts(ctx, item, parts, now)
}

func withFaultyStore(f **faultyStore) rlOption {
	return withStore(func(s *db.Store) RunLoopStore {
		*f = &faultyStore{Store: s}
		return *f
	})
}

// TestOutbox_UnreadableAnswerIsRetried (D6): a reply whose fragments could
// not be read says nothing about the reply: it is due again, not failed.
func TestOutbox_UnreadableAnswerIsRetried(t *testing.T) {
	var fs *faultyStore
	h := newRunLoopHarness(t, withFaultyStore(&fs))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	h.failSends(floodWait)
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "an answer"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	h.failSends(nil)
	fs.set(true, false)
	h.now = h.now.Add(jobs.OutboxBackoff(1))
	h.loop.deliver(context.Background(), 0)
	if st, _ := h.outboxRow(aliceID, jobs.OutboxReply); st != "pending" || len(h.sender.to(aliceID)) != 0 {
		t.Fatalf("row %s after an unreadable answer, want pending and nothing sent", st)
	}
	fs.set(false, false)
	h.now = h.now.Add(jobs.OutboxBackoff(2))
	h.loop.deliver(context.Background(), 0)
	if sent := h.sender.to(aliceID); len(sent) != 1 || sent[0] != "an answer" {
		t.Fatalf("sent %q", sent)
	}
}

// TestOutbox_UnrecordedPartIsUnknown: a part that was delivered but could
// not be recorded would be sent again by a retry, so the row is unknown.
func TestOutbox_UnrecordedPartIsUnknown(t *testing.T) {
	var fs *faultyStore
	h := newRunLoopHarness(t, withFaultyStore(&fs))
	h.enqueueNotice(aliceID, 1, jobs.OutboxBudgetHold)
	fs.set(false, true)
	h.loop.deliver(context.Background(), 0)
	fs.set(false, false)
	h.now = h.now.Add(time.Hour)
	h.loop.deliver(context.Background(), 0)
	if st, _ := h.outboxRow(aliceID, jobs.OutboxBudgetHold); st != "unknown" || len(h.sender.partsTo(aliceID)) != 1 {
		t.Fatalf("row %s, parts %d: want unknown after one delivered part", st, len(h.sender.partsTo(aliceID)))
	}
}

// replyRowFor appends a fragment of the given kind and provenance to
// Alice's open conversation and queues a reply row naming it.
func (h *runLoopHarness) replyRowFor(kind convo.Kind, prov convo.Provenance, text string, job int64) {
	h.t.Helper()
	var convID string
	if err := h.convoHarness.store.DB.QueryRow(`SELECT id FROM pa_conversations WHERE principal = $1`, aliceID).Scan(&convID); err != nil {
		h.t.Fatal(err)
	}
	ctx := context.Background()
	tx, err := h.convoHarness.store.DB.Begin()
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	seq, err := h.store.NextPAFragmentSeq(ctx, tx, aliceID, convID)
	if err != nil {
		h.t.Fatal(err)
	}
	sf, err := h.loop.sealer.Seal(aliceID, convID, seq, convo.NewFragment(kind, prov, text))
	if err != nil {
		h.t.Fatal(err)
	}
	sf.CreatedAt = h.now
	if err := h.store.AppendPAFragment(ctx, tx, sf); err != nil {
		h.t.Fatal(err)
	}
	if err := h.store.EnqueuePAOutbox(ctx, tx, jobs.OutboxItem{Principal: aliceID, JobID: job, Kind: jobs.OutboxReply,
		ConversationID: convID, FragmentSeq: seq}, h.now); err != nil {
		h.t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		h.t.Fatal(err)
	}
}

// TestOutbox_ReplyMustBeExternalAssistant (D4): a reply row goes out only
// when it names an assistant fragment that is marked external. Each half
// of the check is pinned on its own: an assistant fragment claiming the
// user's voice, and external text that is not an answer.
func TestOutbox_ReplyMustBeExternalAssistant(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind convo.Kind
		prov convo.Provenance
		sent bool
	}{
		{"external assistant answer", convo.KindAssistant, convo.ProvenanceExternal, true},
		{"assistant fragment in the user's voice", convo.KindAssistant, convo.ProvenanceUser, false},
		{"external text that is not an answer", convo.KindText, convo.ProvenanceExternal, false},
		{"the principal's own text", convo.KindText, convo.ProvenanceUser, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRunLoopHarness(t)
			h.consent(aliceID)
			h.text(aliceID, "hello")
			h.replyRowFor(tc.kind, tc.prov, "an answer", 4242)
			h.loop.deliver(context.Background(), 0)
			st, _ := h.outboxRow(aliceID, jobs.OutboxReply)
			if sent := h.sender.to(aliceID); tc.sent != (len(sent) == 1) || (tc.sent && st != "sent") || (!tc.sent && st != "failed") {
				t.Fatalf("row %s, sent %d messages; want sent %v", st, len(sent), tc.sent)
			}
		})
	}
}

// TestOutbox_RetryRendersAsFirstAttempt (D5): the allow-list is what the
// principal typed before the answer. A link the principal types after a
// failed first attempt does not change what the retry renders, so the
// parts a retry resumes after are the parts the first attempt sent.
func TestOutbox_RetryRendersAsFirstAttempt(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	const link = "https://example.org/report"
	answer := "see " + link
	want, err := safetext.Render(answer, safetext.AllowFromUserText("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if later, _ := safetext.Render(answer, safetext.AllowFromUserText("hello", link)); later.String() == want.String() {
		t.Fatal("the probe needs a link the allow-list changes")
	}
	h.failSends(floodWait)
	if w := h.post(RouteReply, c.Token, replyRequest{Text: answer}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	h.failSends(nil)
	h.text(aliceID, link)
	h.now = h.now.Add(jobs.OutboxBackoff(1))
	h.loop.deliver(context.Background(), aliceID)
	if sent := h.sender.to(aliceID); len(sent) != 1 || sent[0] != want.String() {
		t.Fatalf("sent %q, want the answer rendered as at its first attempt", sent)
	}
}

// TestOutbox_RowAheadOfItsRendering: a row that recorded more parts than
// its text now has was fully delivered; it is completed as sent, not
// failed for a resume point past the end.
func TestOutbox_RowAheadOfItsRendering(t *testing.T) {
	h := newRunLoopHarness(t)
	h.enqueueNotice(aliceID, 1, jobs.OutboxRunFailed)
	ctx := context.Background()
	res, err := h.store.ClaimPAOutbox(ctx, jobs.OutboxClaimRequest{Now: h.now, Lease: jobs.OutboxLease, Principal: aliceID, Limit: 1})
	if err != nil || len(res.Items) != 1 {
		t.Fatalf("claim: %v %d", err, len(res.Items))
	}
	it := res.Items[0]
	if err := h.store.RecordPAOutboxParts(ctx, it, 2, h.now); err != nil {
		t.Fatal(err)
	}
	if err := h.store.CompletePAOutbox(ctx, it, jobs.OutboxCompletion{Now: h.now, Status: jobs.OutboxPending, RetryAt: h.now}); err != nil {
		t.Fatal(err)
	}
	h.loop.deliver(ctx, 0)
	if st, _ := h.outboxRow(aliceID, jobs.OutboxRunFailed); st != "sent" || len(h.sender.to(aliceID)) != 0 {
		t.Fatalf("row %s, sent %d: want sent with nothing resent", st, len(h.sender.to(aliceID)))
	}
}

// TestOutbox_SendOutlivesItsCaller (P2-2c): the context deliver is given
// decides only whether another row is claimed. A caller that goes away
// mid-send (RunOutbox at shutdown) does not cut the send off.
func TestOutbox_SendOutlivesItsCaller(t *testing.T) {
	h := newRunLoopHarness(t)
	h.enqueueNotice(aliceID, 1, jobs.OutboxRunFailed)
	h.enqueueNotice(aliceID, 2, jobs.OutboxRequestDropped)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.setBefore(func(sctx context.Context, _ int64, _ int) error {
		cancel()
		return sctx.Err()
	})
	h.loop.deliver(ctx, aliceID)
	if st, _ := h.outboxRow(aliceID, jobs.OutboxRunFailed); st != "sent" || len(h.sender.to(aliceID)) != 1 {
		t.Fatalf("row %s, sent %d: want the send in flight completed", st, len(h.sender.to(aliceID)))
	}
	if st, _ := h.outboxRow(aliceID, jobs.OutboxRequestDropped); st != "pending" {
		t.Fatalf("second row %s: a caller that left claims no more rows", st)
	}
}

// TestOutbox_StoredAnswerTooLong (D3): a stored answer that no longer
// renders is replaced by the server text, never cut.
func TestOutbox_StoredAnswerTooLong(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	var convID string
	if err := h.convoHarness.store.DB.QueryRow(`SELECT id FROM pa_conversations WHERE principal = $1`, aliceID).Scan(&convID); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tx, err := h.convoHarness.store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	seq, err := h.loop.appendAssistant(ctx, tx, jobs.Job{Principal: aliceID, ConversationID: convID}, strings.Repeat("x", (safetext.MaxParts+1)*4096))
	if err != nil {
		t.Fatal(err)
	}
	if err := h.store.EnqueuePAOutbox(ctx, tx, jobs.OutboxItem{Principal: aliceID, JobID: 4242, Kind: jobs.OutboxReply,
		ConversationID: convID, FragmentSeq: seq}, h.now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	h.loop.deliver(ctx, 0)
	if sent := h.sender.to(aliceID); len(sent) != 1 || sent[0] != safetext.ServerText(safetext.TextReplyTooLong).String() {
		t.Fatalf("sent %d messages, want the too-long server text", len(sent))
	}
}

// TestOutbox_PassKeepsGoing (R4): a pass with more due rows than one batch
// sends them all.
func TestOutbox_PassKeepsGoing(t *testing.T) {
	h := newRunLoopHarness(t)
	n := jobs.OutboxBatch + 3
	for i := range n {
		h.enqueueNotice(int64(880000+i), int64(i+1), jobs.OutboxRunFailed)
	}
	h.loop.outboxPass(context.Background())
	h.sender.mu.Lock()
	got := len(h.sender.sent)
	h.sender.mu.Unlock()
	if got != n {
		t.Fatalf("one pass sent %d of %d due rows", got, n)
	}
}

// TestOutbox_RunOutboxDeliversAndStops: the background pass sends a due
// row and returns when its context ends.
func TestOutbox_RunOutboxDeliversAndStops(t *testing.T) {
	h := newRunLoopHarness(t)
	h.enqueueNotice(aliceID, 1, jobs.OutboxRunFailed)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.loop.RunOutbox(ctx, 5*time.Millisecond)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for len(h.sender.to(aliceID)) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunOutbox did not stop with its context")
	}
	if len(h.sender.to(aliceID)) != 1 {
		t.Fatal("RunOutbox did not deliver the due row")
	}
}

// TestOutbox_ForgetDeletesPendingNotices (P3-6): /forget takes the
// principal's pending notices with it.
func TestOutbox_ForgetDeletesPendingNotices(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.enqueueNotice(aliceID, 1, jobs.OutboxRunFailed)
	h.enqueueNotice(aliceID, 2, jobs.OutboxBudgetHold)
	h.enqueueNotice(bobID, 3, jobs.OutboxRunFailed)
	h.text(aliceID, CommandForget)
	if n := h.count(`SELECT COUNT(*) FROM pa_outbox WHERE principal = $1`, aliceID); n != 0 {
		t.Fatalf("%d of Alice's notices survived /forget", n)
	}
	if n := h.count(`SELECT COUNT(*) FROM pa_outbox WHERE principal = $1`, bobID); n != 1 {
		t.Fatalf("Bob has %d rows; /forget must touch Alice's only", n)
	}
	h.loop.deliver(context.Background(), 0)
	if sent := h.sender.to(aliceID); len(sent) != 0 {
		t.Fatalf("Alice got %q from the outbox after /forget", sent)
	}
}
