package pa

// export_test.go hands the run-loop harness to the connector dispatch
// acceptance tests (package pa_test, dispatch_acceptance_test.go), which
// cannot live in package pa: the connector imports pa.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Synthetic personas of this package's tests.
const (
	TestAliceID = aliceID
	TestBobID   = bobID
)

// DispatchHarness is a run loop with a webhook, conversations and the job
// ledger on one store.
type DispatchHarness struct {
	h           *runLoopHarness
	failDisable atomic.Bool
}

// NewDispatchHarness builds the harness on store.
func NewDispatchHarness(t *testing.T, store *db.Store) *DispatchHarness {
	t.Helper()
	d := &DispatchHarness{}
	d.h = newRunLoopHarnessOn(t, store, withStore(func(s *db.Store) RunLoopStore {
		return &toggleDisable{Store: s, fail: &d.failDisable}
	}))
	return d
}

func (d *DispatchHarness) Loop() *RunLoop           { return d.h.loop }
func (d *DispatchHarness) Issuer() *localjwt.Issuer { return d.h.issuer }
func (d *DispatchHarness) Now() time.Time           { return d.h.now }
func (d *DispatchHarness) Advance(dur time.Duration) {
	d.h.now = d.h.now.Add(dur)
}
func (d *DispatchHarness) SetTools(tools []string) { d.h.tools = tools }
func (d *DispatchHarness) SetConns(conns map[int64][]ConnectionRevision) {
	d.h.conns = conns
}
func (d *DispatchHarness) Consent(user int64) { d.h.consent(user) }
func (d *DispatchHarness) Text(user int64, s string) {
	if code := d.h.text(user, s); code != http.StatusOK {
		d.h.t.Fatalf("message: %d", code)
	}
}
func (d *DispatchHarness) Count(q string, args ...any) int { return d.h.count(q, args...) }

// PoolToken is the pool credential a worker claims with.
func (d *DispatchHarness) PoolToken() string { return d.h.pool }

// SentTo returns what the bot sent to chat, once deliveries are done.
func (d *DispatchHarness) SentTo(chat int64) []string { return d.h.sentTo(chat) }

// FailDisableReads makes the run loop's principal-disable read fail (on)
// or read the store again (off).
func (d *DispatchHarness) FailDisableReads(on bool) { d.failDisable.Store(on) }

// Deny takes user off the run loop's and the conversations' allowlist.
func (d *DispatchHarness) Deny(user int64) { d.h.allow.deny(user) }

// Claim claims the next job as the pool.
func (d *DispatchHarness) Claim() (token string, jobID int64, attempt int, code int) {
	c, code := d.h.claim()
	return c.Token, c.JobID, c.Attempt, code
}

// ClaimRaw claims the next job as the pool and returns the response body
// as the worker receives it (S1-K2 scans it for token material).
func (d *DispatchHarness) ClaimRaw() (body []byte, token string, code int) {
	w := d.h.post(RouteClaim, d.h.pool, nil)
	var c claimResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
			d.h.t.Fatal(err)
		}
	}
	return w.Body.Bytes(), c.Token, w.Code
}

// TurnRaw asks for a model turn under token and returns the raw body.
func (d *DispatchHarness) TurnRaw(token string) (body []byte, code int) {
	w := d.h.post(RouteTurn, token, turnRequest{ContextTokens: 10})
	return w.Body.Bytes(), w.Code
}

// RevokePool revokes the pool credential every job token inherits and
// refreshes the revocation cache, as its TTL running out would.
func (d *DispatchHarness) RevokePool(t *testing.T) {
	t.Helper()
	if err := d.h.convoHarness.store.RevokeWorkerToken(t.Context(), "pool-jti", 0, "test", 1); err != nil {
		t.Fatal(err)
	}
	if err := d.h.cache.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// SentCard is one message the bot sent, with its buttons as (label,
// callback data) pairs, row by row.
type SentCard struct {
	Text    string
	Buttons [][][2]string
}

// MessagesTo returns the completed sends to chat with their keyboards,
// once deliveries are done.
func (d *DispatchHarness) MessagesTo(chat int64) []SentCard {
	d.h.loop.WaitDeliveries()
	var out []SentCard
	for _, m := range d.h.sender.messagesTo(chat) {
		c := SentCard{Text: m.text}
		for _, row := range m.kb {
			var r [][2]string
			for _, b := range row {
				r = append(r, [2]string{b.Label.String(), b.Data})
			}
			c.Buttons = append(c.Buttons, r)
		}
		out = append(out, c)
	}
	return out
}

// EnableApprovalCards wires what no production wiring does yet (#1320
// slice P2-S5): the run loop sends approval cards built by cards, the
// conversations handle a card's buttons against the store's approval
// ledger, and the webhook hands an approved approval to approved after the
// update's transaction committed, as cmd/server will hand it to the write
// executor.
func (d *DispatchHarness) EnableApprovalCards(cards CardRenderer, approvals ApprovalCallbacks,
	approved func(ctx context.Context, principal int64, approvalID string)) {
	h := d.h
	h.loop.cards = cards
	h.conv.approvals = approvals
	wh, err := NewWebhookHandler(WebhookConfig{
		Secret: testSecret, Dedup: h.convoHarness.store, Handler: h.conv, Failures: h.convoHarness.store,
		AfterCommit: func(ctx context.Context, u VerifiedUpdate) {
			if id, ok := PostCommitApproval(ctx); ok {
				approved(ctx, u.Principal().TelegramID(), id)
			}
			h.loop.DeliverAfter(ctx, u.Principal().TelegramID())
		},
	})
	if err != nil {
		h.t.Fatal(err)
	}
	h.hook = wh
}

// PressConcurrently delivers n presses of the button by user at the same
// time, each as a new update, and returns the webhook's statuses. The
// deliveries are waited for once, after every press returned: a WaitGroup
// may not be waited on while another press is still adding to it.
func (d *DispatchHarness) PressConcurrently(user int64, data string, n int) []int {
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = d.h.press(user, data)
		}()
	}
	wg.Wait()
	d.h.loop.WaitDeliveries()
	return codes
}

// Press delivers a press of the button with callback data by user, as a
// new update, and returns the webhook's status.
func (d *DispatchHarness) Press(user int64, data string) int {
	code := d.h.press(user, data)
	d.h.loop.WaitDeliveries()
	return code
}

// PressUpdate is Press with a given update id, for a redelivery.
func (d *DispatchHarness) PressUpdate(updateID, user int64, data string) int {
	body := fmt.Sprintf(`{"update_id":%d,"callback_query":{"id":"cb","data":%q,"from":{"id":%d,"is_bot":false},`+
		`"message":{"message_id":9,"date":1,"chat":{"id":%d,"type":"private"}}}}`, updateID, data, user, user)
	code := deliver(d.h.hook, testSecret, body)
	d.h.loop.WaitDeliveries()
	return code
}

// NextUpdateID reserves an update id no other update of the harness uses.
func (d *DispatchHarness) NextUpdateID() int64 { return d.h.nextID.Add(1) }

// Replies returns every reply the conversations queued for user, oldest
// first.
func (d *DispatchHarness) Replies(user int64) []Reply {
	r := d.h.replies
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Reply
	for _, q := range r.replies {
		if q.principal == user {
			out = append(out, q.reply)
		}
	}
	return out
}

// DeliverNow sends principal's due outbox rows and waits for it.
func (d *DispatchHarness) DeliverNow(principal int64) {
	d.h.loop.DeliverAfter(context.Background(), principal)
	d.h.loop.WaitDeliveries()
}

// FailSends makes every send fail with err (nil sends again).
func (d *DispatchHarness) FailSends(err error) {
	d.h.sender.mu.Lock()
	d.h.sender.fail = err
	d.h.sender.mu.Unlock()
}
