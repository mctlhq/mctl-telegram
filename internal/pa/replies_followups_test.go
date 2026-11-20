package pa

// Follow-ups to #1352's deferred findings: a pressed button is answered
// after its commit (answerCallbackQuery), a consent prompt held back until
// its button no longer resolves is not sent, and a reply lost to a reused
// update id is counted.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
)

type callbackCounts struct {
	mu sync.Mutex
	m  map[string]int
}

func (c *callbackCounts) CountPACallbackAnswer(o string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]int{}
	}
	c.m[o]++
}

func (c *callbackCounts) get(o string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[o]
}

func withCallbackCounter(c *callbackCounts) rlOption {
	return func(cfg *RunLoopConfig, _ *runLoopHarness) { cfg.CallbackMetrics = c }
}

func withLockedOutboxCounter(c *lockedCounts) rlOption {
	return func(cfg *RunLoopConfig, _ *runLoopHarness) { cfg.Metrics = c }
}

// pressAs delivers a button press with the given update and callback query
// ids.
func (h *runLoopHarness) pressAs(user, updateID int64, queryID, data string) int {
	h.t.Helper()
	body := fmt.Sprintf(`{"update_id":%d,"callback_query":{"id":%q,"data":%q,"from":{"id":%d,"is_bot":false},`+
		`"message":{"message_id":9,"date":1,"chat":{"id":%d,"type":"private"}}}}`, updateID, queryID, data, user, user)
	return deliver(h.hook, testSecret, body)
}

// TestConversationReplies_PressIsAnswered: a press whose update committed
// is answered once, with its own callback query id and no notice; a
// message is not answered, and neither is a redelivered press (the
// duplicate) or one whose update rolled back.
func TestConversationReplies_PressIsAnswered(t *testing.T) {
	eachStore(t, func(t *testing.T, s *db.Store) {
		cb := &callbackCounts{}
		h := newOutboxRepliesHarness(t, s, nil, withCallbackCounter(cb))
		if code := h.text(aliceID, "hello"); code != http.StatusOK {
			t.Fatalf("message: %d", code)
		}
		button := consentButton(t, h.messagesTo(aliceID)[0])
		if a := h.sender.answers(); len(a) != 0 {
			t.Fatalf("a message was answered as a callback: %v", a)
		}
		update := h.nextID.Add(1)
		if code := h.pressAs(aliceID, update, "cbq-alice-1", button); code != http.StatusOK {
			t.Fatalf("press: %d", code)
		}
		h.loop.WaitDeliveries()
		if a := h.sender.answers(); !slices.Equal(a, []string{"cbq-alice-1"}) {
			t.Fatalf("answers = %v, want [cbq-alice-1]", a)
		}
		if cb.get(CallbackAnswerAnswered) != 1 || cb.get(CallbackAnswerFailed) != 0 {
			t.Fatalf("callback counts = %v", cb.m)
		}
		// Telegram redelivers the same update: the dedup refuses it, and
		// it is not answered a second time.
		if code := h.pressAs(aliceID, update, "cbq-alice-1", button); code != http.StatusOK {
			t.Fatalf("redelivered press: %d", code)
		}
		h.loop.WaitDeliveries()
		if a := h.sender.answers(); len(a) != 1 {
			t.Fatalf("a duplicate press was answered again: %v", a)
		}
		msgs := h.messagesTo(aliceID)
		if len(msgs) != 2 || msgs[1].text != output.ServerText(output.TextConsentAccepted).String() {
			t.Fatalf("sent = %+v", msgs)
		}
	})
}

// TestConversationReplies_RolledBackPressNotAnswered: a press whose update
// rolled back is not answered; Telegram retries it, and that delivery is.
func TestConversationReplies_RolledBackPressNotAnswered(t *testing.T) {
	h := newOutboxRepliesHarness(t, newStore(t), func(q ReplyQueue) ReplyQueue { return failAfterQueue{q} })
	if code := h.pressAs(aliceID, h.nextID.Add(1), "cbq-rolled-back", "no-such-button"); code != http.StatusInternalServerError {
		t.Fatalf("press = %d, want 500 (rolled back)", code)
	}
	h.loop.WaitDeliveries()
	if a := h.sender.answers(); len(a) != 0 {
		t.Fatalf("a rolled-back press was answered: %v", a)
	}
}

// TestConversationReplies_FailedAnswerIsCountedNotFatal: an answer the Bot
// API refuses is counted and logged; the press itself stands and its reply
// is delivered.
func TestConversationReplies_FailedAnswerIsCountedNotFatal(t *testing.T) {
	cb := &callbackCounts{}
	h := newOutboxRepliesHarness(t, newStore(t), nil, withCallbackCounter(cb))
	h.text(aliceID, "hello")
	button := consentButton(t, h.messagesTo(aliceID)[0])
	h.sender.mu.Lock()
	h.sender.answerFail = &output.APIError{Method: "answerCallbackQuery", Status: 400, Code: 400, Description: "query is too old"}
	h.sender.mu.Unlock()
	if code := h.pressAs(aliceID, h.nextID.Add(1), "cbq-too-old", button); code != http.StatusOK {
		t.Fatalf("press: %d, want 200 (an unanswered query does not fail the update)", code)
	}
	h.loop.WaitDeliveries()
	if cb.get(CallbackAnswerFailed) != 1 || cb.get(CallbackAnswerAnswered) != 0 {
		t.Fatalf("callback counts = %v", cb.m)
	}
	msgs := h.messagesTo(aliceID)
	if len(msgs) != 2 || msgs[1].text != output.ServerText(output.TextConsentAccepted).String() {
		t.Fatalf("sent = %+v", msgs)
	}
}

// TestConversationReplies_ExpiredButtonNotSent: a prompt held back by
// flood waits until its button would expire is dropped, unsent, as
// button_expired; one that still has time is sent with its button.
func TestConversationReplies_ExpiredButtonNotSent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after time.Duration
		sent  bool
	}{
		{"still live", ConsentPromptTTL - outboxButtonMinLife - time.Minute, true},
		{"within the minimum life", ConsentPromptTTL - outboxButtonMinLife + time.Minute, false},
		{"expired", ConsentPromptTTL + time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eachStore(t, func(t *testing.T, s *db.Store) {
				counts := outboxCounts{}
				h := newOutboxRepliesHarness(t, s, nil, withOutboxCounter(counts))
				h.failSends(floodWait)
				h.text(aliceID, "hello")
				h.loop.WaitDeliveries()
				if st := h.outboxStatus(jobs.OutboxConsentPrompt); st != "pending" {
					t.Fatalf("status %q after a flood wait", st)
				}
				h.failSends(nil)
				h.now = h.now.Add(tc.after)
				h.loop.outboxPass(context.Background())
				msgs := h.messagesTo(aliceID)
				if tc.sent {
					if len(msgs) != 1 || counts[OutboxOutcomeSent] != 1 {
						t.Fatalf("sent %+v, counts %v", msgs, counts)
					}
					consentButton(t, msgs[0])
					return
				}
				if len(msgs) != 0 {
					t.Fatalf("a prompt with a dead button was sent: %+v", msgs)
				}
				if st := h.outboxStatus(jobs.OutboxConsentPrompt); st != "dropped" || counts[OutboxOutcomeButtonExpired] != 1 {
					t.Fatalf("status %q, counts %v", st, counts)
				}
				// Terminal: later passes do not send it either.
				h.now = h.now.Add(time.Hour)
				h.loop.outboxPass(context.Background())
				if msgs := h.messagesTo(aliceID); len(msgs) != 0 {
					t.Fatalf("a dropped prompt was sent later: %+v", msgs)
				}
			})
		})
	}
}

// TestConversationReplies_MissingButtonNotSent: a prompt whose callback id
// is gone (purged, consumed) is dropped as button_expired, not sent.
func TestConversationReplies_MissingButtonNotSent(t *testing.T) {
	counts := outboxCounts{}
	h := newOutboxRepliesHarness(t, newStore(t), nil, withOutboxCounter(counts))
	h.failSends(floodWait)
	h.text(aliceID, "hello")
	h.loop.WaitDeliveries()
	if _, err := h.convoHarness.store.DB.Exec(`DELETE FROM pa_callbacks WHERE principal = $1`, aliceID); err != nil {
		t.Fatal(err)
	}
	h.failSends(nil)
	h.now = h.now.Add(time.Minute)
	h.loop.outboxPass(context.Background())
	if msgs := h.messagesTo(aliceID); len(msgs) != 0 {
		t.Fatalf("a prompt without its callback was sent: %+v", msgs)
	}
	if st := h.outboxStatus(jobs.OutboxConsentPrompt); st != "dropped" || counts[OutboxOutcomeButtonExpired] != 1 {
		t.Fatalf("status %q, counts %v", st, counts)
	}
}

// TestConversationReplies_DeliveredPromptStaysSent: a prompt delivered in
// full on an earlier attempt, whose completion write was lost, is recorded
// as sent even though its button was pressed (consumed) since; it is not
// sent again and not counted as button_expired.
func TestConversationReplies_DeliveredPromptStaysSent(t *testing.T) {
	counts := outboxCounts{}
	h := newOutboxRepliesHarness(t, newStore(t), nil, withOutboxCounter(counts))
	h.failSends(floodWait)
	h.text(aliceID, "hello")
	h.loop.WaitDeliveries()
	// Every part reached Telegram; only the completion was lost. Then the
	// principal pressed the button, which consumed its callback.
	if _, err := h.convoHarness.store.DB.Exec(`UPDATE pa_outbox SET sent_parts = 1 WHERE principal = $1 AND kind = $2`,
		aliceID, jobs.OutboxConsentPrompt); err != nil {
		t.Fatal(err)
	}
	if _, err := h.convoHarness.store.DB.Exec(`DELETE FROM pa_callbacks WHERE principal = $1`, aliceID); err != nil {
		t.Fatal(err)
	}
	h.failSends(nil)
	h.now = h.now.Add(time.Minute)
	h.loop.outboxPass(context.Background())
	if msgs := h.messagesTo(aliceID); len(msgs) != 0 {
		t.Fatalf("a delivered prompt was sent again: %+v", msgs)
	}
	if st := h.outboxStatus(jobs.OutboxConsentPrompt); st != "sent" || counts[OutboxOutcomeSent] != 1 || counts[OutboxOutcomeButtonExpired] != 0 {
		t.Fatalf("status %q, counts %v", st, counts)
	}
}

// callbackExpiryDown fails the button read.
type callbackExpiryDown struct{ *db.Store }

func (callbackExpiryDown) PACallbackExpiry(context.Context, int64, string) (time.Time, error) {
	return time.Time{}, fmt.Errorf("%w: connection reset", convo.ErrStoreFault)
}

// TestConversationReplies_UnreadableButtonRetried: a button that could not
// be read is neither sent nor dropped: nothing is known about it, so the
// prompt stays due.
func TestConversationReplies_UnreadableButtonRetried(t *testing.T) {
	counts := outboxCounts{}
	h := newOutboxRepliesHarness(t, newStore(t), nil, withOutboxCounter(counts),
		withStore(func(s *db.Store) RunLoopStore { return callbackExpiryDown{s} }))
	h.text(aliceID, "hello")
	h.loop.WaitDeliveries()
	if msgs := h.messagesTo(aliceID); len(msgs) != 0 {
		t.Fatalf("sent with an unreadable button: %+v", msgs)
	}
	if st := h.outboxStatus(jobs.OutboxConsentPrompt); st != "pending" || counts[OutboxOutcomeRetry] != 1 || counts[OutboxOutcomeButtonExpired] != 0 {
		t.Fatalf("status %q, counts %v", st, counts)
	}
}

// TestConversationReplies_ReusedUpdateIDCounted: an update id Telegram
// reuses after its dedup row was purged runs again; the reply it owes
// collides with the first one's row, is not queued, and is counted and
// logged instead of lost silently. The update itself is accepted.
func TestConversationReplies_ReusedUpdateIDCounted(t *testing.T) {
	eachStore(t, func(t *testing.T, s *db.Store) {
		counts := &lockedCounts{m: outboxCounts{}}
		h := newOutboxRepliesHarness(t, s, func(q ReplyQueue) ReplyQueue {
			q.(*OutboxReplies).Metrics = counts
			return q
		}, withLockedOutboxCounter(counts))
		h.nextID.Store(7_000_000)
		if code := h.text(aliceID, "/new"); code != http.StatusOK {
			t.Fatalf("first: %d", code)
		}
		h.loop.WaitDeliveries()
		reused := h.nextID.Load()
		if got := counts.get()[OutboxOutcomeUpdateReused]; got != 0 {
			t.Fatalf("update_reused = %d before any reuse", got)
		}
		// The dedup row is gone (retention purge), and Telegram hands out
		// the same update id again.
		if _, err := h.convoHarness.store.DB.Exec(`DELETE FROM pa_updates WHERE update_id = $1`, reused); err != nil {
			t.Fatal(err)
		}
		h.nextID.Store(reused - 1)
		if code := h.text(aliceID, "/new"); code != http.StatusOK {
			t.Fatalf("reused: %d, want 200", code)
		}
		h.loop.WaitDeliveries()
		if got := counts.get()[OutboxOutcomeUpdateReused]; got != 1 {
			t.Fatalf("update_reused = %d, want 1 (counts %v)", got, counts.get())
		}
		rows := h.outboxRows(aliceID)
		if len(rows) != 1 || rows[0].update != reused || rows[0].kind != string(jobs.OutboxNewConversation) {
			t.Fatalf("rows = %+v", rows)
		}
		if msgs := h.messagesTo(aliceID); len(msgs) != 1 {
			t.Fatalf("sent %d, want only the first answer", len(msgs))
		}
	})
}

// TestOutboxReplies_OtherEnqueueErrorsPropagate: only the update-reuse
// conflict is absorbed; any other enqueue failure rolls the update back.
func TestOutboxReplies_OtherEnqueueErrorsPropagate(t *testing.T) {
	boom := errors.New("enqueue failed")
	q := &OutboxReplies{Store: enqueueErr{boom}}
	if err := q.QueueReply(context.Background(), nil, Principal{telegramID: aliceID}, 1, ReplyForgotten, ""); !errors.Is(err, boom) {
		t.Fatalf("QueueReply = %v, want the enqueue error", err)
	}
}

type enqueueErr struct{ err error }

func (e enqueueErr) EnqueuePAOutbox(context.Context, *sql.Tx, jobs.OutboxItem, time.Time) error {
	return e.err
}
