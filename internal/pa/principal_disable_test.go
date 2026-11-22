package pa

// The admin per-principal disable and the preview allowlist (#1318 slice
// A1, threat model T11, S1-F4) at ingress and at every run-loop step.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// disableAdmin is the admin id recorded with a test disable.
const disableAdmin = 4242999

func disable(t *testing.T, s *db.Store, principal int64) {
	t.Helper()
	if err := s.SetPAPrincipalDisabled(context.Background(), principal, disableAdmin, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
}

// failingDisableStore makes it fail at ingress, as a store fault.
type failingDisableStore struct{ convo.Store }

func (failingDisableStore) PAPrincipalDisabled(context.Context, *sql.Tx, int64) (bool, error) {
	return false, fmt.Errorf("%w: %w: connection reset", convo.ErrUnreadable, convo.ErrStoreFault)
}

// TestConversations_DisabledPrincipalNotQueued: a disabled principal, and
// one not on the allowlist, get the fixed refusal once per rate window and
// nothing else: no fragment, conversation, job, callback or consent
// prompt. /forget and /consent withdraw still run. A disable that cannot
// be read rolls the update back for Telegram to retry, and stores nothing.
// It runs under the run loop's real limiter.
func TestConversations_DisabledPrincipalNotQueued(t *testing.T) {
	for name, refuse := range map[string]func(h *runLoopHarness){
		// Disabling resets the rate window, so the next update is told.
		"disabled": func(h *runLoopHarness) { disable(h.t, h.convoHarness.store, aliceID) },
		// The allowlist changes on restart only; a principal dropped from
		// it is told on the first update of their next window.
		"not allowed": func(h *runLoopHarness) {
			h.allow.deny(aliceID)
			h.now = h.now.Add(jobs.DefaultRateWindow)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newRunLoopHarness(t)
			jobsOf := func(p int64) int { return h.count(`SELECT count(*) FROM pa_jobs WHERE principal = $1`, p) }
			h.consent(aliceID)
			h.text(aliceID, "before")
			if h.fragments(aliceID) != 1 || jobsOf(aliceID) != 1 {
				t.Fatal("control: the message before the refusal was not stored and queued")
			}
			refuse(h)
			callbacks := h.count(`SELECT count(*) FROM pa_callbacks`)
			replies := h.repliesTo(aliceID)
			for i, msg := range []string{"after", "/consent", "/new"} {
				if code := h.text(aliceID, msg); code != http.StatusOK {
					t.Fatalf("%s: %d", msg, code)
				}
				got := h.repliesTo(aliceID)
				if i == 0 && (len(got) != len(replies)+1 || got[len(got)-1].reply != ReplyPrincipalDisabled || got[len(got)-1].button != "") {
					t.Fatalf("%s: replies %+v, want the fixed refusal once", msg, got[len(replies):])
				}
				if i > 0 && len(got) != len(replies)+1 {
					t.Fatalf("%s: refusal repeated inside the window: %+v", msg, got[len(replies):])
				}
			}
			if h.fragments(aliceID) != 1 || jobsOf(aliceID) != 1 ||
				h.count(`SELECT count(*) FROM pa_conversations WHERE principal = $1 AND closed_at_ms = 0`, aliceID) != 1 ||
				h.count(`SELECT count(*) FROM pa_callbacks`) != callbacks {
				t.Fatal("a refused principal's update stored or queued something")
			}
			// Bob is not touched.
			h.consent(bobID)
			h.text(bobID, "hi")
			if h.fragments(bobID) != 1 {
				t.Fatal("another principal was refused")
			}
			// Erasure still runs.
			h.text(aliceID, "/forget")
			if r := h.replies.last(aliceID); r.reply != ReplyForgotten || h.fragments(aliceID) != 0 {
				t.Fatalf("/forget for a refused principal: %+v, %d fragments", r, h.fragments(aliceID))
			}
			h.text(aliceID, "/consent withdraw")
			if r := h.replies.last(aliceID); r.reply != ReplyConsentWithdrawn {
				t.Fatalf("/consent withdraw for a refused principal: %+v", r)
			}
		})
	}
	t.Run("unreadable", func(t *testing.T) {
		h := newConvoHarness(t)
		h.consent(aliceID)
		sealer, err := convo.NewSealer(make([]byte, 32))
		if err != nil {
			t.Fatal(err)
		}
		h.conv, err = NewConversations(ConversationsConfig{
			Store: failingDisableStore{h.store}, Sealer: sealer, TTL: DefaultConversationTTL,
			Runs: h.runs, Replies: h.replies, Limiter: unlimited{}, Allowed: h.allow,
			Now: func() time.Time { return h.now },
		})
		if err != nil {
			t.Fatal(err)
		}
		h.hook = newWebhook(t, h.store, h.conv, nil)
		replies := len(h.replies.replies)
		updates := h.count(`SELECT count(*) FROM pa_updates`)
		if code := h.text(aliceID, "hello"); code < 500 {
			t.Fatalf("unreadable disable: %d, want a 5xx for Telegram to retry", code)
		}
		if h.fragments(aliceID) != 0 || len(h.runs.calls()) != 0 || len(h.replies.replies) != replies {
			t.Fatal("an unreadable disable stored, queued or answered")
		}
		if h.count(`SELECT count(*) FROM pa_updates`) != updates {
			t.Fatal("the update's dedup row was kept: Telegram would not retry")
		}
	})
}

// TestConversations_RefusalIsRateBounded: a refused principal is answered
// once per rate window however many updates they send, and gets no rate
// notice either, so a stranger cannot flood the outbox or the bot's send
// rate (#1318 review). Under the run loop's real limiter.
func TestConversations_RefusalIsRateBounded(t *testing.T) {
	lim := jobs.DefaultLimits()
	lim.RateMessages = 3
	h := newRunLoopHarness(t, withLimits(lim))
	h.allow.deny(aliceID)
	for i := range 3*lim.RateMessages + 1 {
		if code := h.text(aliceID, fmt.Sprintf("hi %d", i)); code != http.StatusOK {
			t.Fatalf("update %d: %d", i, code)
		}
	}
	if got := h.repliesTo(aliceID); len(got) != 1 || got[0].reply != ReplyPrincipalDisabled {
		t.Fatalf("replies %+v, want the refusal exactly once in the window", got)
	}
	if n := h.count(`SELECT count(*) FROM pa_jobs WHERE principal = $1`, aliceID); n != 0 {
		t.Fatalf("%d jobs for a refused principal", n)
	}
	// The next window is told once more.
	h.now = h.now.Add(lim.RateWindow)
	for range 2 {
		h.text(aliceID, "again")
	}
	if got := h.repliesTo(aliceID); len(got) != 2 || got[1].reply != ReplyPrincipalDisabled {
		t.Fatalf("replies %+v, want one more refusal in the next window", got)
	}
}

// to returns the replies queued for principal, in order.
func (r *replyRecorder) to(principal int64) []queuedReply {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []queuedReply
	for _, q := range r.replies {
		if q.principal == principal {
			out = append(out, q)
		}
	}
	return out
}

func (h *convoHarness) repliesTo(principal int64) []queuedReply { return h.replies.to(principal) }

// TestRunLoop_PrincipalDisabledStopsTurn: a principal disabled, or taken
// off the allowlist, after the claim is refused at the next turn; the job
// is cancelled, its reservation held, and the principal told once. One
// disabled before the claim is cancelled at the claim.
func TestRunLoop_PrincipalDisabledStopsTurn(t *testing.T) {
	unavailable := safetext.ServerText(safetext.TextAssistantUnavailable).String()
	for name, refuse := range map[string]func(h *runLoopHarness){
		"disabled":    func(h *runLoopHarness) { disable(h.t, h.convoHarness.store, aliceID) },
		"not allowed": func(h *runLoopHarness) { h.allow.deny(aliceID) },
	} {
		t.Run(name+" after claim", func(t *testing.T) {
			h := newRunLoopHarness(t)
			h.consent(aliceID)
			h.text(aliceID, "hello")
			c := h.mustClaim()
			if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 100}); w.Code != http.StatusOK {
				t.Fatalf("control turn: %d", w.Code)
			}
			refuse(h)
			w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 100})
			if w.Code != http.StatusConflict || stopOf(w) != "principal_disabled" {
				t.Fatalf("turn after the refusal: %d %q", w.Code, stopOf(w))
			}
			if js, us := h.jobStatus(c.JobID); js != "cancelled" || us != "held" {
				t.Fatalf("job %s usage %s", js, us)
			}
			if sent := h.sender.to(aliceID); len(sent) != 1 || sent[0] != unavailable {
				t.Fatalf("sent %q, want the unavailable notice once", sent)
			}
			if w := h.post(RouteReply, c.Token, replyRequest{Text: "secret"}); w.Code == http.StatusOK {
				t.Fatal("reply accepted after the refusal")
			}
			if len(h.sender.to(aliceID)) != 1 {
				t.Fatal("notice repeated or reply sent")
			}
		})
		t.Run(name+" before claim", func(t *testing.T) {
			h := newRunLoopHarness(t)
			h.consent(aliceID)
			h.text(aliceID, "hello")
			refuse(h)
			if _, code := h.claim(); code != http.StatusNoContent {
				t.Fatalf("claim of a refused principal's job: %d", code)
			}
			if n := h.count(`SELECT count(*) FROM pa_jobs WHERE principal = $1 AND status = 'cancelled'`, aliceID); n != 1 {
				t.Fatal("the job was not cancelled at the claim")
			}
			if h.count(`SELECT count(*) FROM pa_usage`) != 0 {
				t.Fatal("reserved for a refused principal")
			}
			if sent := h.sender.to(aliceID); len(sent) != 1 || sent[0] != unavailable {
				t.Fatalf("sent %q, want the unavailable notice once", sent)
			}
		})
	}
	t.Run("unreadable at the turn", func(t *testing.T) {
		var fail atomic.Bool
		h := newRunLoopHarness(t, withStore(func(s *db.Store) RunLoopStore { return &toggleDisable{Store: s, fail: &fail} }))
		h.consent(aliceID)
		h.text(aliceID, "hello")
		c := h.mustClaim()
		fail.Store(true)
		if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 100}); w.Code == http.StatusOK || stopOf(w) == "principal_disabled" {
			t.Fatalf("turn with an unreadable disable: %d %q, want a refusal that is not a disable", w.Code, stopOf(w))
		}
		if js, _ := h.jobStatus(c.JobID); js == "cancelled" {
			t.Fatal("an unreadable disable cancelled the job")
		}
	})
}

// toggleDisable fails the disable read once fail is set.
type toggleDisable struct {
	*db.Store
	fail *atomic.Bool
}

func (d *toggleDisable) PAPrincipalDisabled(ctx context.Context, tx *sql.Tx, p int64) (bool, error) {
	if d.fail.Load() {
		return false, errors.New("disable table unreadable")
	}
	return d.Store.PAPrincipalDisabled(ctx, tx, p)
}

// faultedDisable makes every disable read a store fault.
type faultedDisable struct{ *db.Store }

func (faultedDisable) PAPrincipalDisabled(context.Context, *sql.Tx, int64) (bool, error) {
	return true, fmt.Errorf("%w: %w: connection reset", convo.ErrUnreadable, convo.ErrStoreFault)
}

// TestRunLoop_PrincipalDisableStoreFaultChangesNothing: a store fault on
// the disable read at the claim is "could not observe": it refuses the
// claim, counts no failure against the job, never cancels it and tells
// nobody, however long it lasts. The job is claimed once the store
// recovers.
func TestRunLoop_PrincipalDisableStoreFaultChangesNothing(t *testing.T) {
	var fail atomic.Bool
	h := newRunLoopHarness(t, withStore(func(s *db.Store) RunLoopStore { return &toggleFault{Store: s, fail: &fail} }))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	fail.Store(true)
	for range 2 * jobs.MaxClaimFailures {
		h.now = h.now.Add(10 * time.Minute)
		if _, code := h.claim(); code != http.StatusServiceUnavailable {
			t.Fatalf("claim under a disable store fault: %d", code)
		}
	}
	if got := h.count(`SELECT count(*) FROM pa_jobs WHERE principal = $1 AND status = 'pending' AND claim_failures = 0`, aliceID); got != 1 {
		t.Fatal("a store fault on the disable read counted against the job or ended it")
	}
	if len(h.sender.to(aliceID)) != 0 || h.count(`SELECT count(*) FROM pa_usage`) != 0 {
		t.Fatal("a store fault sent a notice or reserved")
	}
	fail.Store(false)
	h.now = h.now.Add(time.Hour)
	if c := h.mustClaim(); c.Token == "" {
		t.Fatal("not claimed once the store recovered")
	}
}

// toggleFault returns faultedDisable's store fault once fail is set.
type toggleFault struct {
	*db.Store
	fail *atomic.Bool
}

func (d *toggleFault) PAPrincipalDisabled(ctx context.Context, tx *sql.Tx, p int64) (bool, error) {
	if d.fail.Load() {
		return faultedDisable{}.PAPrincipalDisabled(ctx, tx, p)
	}
	return d.Store.PAPrincipalDisabled(ctx, tx, p)
}
