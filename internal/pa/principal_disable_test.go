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
// one not on the allowlist, get the fixed refusal and nothing else: no
// fragment, conversation, job, callback or consent prompt. /forget and
// /consent withdraw still run. A disable that cannot be read rolls the
// update back for Telegram to retry, and stores nothing.
func TestConversations_DisabledPrincipalNotQueued(t *testing.T) {
	for name, refuse := range map[string]func(h *convoHarness){
		"disabled":    func(h *convoHarness) { disable(h.t, h.store, aliceID) },
		"not allowed": func(h *convoHarness) { h.allow.deny(aliceID) },
	} {
		t.Run(name, func(t *testing.T) {
			h := newConvoHarness(t)
			h.consent(aliceID)
			h.text(aliceID, "before")
			if h.fragments(aliceID) != 1 || len(h.runs.calls()) != 1 {
				t.Fatal("control: the message before the refusal was not stored and queued")
			}
			refuse(h)
			callbacks := h.count(`SELECT count(*) FROM pa_callbacks`)
			for _, msg := range []string{"after", "/consent", "/new"} {
				if code := h.text(aliceID, msg); code != http.StatusOK {
					t.Fatalf("%s: %d", msg, code)
				}
				if r := h.replies.last(aliceID); r.reply != ReplyPrincipalDisabled || r.button != "" {
					t.Fatalf("%s: reply %+v, want the fixed refusal", msg, r)
				}
			}
			if h.fragments(aliceID) != 1 || len(h.runs.calls()) != 1 ||
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
