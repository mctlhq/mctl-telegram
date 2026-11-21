package pa

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
)

// linkHarness is the conversation harness with the linking flow on and an
// AfterCommit hook that records what the handler handed to it.
type linkHarness struct {
	*convoHarness
	mu sync.Mutex
	// after are the actions AfterCommit found, in order.
	after []LinkAction
	// afterErr is the result of taking the principal lock in its own
	// transaction from AfterCommit, as Manager.Begin does.
	afterErr []error
	consumed int
}

// consumeCounter counts pa_callbacks consumptions.
type consumeCounter struct {
	*db.Store
	h *linkHarness
}

func (s consumeCounter) ConsumePACallback(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) (string, error) {
	s.h.mu.Lock()
	s.h.consumed++
	s.h.mu.Unlock()
	return s.Store.ConsumePACallback(ctx, tx, principal, id, now)
}

func newLinkHarness(t *testing.T, linking bool) *linkHarness {
	t.Helper()
	base := newConvoHarness(t)
	h := &linkHarness{convoHarness: base}
	sealer, err := convo.NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	base.conv, err = NewConversations(ConversationsConfig{
		Store: consumeCounter{Store: base.store, h: h}, Sealer: sealer, TTL: DefaultConversationTTL,
		Runs: base.runs, Replies: base.replies, Limiter: unlimited{}, Linking: linking,
		Now: func() time.Time { return base.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	wh, err := NewWebhookHandler(WebhookConfig{
		Secret: testSecret, Dedup: base.store, Handler: base.conv, Failures: base.store,
		AfterCommit: func(ctx context.Context, u VerifiedUpdate) {
			a, ok := PostCommitAction(ctx)
			if !ok {
				return
			}
			// What a linking action does first: take the principal lock in
			// a transaction of its own. Inside the update's transaction this
			// is the self-wait the post-commit split exists to avoid.
			actx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			_, err := base.store.AdmitPAConnection(actx, u.Principal().TelegramID())
			h.mu.Lock()
			h.after = append(h.after, a)
			h.afterErr = append(h.afterErr, err)
			h.mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	base.hook = wh
	return h
}

func (h *linkHarness) actions() ([]LinkAction, []error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]LinkAction(nil), h.after...), append([]error(nil), h.afterErr...)
}

// TestConversations_ConnectRunsAfterCommit: a linking command from a
// consenting principal is admitted in the update's transaction and handed
// to AfterCommit, where taking the principal lock in a new transaction
// succeeds because the update's transaction is over. A linking button is
// handed over the same way and is not consumed from pa_callbacks.
func TestConversations_ConnectRunsAfterCommit(t *testing.T) {
	h := newLinkHarness(t, true)
	const alice = 100001
	h.consent(alice)
	for _, tc := range []struct{ text, cmd, arg string }{
		{"/connect tg", CommandConnect, "tg"},
		{"/Disconnect TG", CommandDisconnect, "tg"},
		{"/connections", CommandConnections, ""},
	} {
		if code := h.text(alice, tc.text); code != http.StatusOK {
			t.Fatalf("%s: status %d", tc.text, code)
		}
		got, errs := h.actions()
		last := got[len(got)-1]
		if last.Command != tc.cmd || last.Arg != tc.arg || last.Button {
			t.Fatalf("%s: action %+v", tc.text, last)
		}
		if err := errs[len(errs)-1]; err != nil {
			t.Fatalf("%s: principal lock after the commit: %v", tc.text, err)
		}
	}
	if n := h.fragments(alice); n != 0 {
		t.Fatalf("a linking command was stored as %d fragments", n)
	}
	before := h.consumed
	data := "pa:lc:" + strings.Repeat("A", 43)
	if code := h.press(alice, data); code != http.StatusOK {
		t.Fatalf("press: status %d", code)
	}
	got, errs := h.actions()
	if last := got[len(got)-1]; !last.Button || last.Command != "" {
		t.Fatalf("press: action %+v", last)
	}
	if errs[len(errs)-1] != nil {
		t.Fatalf("press: principal lock after the commit: %v", errs[len(errs)-1])
	}
	if h.consumed != before {
		t.Fatal("a linking button was consumed from pa_callbacks")
	}
	if r := h.replies.last(alice); r.reply == ReplyUnknownButton {
		t.Fatal("a linking button was answered as unknown in the transaction")
	}
}

// TestConversations_LinkCommandNeedsConsent: without consent a linking
// command shows the consent prompt and hands nothing to AfterCommit.
func TestConversations_LinkCommandNeedsConsent(t *testing.T) {
	h := newLinkHarness(t, true)
	const bob = 100002
	if code := h.text(bob, "/connect tg"); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if got, _ := h.actions(); len(got) != 0 {
		t.Fatalf("actions without consent: %+v", got)
	}
	if r := h.replies.last(bob); r.reply != ReplyConsentPrompt {
		t.Fatalf("reply %q, want the consent prompt", r.reply)
	}
}

// TestConversations_LinkingOffAnswersUnavailable: with no linking flow a
// linking command is answered in the transaction and a linking-looking
// button takes the pa_callbacks path; nothing reaches AfterCommit.
func TestConversations_LinkingOffAnswersUnavailable(t *testing.T) {
	h := newLinkHarness(t, false)
	const carol = 100003
	h.consent(carol)
	for i, text := range []string{"/connect tg", "/disconnect tg", "/connections"} {
		if code := h.text(carol, text); code != http.StatusOK {
			t.Fatalf("%s: status %d", text, code)
		}
		if r := h.replies.last(carol); r.reply != ReplyLinkingUnavailable {
			t.Fatalf("%s (%d): reply %q", text, i, r.reply)
		}
	}
	before := h.consumed
	if code := h.press(carol, "pa:lc:"+strings.Repeat("A", 43)); code != http.StatusOK {
		t.Fatal("press")
	}
	if h.consumed != before+1 || h.replies.last(carol).reply != ReplyUnknownButton {
		t.Fatalf("linking off: button consumed %d times, reply %q", h.consumed-before, h.replies.last(carol).reply)
	}
	if got, _ := h.actions(); len(got) != 0 {
		t.Fatalf("actions with linking off: %+v", got)
	}
}

// TestPostCommit_NoSlotFailsTheUpdate: a handler run without a post-commit
// slot cannot lose the action silently.
func TestPostCommit_NoSlotFailsTheUpdate(t *testing.T) {
	if err := setPostCommit(context.Background(), LinkAction{Command: CommandConnect}); err != ErrNoPostCommit {
		t.Fatalf("err = %v, want ErrNoPostCommit", err)
	}
	ctx := WithPostCommit(context.Background())
	if _, ok := PostCommitAction(ctx); ok {
		t.Fatal("empty slot reported an action")
	}
	if err := setPostCommit(ctx, LinkAction{Command: CommandConnect, Arg: "tg"}); err != nil {
		t.Fatal(err)
	}
	if a, ok := PostCommitAction(ctx); !ok || a.Command != CommandConnect || a.Arg != "tg" {
		t.Fatalf("action %+v %v", a, ok)
	}
}
