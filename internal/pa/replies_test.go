package pa

// Conversation-level replies through the outbox (#1348): the consent
// prompt, its button and the command answers are written in the update's
// transaction by OutboxReplies, delivered after the commit, and sent once.

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// newOutboxRepliesHarness is the run-loop harness with the production
// reply path, wired as buildPA wires it: Conversations queue through
// OutboxReplies, and the webhook starts delivery once the update committed.
// replies, when set, wraps the production queue.
func newOutboxRepliesHarness(t *testing.T, store *db.Store, replies func(ReplyQueue) ReplyQueue, opts ...rlOption) *runLoopHarness {
	t.Helper()
	h := newRunLoopHarnessOn(t, store, opts...)
	sealer, err := convo.NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var q ReplyQueue = &OutboxReplies{Store: store, Now: func() time.Time { return h.now }}
	if replies != nil {
		q = replies(q)
	}
	h.conv, err = NewConversations(ConversationsConfig{
		Store: store, Sealer: sealer, TTL: DefaultConversationTTL,
		Runs: h.loop, Limiter: h.loop, Replies: q, Allowed: h.loop.allowed, Now: func() time.Time { return h.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.hook, err = NewWebhookHandler(WebhookConfig{
		Secret: testSecret, Dedup: store, Handler: h.conv, Failures: store,
		AfterCommit: func(ctx context.Context, u VerifiedUpdate) {
			h.loop.DeliverAfter(ctx, u.Principal().TelegramID())
			h.loop.AnswerCallbackAfter(ctx, u)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *runLoopHarness) messagesTo(chat int64) []sentMessage {
	h.loop.WaitDeliveries()
	return h.sender.messagesTo(chat)
}

type outboxRow struct {
	kind   string
	status string
	update int64
	job    int64
	button string
}

func (h *runLoopHarness) outboxRows(principal int64) []outboxRow {
	h.t.Helper()
	rows, err := h.convoHarness.store.PAOutboxRows(context.Background(), principal)
	if err != nil {
		h.t.Fatal(err)
	}
	out := make([]outboxRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, outboxRow{string(r.Kind), string(r.Status), r.UpdateID, r.JobID, r.Button})
	}
	return out
}

// consentButton returns the callback id of a sent consent prompt.
func consentButton(t *testing.T, m sentMessage) string {
	t.Helper()
	if m.text != convo.ConsentText {
		t.Fatalf("sent %q, want the consent text", m.text)
	}
	if len(m.kb) != 1 || len(m.kb[0]) != 1 || m.kb[0][0].Data == "" || m.kb[0][0].Label != safetext.LabelConsentAccept {
		t.Fatalf("prompt keyboard = %+v, want one consent button", m.kb)
	}
	return m.kb[0][0].Data
}

func eachStore(t *testing.T, fn func(t *testing.T, s *db.Store)) {
	t.Run("sqlite", func(t *testing.T) { fn(t, newStore(t)) })
	t.Run("postgres", func(t *testing.T) { fn(t, newPostgresStore(t)) })
}

// TestConversationReplies_E2E: a message without consent sends the prompt
// with its button and stores nothing; the button records consent and is
// answered; the next message is claimed, run and answered. Every reply
// went through the outbox, and only the webhook's after-commit delivery
// sent the conversation rows: no RunOutbox pass runs here.
func TestConversationReplies_E2E(t *testing.T) {
	eachStore(t, func(t *testing.T, s *db.Store) {
		h := newOutboxRepliesHarness(t, s, nil)
		if code := h.text(aliceID, "hello"); code != http.StatusOK {
			t.Fatalf("first message: %d", code)
		}
		msgs := h.messagesTo(aliceID)
		if len(msgs) != 1 {
			t.Fatalf("sent %d messages, want the consent prompt", len(msgs))
		}
		button := consentButton(t, msgs[0])
		if n := h.fragments(aliceID); n != 0 {
			t.Fatalf("%d fragments stored without consent", n)
		}
		if n := h.count(`SELECT count(*) FROM pa_jobs WHERE principal = $1`, aliceID); n != 0 {
			t.Fatalf("%d jobs enqueued without consent", n)
		}

		if code := h.press(aliceID, button); code != http.StatusOK {
			t.Fatalf("press: %d", code)
		}
		msgs = h.messagesTo(aliceID)
		if len(msgs) != 2 || msgs[1].text != safetext.ServerText(safetext.TextConsentAccepted).String() || msgs[1].kb != nil {
			t.Fatalf("after press = %+v", msgs)
		}

		if code := h.text(aliceID, "what is on https://example.org/a ?"); code != http.StatusOK {
			t.Fatalf("second message: %d", code)
		}
		w := newE2EWorker(t, h, &e2eModel{results: []*agentworker.ChatResult{e2eAnswer("It is https://example.org/a", 10, 1)}})
		c, err := w.Claim(context.Background())
		if err != nil || c == nil {
			t.Fatalf("claim = %v, %v", c, err)
		}
		if out, err := w.Run(context.Background(), c); out != agentworker.PAReplied || err != nil {
			t.Fatalf("run = %s, %v", out, err)
		}
		msgs = h.messagesTo(aliceID)
		if len(msgs) != 3 || !strings.Contains(msgs[2].text, "https://example.org/a") {
			t.Fatalf("after run = %+v", msgs)
		}

		rows := h.outboxRows(aliceID)
		if len(rows) != 3 {
			t.Fatalf("outbox = %+v", rows)
		}
		p, a, r := rows[0], rows[1], rows[2]
		if p.kind != string(jobs.OutboxConsentPrompt) || p.status != "sent" || p.update <= 0 || p.job != 0 || p.button != button {
			t.Fatalf("prompt row = %+v", p)
		}
		if a.kind != string(jobs.OutboxConsentAccepted) || a.status != "sent" || a.update <= p.update || a.job != 0 || a.button != "" {
			t.Fatalf("accepted row = %+v", a)
		}
		if r.kind != string(jobs.OutboxReply) || r.status != "sent" || r.job != c.JobID || r.update != 0 {
			t.Fatalf("reply row = %+v", r)
		}
	})
}

// TestConversationReplies_RolledBackUpdateLeavesNoRow: a reply queued by
// an update whose transaction rolls back is neither stored nor sent.
func TestConversationReplies_RolledBackUpdateLeavesNoRow(t *testing.T) {
	eachStore(t, func(t *testing.T, s *db.Store) {
		h := newOutboxRepliesHarness(t, s, func(q ReplyQueue) ReplyQueue { return failAfterQueue{q} })
		if code := h.text(aliceID, "hello"); code != http.StatusInternalServerError {
			t.Fatalf("update = %d, want 500 (rolled back)", code)
		}
		if rows := h.outboxRows(aliceID); len(rows) != 0 {
			t.Fatalf("rows of a rolled-back update: %+v", rows)
		}
		h.now = h.now.Add(time.Minute)
		h.loop.outboxPass(context.Background())
		if msgs := h.messagesTo(aliceID); len(msgs) != 0 {
			t.Fatalf("sent %+v for a rolled-back update", msgs)
		}
	})
}

// failAfterQueue queues the reply, then fails the update.
type failAfterQueue struct{ inner ReplyQueue }

func (f failAfterQueue) QueueReply(ctx context.Context, tx *sql.Tx, p Principal, update int64, r Reply, button string) error {
	if err := f.inner.QueueReply(ctx, tx, p, update, r, button); err != nil {
		return err
	}
	return errors.New("update fails after its reply was queued")
}

// TestConversationReplies_LostSendNotRetried: a prompt whose send may have
// reached Telegram is unknown, counted once, and never sent again.
func TestConversationReplies_LostSendNotRetried(t *testing.T) {
	counts := outboxCounts{}
	h := newOutboxRepliesHarness(t, newStore(t), nil, withOutboxCounter(counts))
	h.failSends(cutOff)
	if code := h.text(aliceID, "hello"); code != http.StatusOK {
		t.Fatalf("update = %d", code)
	}
	h.loop.WaitDeliveries()
	if st := h.outboxStatus(jobs.OutboxConsentPrompt); st != "unknown" || counts[OutboxOutcomeUnknown] != 1 {
		t.Fatalf("status %q, counts %v", st, counts)
	}
	h.failSends(nil)
	for range 3 {
		h.now = h.now.Add(time.Hour)
		h.loop.outboxPass(context.Background())
	}
	if msgs := h.messagesTo(aliceID); len(msgs) != 0 {
		t.Fatalf("an unknown prompt was sent again: %+v", msgs)
	}
	if counts[OutboxOutcomeSent] != 0 || counts[OutboxOutcomeUnknown] != 1 {
		t.Fatalf("counts %v", counts)
	}
}

// TestConversationReplies_FloodWaitRetriesWithButton: a prompt refused
// with a flood wait stays due, and the retry carries the same button.
func TestConversationReplies_FloodWaitRetriesWithButton(t *testing.T) {
	counts := outboxCounts{}
	h := newOutboxRepliesHarness(t, newStore(t), nil, withOutboxCounter(counts))
	h.failSends(floodWait)
	h.text(aliceID, "hello")
	h.loop.WaitDeliveries()
	if st := h.outboxStatus(jobs.OutboxConsentPrompt); st != "pending" || counts[OutboxOutcomeRetry] != 1 {
		t.Fatalf("status %q, counts %v", st, counts)
	}
	h.failSends(nil)
	h.now = h.now.Add(time.Minute)
	h.loop.outboxPass(context.Background())
	msgs := h.messagesTo(aliceID)
	if len(msgs) != 1 || counts[OutboxOutcomeSent] != 1 {
		t.Fatalf("sent %+v, counts %v", msgs, counts)
	}
	button := consentButton(t, msgs[0])
	if rows := h.outboxRows(aliceID); len(rows) != 1 || rows[0].button != button {
		t.Fatalf("rows %+v, button %q", rows, button)
	}
	// The retried button still records consent.
	h.press(aliceID, button)
	if got := h.messagesTo(aliceID); len(got) != 2 || got[1].text != safetext.ServerText(safetext.TextConsentAccepted).String() {
		t.Fatalf("after press = %+v", got)
	}
}

// TestConversationReplies_CommandsAnswered: /new, /forget, /consent
// withdraw and an unknown button are each answered with their text.
func TestConversationReplies_CommandsAnswered(t *testing.T) {
	h := newOutboxRepliesHarness(t, newStore(t), nil)
	h.text(aliceID, "/new")
	h.text(aliceID, "/forget")
	h.text(aliceID, "/consent withdraw")
	h.press(aliceID, "no-such-button")
	want := []safetext.Template{safetext.TextNewConversation, safetext.TextForgotten, safetext.TextConsentWithdrawn, safetext.TextUnknownButton}
	msgs := h.messagesTo(aliceID)
	if len(msgs) != len(want) {
		t.Fatalf("sent %d messages, want %d", len(msgs), len(want))
	}
	for i, tpl := range want {
		if msgs[i].text != safetext.ServerText(tpl).String() || msgs[i].kb != nil {
			t.Fatalf("message %d = %q, want %q", i, msgs[i].text, safetext.ServerText(tpl).String())
		}
	}
}

// TestConsentPromptIsConsentText: the prompt sends exactly the text whose
// hash its button binds, in one message.
func TestConsentPromptIsConsentText(t *testing.T) {
	txt := safetext.ServerText(safetext.TextConsentPrompt)
	if txt.String() != convo.ConsentText || txt.Parts() != 1 {
		t.Fatalf("consent prompt differs from convo.ConsentText (parts %d)", txt.Parts())
	}
}

// TestEveryReplyHasAKindAndATemplate: each Reply maps to its own
// conversation-level kind, and each such kind to a non-empty server text.
func TestEveryReplyHasAKindAndATemplate(t *testing.T) {
	all := []Reply{ReplyConsentPrompt, ReplyConsentAccepted, ReplyConsentWithdrawn, ReplyConsentStale,
		ReplyNewConversation, ReplyForgotten, ReplyUnknownButton, ReplyRateLimited, ReplyMessageTooLong,
		ReplyLinkingUnavailable, ReplyPrincipalDisabled}
	if len(replyKinds) != len(all) || len(jobs.ConversationOutboxKinds()) != len(all) {
		t.Fatalf("%d replies, %d mapped, %d kinds", len(all), len(replyKinds), len(jobs.ConversationOutboxKinds()))
	}
	seen := map[jobs.OutboxKind]bool{}
	for _, r := range all {
		k, ok := replyKinds[r]
		if !ok || !k.ConversationLevel() || seen[k] || string(k) != string(r) {
			t.Fatalf("reply %q -> kind %q", r, k)
		}
		seen[k] = true
		tpl, ok := outboxTemplates[k]
		if !ok || safetext.ServerText(tpl).Parts() == 0 {
			t.Fatalf("kind %q has no server text", k)
		}
	}
	var q OutboxReplies
	if err := q.QueueReply(context.Background(), nil, Principal{}, 1, Reply("nope"), ""); !errors.Is(err, ErrUnknownReply) {
		t.Fatalf("unknown reply = %v", err)
	}
}

// TestOutboxKeyboard: only a consent prompt carries a button, and a prompt
// row without its id is not sendable.
func TestOutboxKeyboard(t *testing.T) {
	if kb, ok := outboxKeyboard(jobs.OutboxItem{Kind: jobs.OutboxConsentPrompt, Button: "id"}); !ok || len(kb) != 1 || kb[0][0].Data != "id" {
		t.Fatalf("prompt keyboard = %+v, %v", kb, ok)
	}
	if _, ok := outboxKeyboard(jobs.OutboxItem{Kind: jobs.OutboxConsentPrompt}); ok {
		t.Fatal("a prompt without its button is sendable")
	}
	if kb, ok := outboxKeyboard(jobs.OutboxItem{Kind: jobs.OutboxForgotten}); !ok || kb != nil {
		t.Fatalf("forgotten keyboard = %+v, %v", kb, ok)
	}
	if _, ok := outboxKeyboard(jobs.OutboxItem{Kind: jobs.OutboxRunFailed, Button: "x"}); ok {
		t.Fatal("a button on another kind is sendable")
	}
}
