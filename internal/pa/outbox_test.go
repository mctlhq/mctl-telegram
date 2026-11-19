package pa

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
)

// Outbox delivery through the run loop (issue #1313 slice d2, d1 deferral
// F4): a message owed after a commit is not lost when the send fails.

type outboxCounts map[string]int

func (c outboxCounts) CountPAOutbox(o string) { c[o]++ }

func withOutboxCounter(c outboxCounts) rlOption {
	return func(cfg *RunLoopConfig, _ *runLoopHarness) { cfg.Metrics = c }
}

func (h *runLoopHarness) outboxStatus(kind jobs.OutboxKind) string {
	h.t.Helper()
	var st string
	_ = h.convoHarness.store.DB.QueryRow(`SELECT status FROM pa_outbox WHERE principal = $1 AND kind = $2 ORDER BY id DESC LIMIT 1`,
		aliceID, string(kind)).Scan(&st)
	return st
}

func (h *runLoopHarness) failSends(err error) {
	h.sender.mu.Lock()
	h.sender.fail = err
	h.sender.mu.Unlock()
}

var floodWait = &output.APIError{Method: "sendMessage", Status: 429, Code: 429, RetryAfter: 3}

// TestRunLoop_ReplySurvivesFailedSend: the answer is committed with the
// job; a failed send answers delivered:false, and the background pass
// sends it once, rendered again from the stored fragment.
func TestRunLoop_ReplySurvivesFailedSend(t *testing.T) {
	counts := outboxCounts{}
	h := newRunLoopHarness(t, withOutboxCounter(counts))
	h.consent(aliceID)
	h.text(aliceID, "summarise https://example.org/a please")
	c := h.mustClaim()
	h.failSends(floodWait)
	w := h.post(RouteReply, c.Token, replyRequest{Text: "See https://example.org/a and https://evil.example/x"})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"delivered":false`) {
		t.Fatalf("reply: %d %s", w.Code, w.Body)
	}
	if js, _ := h.jobStatus(c.JobID); js != "done" || h.outboxStatus(jobs.OutboxReply) != "pending" {
		t.Fatalf("job %s outbox %s: the answer must be kept for a retry", js, h.outboxStatus(jobs.OutboxReply))
	}
	h.failSends(nil)
	// Not before its backoff, and not more than once after it.
	h.loop.deliver(context.Background(), 0)
	if len(h.sender.to(aliceID)) != 0 {
		t.Fatal("a retry went out before its backoff")
	}
	h.now = h.now.Add(jobs.OutboxBackoff(1))
	h.loop.deliver(context.Background(), 0)
	h.loop.deliver(context.Background(), 0)
	sent := h.sender.to(aliceID)
	if len(sent) != 1 || !strings.Contains(sent[0], "https://example.org/a") || strings.Contains(sent[0], "evil.example/x") {
		t.Fatalf("sent %q: one reply, through Render with only the typed URL", sent)
	}
	if h.outboxStatus(jobs.OutboxReply) != "sent" || counts[OutboxOutcomeRetry] != 1 || counts[OutboxOutcomeSent] != 1 {
		t.Fatalf("outbox %s counts %v", h.outboxStatus(jobs.OutboxReply), counts)
	}
}

// TestRunLoop_NoticesSurviveFailedSend: the hold, run-failed and dropped
// notices are retried after a failed send.
func TestRunLoop_NoticesSurviveFailedSend(t *testing.T) {
	h := newRunLoopHarness(t, withBudget(jobs.Budget{PerJobUSD: 0.25, PrincipalDayUSD: 0.25, PrincipalMonthUSD: 20, GlobalDayUSD: 20}))
	h.consent(aliceID)
	h.text(aliceID, "one")
	c := h.mustClaim()
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "done"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	h.failSends(errors.New("connection reset"))
	h.text(aliceID, "two")
	if _, code := h.claim(); code != http.StatusNoContent {
		t.Fatalf("claim: %d", code)
	}
	if h.outboxStatus(jobs.OutboxBudgetHold) != "pending" {
		t.Fatalf("hold notice %s, want pending after a failed send", h.outboxStatus(jobs.OutboxBudgetHold))
	}
	h.failSends(nil)
	h.now = h.now.Add(jobs.OutboxBackoff(1))
	h.loop.deliver(context.Background(), 0)
	sent := h.sender.to(aliceID)
	if len(sent) != 2 || sent[1] != output.ServerText(output.TextBudgetHold).String() {
		t.Fatalf("sent %q, want the answer then the hold notice", sent)
	}
}

// TestRunLoop_RunFailedNoticeSurvivesFailedSend covers the expiry path.
func TestRunLoop_RunFailedNoticeSurvivesFailedSend(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	h.mustClaim()
	h.failSends(floodWait)
	h.now = h.now.Add(jobs.DefaultLease + time.Second)
	if _, code := h.claim(); code != http.StatusNoContent {
		t.Fatalf("claim: %d", code)
	}
	h.failSends(nil)
	h.now = h.now.Add(3 * time.Second)
	h.loop.deliver(context.Background(), 0)
	if len(h.sender.to(aliceID)) != 0 {
		t.Fatal("sent before the backoff")
	}
	h.now = h.now.Add(jobs.OutboxBackoff(1))
	h.loop.deliver(context.Background(), 0)
	sent := h.sender.to(aliceID)
	if len(sent) != 1 || sent[0] != output.ServerText(output.TextRunFailed).String() {
		t.Fatalf("sent %q", sent)
	}
}

// TestRunLoop_ReplyDroppedWithItsConversation: an answer still undelivered
// when the principal says /forget is not sent afterwards.
func TestRunLoop_ReplyDroppedWithItsConversation(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	h.failSends(floodWait)
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "an answer"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	h.failSends(nil)
	h.text(aliceID, CommandForget)
	h.now = h.now.Add(time.Hour)
	h.loop.deliver(context.Background(), 0)
	if sent := h.sender.to(aliceID); len(sent) != 0 {
		t.Fatalf("sent %q after /forget", sent)
	}
	if st := h.outboxStatus(jobs.OutboxReply); st != "dropped" {
		t.Fatalf("outbox %s, want dropped", st)
	}
}

// TestRunLoop_OutboxPermanentFailure: a refusal that would repeat (the bot
// was blocked) fails the row at once; it is not retried.
func TestRunLoop_OutboxPermanentFailure(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	h.failSends(&output.APIError{Method: "sendMessage", Status: 403, Code: 403})
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "an answer"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	if st := h.outboxStatus(jobs.OutboxReply); st != "failed" {
		t.Fatalf("outbox %s, want failed", st)
	}
}

// TestRunLoop_OutboxGivesUp: transient failures are retried up to
// OutboxMaxAttempts, then the row fails.
func TestRunLoop_OutboxGivesUp(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	h.failSends(errors.New("connection reset"))
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "an answer"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	for range jobs.OutboxMaxAttempts {
		h.now = h.now.Add(time.Hour)
		h.loop.deliver(context.Background(), 0)
	}
	var attempts int
	_ = h.convoHarness.store.DB.QueryRow(`SELECT attempts FROM pa_outbox WHERE principal = $1`, aliceID).Scan(&attempts)
	if st := h.outboxStatus(jobs.OutboxReply); st != "failed" || attempts != jobs.OutboxMaxAttempts {
		t.Fatalf("outbox %s after %d attempts, want failed after %d", st, attempts, jobs.OutboxMaxAttempts)
	}
}

// TestRunLoop_OutboxUnknownNotResent: a row claimed and never completed
// (the process died mid-send) is not sent again.
func TestRunLoop_OutboxUnknownNotResent(t *testing.T) {
	counts := outboxCounts{}
	h := newRunLoopHarness(t, withOutboxCounter(counts))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	h.failSends(floodWait)
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "an answer"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	h.failSends(nil)
	h.now = h.now.Add(time.Hour)
	// A deliverer claims the row and dies before it completes it.
	if res, err := h.store.ClaimPAOutbox(context.Background(), jobs.OutboxClaimRequest{
		Now: h.now, Lease: jobs.OutboxLease, Principal: aliceID, Limit: 1,
	}); err != nil || len(res.Items) != 1 {
		t.Fatalf("claim: %+v %v", res, err)
	}
	h.now = h.now.Add(jobs.OutboxLease)
	h.loop.deliver(context.Background(), 0)
	h.now = h.now.Add(time.Hour)
	h.loop.deliver(context.Background(), 0)
	if sent := h.sender.to(aliceID); len(sent) != 0 || h.outboxStatus(jobs.OutboxReply) != "unknown" || counts[OutboxOutcomeUnknown] != 1 {
		t.Fatalf("sent %q status %s counts %v", sent, h.outboxStatus(jobs.OutboxReply), counts)
	}
}

// TestRunLoop_OutboxUnreadableIsNotEmpty: an outbox read that fails is
// counted as an error, never as nothing due (I9).
func TestRunLoop_OutboxUnreadableIsNotEmpty(t *testing.T) {
	counts := outboxCounts{}
	h := newRunLoopHarness(t, withOutboxCounter(counts))
	if _, err := h.convoHarness.store.DB.Exec(`DROP TABLE pa_outbox`); err != nil {
		t.Fatal(err)
	}
	h.loop.deliver(context.Background(), 0)
	if counts[OutboxOutcomeClaimError] != 1 {
		t.Fatalf("counts %v, want one claim_error", counts)
	}
}

func TestPermanentSendError(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{&output.APIError{Status: 403}, true},
		{&output.APIError{Status: 400}, true},
		{&output.APIError{Status: 429, RetryAfter: 1}, false},
		{&output.APIError{Status: 502}, false},
		{output.ErrInvalidChat, true},
		{errors.New("dial tcp: timeout"), false},
		{context.DeadlineExceeded, false},
	} {
		if got := permanentSendError(tc.err); got != tc.want {
			t.Errorf("%v: %v, want %v", tc.err, got, tc.want)
		}
	}
}
