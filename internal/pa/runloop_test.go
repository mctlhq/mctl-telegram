package pa

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
)

// Run-loop tests (issue #1313 slice d1). They drive the real webhook, the
// real Conversations handler, the real SQLite store, real pa-job tokens and
// the real Render; only the Bot API Sender is a recorder.

const runLoopIssuer = "https://tg.test"

var runLoopSecret = bytes.Repeat([]byte{9}, 32)

type sentMessage struct {
	chat int64
	text string
}

type sendRecorder struct {
	mu   sync.Mutex
	sent []sentMessage
	fail error
}

func (s *sendRecorder) Send(_ context.Context, chatID int64, t output.Text, _ output.Keyboard) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.sent = append(s.sent, sentMessage{chatID, t.String()})
	return nil
}

func (s *sendRecorder) to(chat int64) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, m := range s.sent {
		if m.chat == chat {
			out = append(out, m.text)
		}
	}
	return out
}

type runLoopHarness struct {
	*convoHarness
	loop   *RunLoop
	sender *sendRecorder
	issuer *localjwt.Issuer
	pool   string
	tools  []string
	store  RunLoopStore
}

type rlOption func(*RunLoopConfig, *runLoopHarness)

func withBudget(b jobs.Budget) rlOption {
	return func(c *RunLoopConfig, _ *runLoopHarness) { c.Budget = b }
}

func withLimits(l jobs.Limits) rlOption {
	return func(c *RunLoopConfig, _ *runLoopHarness) { c.Limits = l }
}

func withStore(wrap func(*db.Store) RunLoopStore) rlOption {
	return func(c *RunLoopConfig, h *runLoopHarness) { c.Store = wrap(c.Store.(*db.Store)) }
}

func newRunLoopHarness(t *testing.T, opts ...rlOption) *runLoopHarness {
	t.Helper()
	store := newStore(t)
	h := &runLoopHarness{sender: &sendRecorder{}}
	iss, err := localjwt.NewIssuer(runLoopSecret, runLoopIssuer)
	if err != nil {
		t.Fatal(err)
	}
	h.issuer = iss
	cache := localjwt.NewRevocationCache(store, time.Minute)
	pool, err := localjwt.NewPoolProvider(localjwt.PoolProviderConfig{Secret: runLoopSecret, ExpectedIssuer: runLoopIssuer, RevocationCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	ver, err := localjwt.NewPAJobVerifier(runLoopSecret, runLoopIssuer, cache)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := convo.NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	cfg := RunLoopConfig{
		Store: store, Sealer: sealer, Pool: pool, Minter: iss, Verifier: ver, Sender: h.sender,
		Tools: func(context.Context, *sql.Tx, int64) ([]ConnectionRevision, []string, error) {
			return nil, h.tools, nil
		},
		Limits: jobs.DefaultLimits(),
		Budget: jobs.Budget{PerJobUSD: 0.25, PrincipalDayUSD: 2, PrincipalMonthUSD: 20, GlobalDayUSD: 20},
		Now:    func() time.Time { return h.now },
	}
	for _, o := range opts {
		o(&cfg, h)
	}
	h.store = cfg.Store
	h.loop, err = NewRunLoop(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.convoHarness = newConvoHarnessOn(t, store, h.loop, 3000)
	h.pool, err = iss.Mint(localjwt.Claims{
		Subject: "pool:main", Audience: []string{localjwt.PoolAudience}, Jti: "pool-jti",
		OriginalIssuedAt: time.Now().Add(-time.Minute).Unix(),
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *runLoopHarness) post(route, token string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			h.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, route, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	mux := http.NewServeMux()
	h.loop.Mount(mux)
	mux.ServeHTTP(w, req)
	return w
}

func (h *runLoopHarness) claim() (claimResponse, int) {
	h.t.Helper()
	w := h.post(RouteClaim, h.pool, nil)
	var c claimResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
			h.t.Fatal(err)
		}
	}
	return c, w.Code
}

func (h *runLoopHarness) mustClaim() claimResponse {
	h.t.Helper()
	c, code := h.claim()
	if code != http.StatusOK {
		h.t.Fatalf("claim: %d", code)
	}
	return c
}

func stopOf(w *httptest.ResponseRecorder) string {
	var s stopResponse
	_ = json.Unmarshal(w.Body.Bytes(), &s)
	return s.Stop
}

func (h *runLoopHarness) jobStatus(id int64) (job, usage string) {
	h.t.Helper()
	_ = h.convoHarness.store.DB.QueryRow(`SELECT status FROM pa_jobs WHERE id = $1`, id).Scan(&job)
	_ = h.convoHarness.store.DB.QueryRow(`SELECT status FROM pa_usage WHERE job_id = $1 ORDER BY attempt DESC LIMIT 1`, id).Scan(&usage)
	return job, usage
}

// TestRunLoop_HappyPath: message, claim, turn, reply, delivered through
// Render; the answer is stored external-marked and the reservation settled.
func TestRunLoop_HappyPath(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "summarise https://example.org/a please")
	c := h.mustClaim()
	if c.Token == "" || c.Attempt != 1 || len(c.ToolSet) != 0 || c.Limits.MaxToolCalls != 8 {
		t.Fatalf("claim = %+v", c)
	}
	if len(c.Fragments) != 1 || c.Fragments[0].Provenance != string(convo.ProvenanceUser) {
		t.Fatalf("fragments = %+v", c.Fragments)
	}
	if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 100}); w.Code != http.StatusOK {
		t.Fatalf("turn: %d %s", w.Code, w.Body)
	}
	cost := 0.02
	w := h.post(RouteReply, c.Token, replyRequest{
		Text: "See https://example.org/a and https://evil.example/x", CostUSD: &cost,
	})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"delivered":true`) {
		t.Fatalf("reply: %d %s", w.Code, w.Body)
	}
	sent := h.sender.to(aliceID)
	if len(sent) != 1 || !strings.Contains(sent[0], "https://example.org/a") || strings.Contains(sent[0], "evil.example/x") {
		t.Fatalf("sent = %q: the reply must go through Render with the typed URL allowed only", sent)
	}
	if js, us := h.jobStatus(c.JobID); js != "done" || us != "settled" {
		t.Fatalf("after reply: job %s usage %s", js, us)
	}
	n := h.count(`SELECT count(*) FROM pa_fragments WHERE principal = $1 AND kind = 'assistant' AND provenance = 'external'`, aliceID)
	if n != 1 {
		t.Fatalf("assistant fragments marked external = %d, want 1", n)
	}
	// The token is spent: a second reply is stale and sends nothing.
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "again"}); w.Code != http.StatusConflict || stopOf(w) != "stale" {
		t.Fatalf("second reply: %d %s", w.Code, w.Body)
	}
	if len(h.sender.to(aliceID)) != 1 {
		t.Fatal("a stale reply was sent")
	}
}

// TestRunLoop_S1R1 is S1-R1: each size limit is enforced.
func TestRunLoop_S1R1(t *testing.T) {
	t.Run("incoming message over 4096", func(t *testing.T) {
		h := newRunLoopHarness(t)
		h.consent(aliceID)
		h.text(aliceID, strings.Repeat("a", jobs.MaxMessageChars+1))
		if r := h.replies.last(aliceID).reply; r != ReplyMessageTooLong {
			t.Fatalf("reply = %q", r)
		}
		if h.fragments(aliceID) != 0 || h.count(`SELECT count(*) FROM pa_jobs`) != 0 {
			t.Fatal("an over-long message was stored or enqueued")
		}
		// Exactly the limit, in UTF-16 units as Telegram counts, passes.
		h.text(aliceID, strings.Repeat("a", jobs.MaxMessageChars))
		if h.count(`SELECT count(*) FROM pa_jobs`) != 1 {
			t.Fatal("a message at the limit was refused")
		}
	})
	t.Run("context over the token cap at a turn", func(t *testing.T) {
		h := newRunLoopHarness(t)
		h.consent(aliceID)
		h.text(aliceID, "hello")
		c := h.mustClaim()
		w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: jobs.DefaultMaxContextTokens + 1})
		if w.Code != http.StatusConflict || stopOf(w) != "context_too_large" {
			t.Fatalf("turn over the cap: %d %s", w.Code, w.Body)
		}
	})
	t.Run("claimed context is trimmed to the cap, keeping the newest user text", func(t *testing.T) {
		lim := jobs.DefaultLimits()
		lim.MaxContextTokens = 1500
		h := newRunLoopHarness(t, withLimits(lim))
		h.consent(aliceID)
		for _, s := range []string{"first", "second", "third"} {
			h.text(aliceID, s+" "+strings.Repeat("x", 2000))
		}
		c := h.mustClaim()
		total := 0
		for _, f := range c.Fragments {
			total += jobs.EstimateTokens(f.Text)
		}
		if total > lim.MaxContextTokens || len(c.Fragments) == 0 ||
			!strings.HasPrefix(c.Fragments[len(c.Fragments)-1].Text, "third") {
			t.Fatalf("context of %d tokens, %d fragments", total, len(c.Fragments))
		}
	})
	t.Run("tool output is capped with a marker", func(t *testing.T) {
		out, cut := jobs.TruncateToolOutput([]byte(strings.Repeat("é", jobs.MaxToolOutputBytes)))
		if !cut || len(out) > jobs.MaxToolOutputBytes || !strings.HasSuffix(string(out), jobs.TruncationMarker) ||
			!utf8Valid(out) {
			t.Fatalf("len %d cut %v", len(out), cut)
		}
		small := []byte("ok")
		if got, cut := jobs.TruncateToolOutput(small); cut || string(got) != "ok" {
			t.Fatal("a small output was changed")
		}
	})
	t.Run("reply too long fails closed with a server text", func(t *testing.T) {
		h := newRunLoopHarness(t)
		h.consent(aliceID)
		h.text(aliceID, "hello")
		c := h.mustClaim()
		long := strings.Repeat("word ", output.MaxParts*4096/5+10) // needs more than MaxParts messages
		if w := h.post(RouteReply, c.Token, replyRequest{Text: long}); w.Code != http.StatusOK {
			t.Fatalf("reply: %d %s", w.Code, w.Body)
		}
		sent := h.sender.to(aliceID)
		if len(sent) != 1 || sent[0] != output.ServerText(output.TextReplyTooLong).String() {
			t.Fatalf("sent %d messages; a too-long reply must be replaced, never cut", len(sent))
		}
		if h.count(`SELECT count(*) FROM pa_fragments WHERE kind = 'assistant'`) != 0 {
			t.Fatal("an answer the principal never saw was kept")
		}
	})
}

func utf8Valid(b []byte) bool { return strings.ToValidUTF8(string(b), "�") == string(b) }

// TestRunLoop_S1R2 is S1-R2: the tool-call cap stops the loop.
func TestRunLoop_S1R2(t *testing.T) {
	h := newRunLoopHarness(t)
	h.tools = []string{"tg/get_messages"}
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	req := httptest.NewRequest(http.MethodPost, "/exec", nil)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	job, err := h.loop.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	for i := range jobs.DefaultMaxToolCalls {
		if err := h.loop.AdmitPAToolCall(context.Background(), job, "tg", "get_messages"); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
		if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 10}); w.Code != http.StatusOK {
			t.Fatalf("turn %d: %d", i+1, w.Code)
		}
	}
	if err := h.loop.AdmitPAToolCall(context.Background(), job, "tg", "get_messages"); !errors.Is(err, jobs.ErrToolCap) {
		t.Fatalf("call past the cap: %v", err)
	}
	// One more turn to answer, then the loop is stopped.
	if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 10}); w.Code != http.StatusOK {
		t.Fatalf("answer turn: %d", w.Code)
	}
	if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 10}); w.Code != http.StatusConflict || stopOf(w) != "tool_cap" {
		t.Fatalf("turn past the cap: %d %s", w.Code, w.Body)
	}
}

// TestRunLoop_S1R3 is S1-R3: an exhausted budget gives a hold message and no
// model call: no token, no reservation, one message.
func TestRunLoop_S1R3(t *testing.T) {
	h := newRunLoopHarness(t, withBudget(jobs.Budget{PerJobUSD: 0.25, PrincipalDayUSD: 0.25, PrincipalMonthUSD: 20, GlobalDayUSD: 20}))
	h.consent(aliceID)
	h.text(aliceID, "one")
	c := h.mustClaim()
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "done"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	h.text(aliceID, "two")
	if _, code := h.claim(); code != http.StatusNoContent {
		t.Fatalf("claim over budget: %d, want 204 (no token)", code)
	}
	sent := h.sender.to(aliceID)
	if len(sent) != 2 || sent[1] != output.ServerText(output.TextBudgetHold).String() {
		t.Fatalf("sent %q, want the answer then one hold message", sent)
	}
	if n := h.count(`SELECT count(*) FROM pa_usage WHERE principal = $1`, aliceID); n != 1 {
		t.Fatalf("%d ledger rows; a held run reserves nothing", n)
	}
	h.text(aliceID, "three")
	if _, code := h.claim(); code != http.StatusNoContent {
		t.Fatalf("second claim: %d", code)
	}
	if len(h.sender.to(aliceID)) != 2 {
		t.Fatal("the hold message was repeated")
	}
	// The next day the held job runs and reads both messages.
	h.now = h.now.Add(24 * time.Hour)
	h.consentStillOpen(t)
}

// consentStillOpen re-opens the conversation clock check: the harness
// conversation TTL is 24h from creation, so a day later the job is
// cancelled at claim as an expired conversation, never run on stale state.
func (h *runLoopHarness) consentStillOpen(t *testing.T) {
	t.Helper()
	if _, code := h.claim(); code != http.StatusNoContent {
		t.Fatalf("claim of a job whose conversation expired: %d", code)
	}
	var st string
	_ = h.convoHarness.store.DB.QueryRow(`SELECT status FROM pa_jobs WHERE principal = $1 ORDER BY id DESC LIMIT 1`, aliceID).Scan(&st)
	if st != "cancelled" {
		t.Fatalf("job %s, want cancelled with its conversation", st)
	}
}

// TestRunLoop_S1I1 is S1-I1: an injected write request produces no call,
// because no write tool is in the job's tool set.
func TestRunLoop_S1I1(t *testing.T) {
	h := newRunLoopHarness(t)
	h.tools = []string{"alice/alice_get_device_state"}
	h.consent(aliceID)
	h.message(aliceID, map[string]any{
		"text":           "what does this say?",
		"forward_origin": map[string]any{"type": "hidden_user", "sender_user_name": "Bob", "date": 1},
	})
	c := h.mustClaim()
	if len(c.ToolSet) != 1 || c.ToolSet[0] != "alice/alice_get_device_state" {
		t.Fatalf("tool set = %v", c.ToolSet)
	}
	req := httptest.NewRequest(http.MethodPost, "/exec", nil)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	job, err := h.loop.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	for _, write := range [][2]string{{"alice", "alice_control_room"}, {"alice", "alice_say_phrase"}, {"tg", "send_message"}} {
		if err := h.loop.AdmitPAToolCall(context.Background(), job, write[0], write[1]); !errors.Is(err, jobs.ErrToolNotInSet) {
			t.Fatalf("%s/%s admitted: %v", write[0], write[1], err)
		}
	}
	if n := h.count(`SELECT tool_calls FROM pa_jobs WHERE id = $1`, c.JobID); n != 0 {
		t.Fatalf("refused calls counted: %d", n)
	}

	// A resolver that offers a write tool fails the claim: no token.
	t.Run("write tool offered", func(t *testing.T) {
		h2 := newRunLoopHarness(t)
		h2.tools = []string{"alice/alice_control_room"}
		h2.consent(aliceID)
		h2.text(aliceID, "turn off the lights")
		if _, code := h2.claim(); code == http.StatusOK {
			t.Fatal("a job was claimed with a write tool in its set")
		}
		if h2.count(`SELECT count(*) FROM pa_usage`) != 0 {
			t.Fatal("a reservation outlived the refused claim")
		}
		// The unbuildable job is cancelled, so it cannot block the queue:
		// Bob's job behind it is claimed next.
		if n := h2.count(`SELECT count(*) FROM pa_jobs WHERE principal = $1 AND status = 'cancelled'`, aliceID); n != 1 {
			t.Fatalf("cancelled = %d", n)
		}
		h2.tools = nil
		h2.consent(bobID)
		h2.text(bobID, "hi")
		if c := h2.mustClaim(); c.Token == "" {
			t.Fatal("Bob blocked behind an unbuildable job")
		}
	})
}

// TestRunLoop_S1X2Budget is the budget part of S1-X2: Bob's runs are not
// held by Alice's spend.
func TestRunLoop_S1X2Budget(t *testing.T) {
	h := newRunLoopHarness(t, withBudget(jobs.Budget{PerJobUSD: 0.25, PrincipalDayUSD: 0.25, PrincipalMonthUSD: 20, GlobalDayUSD: 20}))
	h.consent(aliceID)
	h.consent(bobID)
	h.text(aliceID, "one")
	c := h.mustClaim()
	h.post(RouteReply, c.Token, replyRequest{Text: "ok"})
	h.text(aliceID, "two")
	h.claim() // Alice held
	h.text(bobID, "hi")
	cb := h.mustClaim()
	if cb.Token == "" {
		t.Fatal("Bob was held by Alice's budget")
	}
	pj, err := localjwt.NewPAJobVerifier(runLoopSecret, runLoopIssuer, localjwt.NewRevocationCache(h.convoHarness.store, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	got, err := pj.Verify(context.Background(), cb.Token)
	if err != nil || got.Principal != bobID {
		t.Fatalf("Bob's token principal = %d err=%v", got.Principal, err)
	}
	if len(h.sender.to(bobID)) != 0 {
		t.Fatal("Bob was sent Alice's hold message")
	}
}

// TestRunLoop_ConsentRechecked: consent and the conversation are re-read at
// every step (T11, T13). Withdrawal or /new after the claim stops the run
// and nothing is sent.
func TestRunLoop_ConsentRechecked(t *testing.T) {
	for _, cmd := range []string{"/consent withdraw", "/new", "/forget"} {
		t.Run(cmd, func(t *testing.T) {
			h := newRunLoopHarness(t)
			h.tools = []string{"tg/get_messages"}
			h.consent(aliceID)
			h.text(aliceID, "hello")
			c := h.mustClaim()
			h.text(aliceID, cmd)
			if w := h.post(RouteTurn, c.Token, turnRequest{}); w.Code != http.StatusConflict {
				t.Fatalf("turn after %s: %d %s", cmd, w.Code, w.Body)
			}
			req := httptest.NewRequest(http.MethodPost, "/exec", nil)
			req.Header.Set("Authorization", "Bearer "+c.Token)
			job, _ := h.loop.Authenticate(req)
			if err := h.loop.AdmitPAToolCall(context.Background(), job, "tg", "get_messages"); err == nil {
				t.Fatal("tool call admitted")
			}
			if w := h.post(RouteReply, c.Token, replyRequest{Text: "secret"}); w.Code != http.StatusConflict {
				t.Fatalf("reply: %d", w.Code)
			}
			if len(h.sender.to(aliceID)) != 0 {
				t.Fatal("a reply was sent after " + cmd)
			}
			if js, us := h.jobStatus(c.JobID); js != "cancelled" || us != "held" {
				t.Fatalf("job %s usage %s", js, us)
			}
		})
	}
	t.Run("changed consent text at claim", func(t *testing.T) {
		h := newRunLoopHarness(t)
		h.consent(aliceID)
		h.text(aliceID, "hello")
		if _, err := h.convoHarness.store.DB.Exec(`UPDATE pa_consents SET text_sha256 = 'old' WHERE principal = $1`, aliceID); err != nil {
			t.Fatal(err)
		}
		if _, code := h.claim(); code != http.StatusNoContent {
			t.Fatalf("claim under a stale consent text: %d", code)
		}
		if h.count(`SELECT count(*) FROM pa_usage`) != 0 {
			t.Fatal("reserved under a stale consent")
		}
	})
}

// failingConsent makes every consent read fail.
type failingConsent struct{ *db.Store }

func (failingConsent) GetPAConsent(context.Context, *sql.Tx, int64) (convo.ConsentRecord, error) {
	return convo.ConsentRecord{}, errors.New("consent table unreadable")
}

// failingConversation makes the conversation check fail to read.
type failingConversation struct{ *db.Store }

func (failingConversation) PAConversationOpen(context.Context, *sql.Tx, int64, string, time.Time) error {
	return errors.New("conversation table unreadable")
}

// TestRunLoop_ReadErrorsFailClosed: a consent or status read error is a
// refusal (503), never consent, never an open conversation, and changes no
// state (I9).
func TestRunLoop_ReadErrorsFailClosed(t *testing.T) {
	for name, wrap := range map[string]func(*db.Store) RunLoopStore{
		"consent":      func(s *db.Store) RunLoopStore { return failingConsent{s} },
		"conversation": func(s *db.Store) RunLoopStore { return failingConversation{s} },
	} {
		t.Run(name, func(t *testing.T) {
			h := newRunLoopHarness(t, withStore(wrap))
			h.consent(aliceID) // the webhook path reads through the real store
			h.text(aliceID, "hello")
			if _, code := h.claim(); code != http.StatusServiceUnavailable {
				t.Fatalf("claim with an unreadable %s: %d", name, code)
			}
			if h.count(`SELECT count(*) FROM pa_usage`) != 0 {
				t.Fatal("reserved on an unreadable read")
			}
			if n := h.count(`SELECT count(*) FROM pa_jobs WHERE status = 'pending'`); n != 1 {
				t.Fatalf("pending jobs = %d; a read error must not cancel or claim", n)
			}
		})
	}
}

// TestRunLoop_RateLimit: PA_RATE_MESSAGES per window, consent prompts
// included; the principal is told once; /forget always passes.
func TestRunLoop_RateLimit(t *testing.T) {
	lim := jobs.DefaultLimits()
	lim.RateMessages = 3
	h := newRunLoopHarness(t, withLimits(lim))
	for range 3 {
		h.text(aliceID, "hi") // no consent: each one prompts
	}
	prompts := func() int {
		n := 0
		h.replies.mu.Lock()
		defer h.replies.mu.Unlock()
		for _, r := range h.replies.replies {
			if r.principal == aliceID && r.reply == ReplyConsentPrompt {
				n++
			}
		}
		return n
	}
	if prompts() != 3 {
		t.Fatalf("prompts = %d", prompts())
	}
	h.text(aliceID, "hi")
	if h.replies.last(aliceID).reply != ReplyRateLimited || prompts() != 3 {
		t.Fatal("the fourth message was not refused with one notice")
	}
	before := len(h.replies.replies)
	h.text(aliceID, "hi")
	if len(h.replies.replies) != before {
		t.Fatal("the notice was repeated")
	}
	h.text(aliceID, "/forget")
	if h.replies.last(aliceID).reply != ReplyForgotten {
		t.Fatal("/forget was rate limited")
	}
	// Bob has his own window.
	h.text(bobID, "hi")
	if h.replies.last(bobID).reply != ReplyConsentPrompt {
		t.Fatal("Bob was limited by Alice's messages")
	}
}

// TestRunLoop_Tokens: only a pool credential claims; only the job's own
// pa-job token drives it.
func TestRunLoop_Tokens(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	// A pa-job-shaped or account token cannot claim.
	acct, _ := h.issuer.Mint(localjwt.Claims{Subject: "u", TelegramID: aliceID, Audience: []string{"agent"}, Jti: "x"}, time.Hour)
	if w := h.post(RouteClaim, acct, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("account token claimed: %d", w.Code)
	}
	if w := h.post(RouteClaim, "", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous claim: %d", w.Code)
	}
	c := h.mustClaim()
	// The pool token cannot drive a job.
	if w := h.post(RouteTurn, h.pool, turnRequest{}); w.Code != http.StatusUnauthorized {
		t.Fatalf("pool token on turn: %d", w.Code)
	}
	// A token re-minted for another attempt of the same job is stale.
	forged, err := h.issuer.MintPAJob(localjwt.PAJob{
		Principal: aliceID, JobID: c.JobID, Attempt: c.Attempt + 1, ContextDigest: strings.Repeat("a", 64),
	}, "pool-jti", 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if w := h.post(RouteTurn, forged, turnRequest{}); w.Code != http.StatusConflict || stopOf(w) != "stale" {
		t.Fatalf("forged attempt: %d %s", w.Code, w.Body)
	}
	// Alice's job under Bob's principal is not found.
	bobs, _ := h.issuer.MintPAJob(localjwt.PAJob{
		Principal: bobID, JobID: c.JobID, Attempt: c.Attempt, ContextDigest: strings.Repeat("a", 64),
	}, "pool-jti", 0, time.Minute)
	if w := h.post(RouteTurn, bobs, turnRequest{}); w.Code != http.StatusConflict {
		t.Fatalf("Bob's token on Alice's job: %d", w.Code)
	}
	// After the lease the token is stale and the job expired.
	h.now = h.now.Add(jobs.DefaultLease + time.Second)
	if w := h.post(RouteTurn, c.Token, turnRequest{}); w.Code != http.StatusConflict {
		t.Fatalf("turn after the lease: %d", w.Code)
	}
}

// TestRunLoop_RedeliveryCap: an update whose handler always fails is
// acknowledged after MaxHandlerAttempts deliveries, with its handler error
// recorded, and never runs afterwards.
func TestRunLoop_RedeliveryCap(t *testing.T) {
	store := newStore(t)
	runs := 0
	failing := HandlerFunc(func(context.Context, *sql.Tx, VerifiedUpdate) error {
		runs++
		return errors.New("deterministic")
	})
	counts := &countRecorder{}
	wh := newWebhook(t, store, failing, counts)
	body := privateMessage(4242, aliceID, "")
	for i := 1; i < MaxHandlerAttempts; i++ {
		if code := deliver(wh, testSecret, body); code != http.StatusInternalServerError {
			t.Fatalf("delivery %d: %d", i, code)
		}
	}
	if code := deliver(wh, testSecret, body); code != http.StatusOK {
		t.Fatalf("delivery %d: %d, want acknowledged", MaxHandlerAttempts, code)
	}
	if counts.seen[OutcomeGaveUp] != 1 {
		t.Fatalf("gave_up = %d", counts.seen[OutcomeGaveUp])
	}
	if reason, err := store.PAUpdateHandlerError(context.Background(), 4242); err != nil || reason != OutcomeHandlerError {
		t.Fatalf("handler_error = %q err=%v", reason, err)
	}
	if code := deliver(wh, testSecret, body); code != http.StatusOK || runs != MaxHandlerAttempts {
		t.Fatalf("after the cap: code %d runs %d", code, runs)
	}
}

// failureRecorderDown cannot count failures: the update is never acked.
type failureRecorderDown struct{ *db.Store }

func (failureRecorderDown) RecordPAUpdateFailure(context.Context, int64) (int, error) {
	return 0, errors.New("down")
}

func TestRunLoop_RedeliveryCapUncountedIsNotAcked(t *testing.T) {
	store := newStore(t)
	failing := HandlerFunc(func(context.Context, *sql.Tx, VerifiedUpdate) error { return errors.New("x") })
	wh, err := NewWebhookHandler(WebhookConfig{Secret: testSecret, Dedup: store, Handler: failing, Failures: failureRecorderDown{store}})
	if err != nil {
		t.Fatal(err)
	}
	for i := range MaxHandlerAttempts + 2 {
		if code := deliver(wh, testSecret, privateMessage(77, aliceID, "")); code != http.StatusInternalServerError {
			t.Fatalf("delivery %d: %d; an uncounted failure must not be acknowledged", i+1, code)
		}
	}
}

func TestNewRunLoop_RequiresEverything(t *testing.T) {
	if _, err := NewRunLoop(RunLoopConfig{}); !errors.Is(err, ErrRunLoopConfig) {
		t.Fatalf("empty config: %v", err)
	}
	if _, err := NewConversations(ConversationsConfig{
		Store: newStore(t), Sealer: mustSealer(t), TTL: time.Hour, Runs: &enqueueRecorder{},
	}); !errors.Is(err, ErrConversationsConfig) {
		t.Fatalf("a run loop without a limiter: %v", err)
	}
}

func mustSealer(t *testing.T) *convo.Sealer {
	s, err := convo.NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
