package pa

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// Run-loop tests (issue #1313 slice d1). They drive the real webhook, the
// real Conversations handler, the real SQLite store, real pa-job tokens and
// the real Render; only the Bot API Sender is a recorder.

const runLoopIssuer = "https://tg.test"

var runLoopSecret = bytes.Repeat([]byte{9}, 32)

type sentMessage struct {
	chat int64
	text string
	// kb is the keyboard a completed send carried.
	kb output.Keyboard
}

type sendRecorder struct {
	mu sync.Mutex
	// sent has one entry per completed send: the parts it sent, joined.
	sent []sentMessage
	// parts has one entry per delivered part, completed send or not.
	parts []sentMessage
	// fail fails every part, or only part failAt (1-based) when set.
	fail   error
	failAt int
	// before runs outside the lock before each part (1-based); it can
	// block, cancel or fail the part.
	before func(ctx context.Context, chat int64, part int) error
	// answered has one entry per callback answer that succeeded;
	// answerFail fails every answer.
	answered   []string
	answerFail error
}

func (s *sendRecorder) AnswerCallback(_ context.Context, id string, notice safetext.Template) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.answerFail != nil {
		return s.answerFail
	}
	if notice != (safetext.Template{}) {
		return errors.New("sendRecorder: a callback answer with a notice")
	}
	s.answered = append(s.answered, id)
	return nil
}

func (s *sendRecorder) answers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.answered...)
}

func (s *sendRecorder) SendFrom(ctx context.Context, chatID int64, t safetext.Text, kb output.Keyboard, from int, sent func(int) error) error {
	var b strings.Builder
	for i := from; i < t.Parts(); i++ {
		s.mu.Lock()
		before := s.before
		s.mu.Unlock()
		if before != nil {
			if err := before(ctx, chatID, i+1); err != nil {
				return err
			}
		}
		s.mu.Lock()
		err := s.fail
		if s.failAt > 0 && s.failAt != i+1 {
			err = nil
		}
		if err == nil {
			s.parts = append(s.parts, sentMessage{chat: chatID, text: t.Part(i)})
			b.WriteString(t.Part(i))
		}
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if sent != nil {
			if err := sent(i + 1); err != nil {
				return err
			}
		}
	}
	s.mu.Lock()
	s.sent = append(s.sent, sentMessage{chat: chatID, text: b.String(), kb: kb})
	s.mu.Unlock()
	return nil
}

// sentTo is sender.to once the deliveries the request paths started are
// done (the worker end-to-end tests go through a real HTTP server).
func (h *runLoopHarness) sentTo(chat int64) []string {
	h.loop.WaitDeliveries()
	return h.sender.to(chat)
}

func (s *sendRecorder) partsTo(chat int64) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, m := range s.parts {
		if m.chat == chat {
			out = append(out, m.text)
		}
	}
	return out
}

// messagesTo returns the completed sends to chat, keyboards included.
func (s *sendRecorder) messagesTo(chat int64) []sentMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []sentMessage
	for _, m := range s.sent {
		if m.chat == chat {
			out = append(out, m)
		}
	}
	return out
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
	cache  *localjwt.RevocationCache
	pool   string
	tools  []string
	conns  map[int64][]ConnectionRevision
	store  RunLoopStore
	// cfg is the configuration the loop was built from.
	cfg RunLoopConfig
}

type rlOption func(*RunLoopConfig, *runLoopHarness)

func withBudget(b jobs.Budget) rlOption {
	return func(c *RunLoopConfig, _ *runLoopHarness) { c.Budget = b }
}

func withLimits(l jobs.Limits) rlOption {
	return func(c *RunLoopConfig, _ *runLoopHarness) { c.Limits = l }
}

func withMinter(m JobMinter) rlOption {
	return func(c *RunLoopConfig, _ *runLoopHarness) { c.Minter = m }
}

func withStore(wrap func(*db.Store) RunLoopStore) rlOption {
	return func(c *RunLoopConfig, h *runLoopHarness) { c.Store = wrap(c.Store.(*db.Store)) }
}

func newRunLoopHarness(t *testing.T, opts ...rlOption) *runLoopHarness {
	t.Helper()
	return newRunLoopHarnessOn(t, newStore(t), opts...)
}

// newRunLoopHarnessOn is newRunLoopHarness on a given store (Postgres
// variants pass newPostgresStore).
func newRunLoopHarnessOn(t *testing.T, store *db.Store, opts ...rlOption) *runLoopHarness {
	t.Helper()
	h := &runLoopHarness{sender: &sendRecorder{}}
	iss, err := localjwt.NewIssuer(runLoopSecret, runLoopIssuer)
	if err != nil {
		t.Fatal(err)
	}
	h.issuer = iss
	cache := localjwt.NewRevocationCache(store, time.Minute)
	h.cache = cache
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
		Tools: func(_ context.Context, _ *sql.Tx, p int64) ([]ConnectionRevision, []string, error) {
			return h.conns[p], h.tools, nil
		},
		Limits:  jobs.DefaultLimits(),
		Budget:  jobs.Budget{PerJobUSD: 0.25, PrincipalDayUSD: 2, PrincipalMonthUSD: 20, GlobalDayUSD: 20, MinTurnUSD: 0.005},
		Allowed: newTestAllowlist(),
		Now:     func() time.Time { return h.now },
	}
	for _, o := range opts {
		o(&cfg, h)
	}
	h.store, h.cfg = cfg.Store, cfg
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
	// The request paths deliver after their response; the tests read the
	// outbox once that delivery is done.
	h.loop.WaitDeliveries()
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
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"queued":true`) {
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
		long := strings.Repeat("word ", safetext.MaxParts*4096/5+10) // needs more than MaxParts messages
		if w := h.post(RouteReply, c.Token, replyRequest{Text: long}); w.Code != http.StatusOK {
			t.Fatalf("reply: %d %s", w.Code, w.Body)
		}
		sent := h.sender.to(aliceID)
		if len(sent) != 1 || sent[0] != safetext.ServerText(safetext.TextReplyTooLong).String() {
			t.Fatalf("sent %d messages; a too-long reply must be replaced, never cut", len(sent))
		}
		if h.count(`SELECT count(*) FROM pa_fragments WHERE kind = 'assistant'`) != 0 {
			t.Fatal("an answer the principal never saw was kept")
		}
	})
}

// TestRunLoop_S1R1NonASCIIReply: the reply body cap is never what refuses
// an answer. Escaped Cyrillic that Render would accept is delivered; one
// past the body cap gets the same server text as ErrTooLong.
func TestRunLoop_S1R1NonASCIIReply(t *testing.T) {
	escaped := func(text string, cost *float64) []byte {
		var b strings.Builder
		b.WriteString(`{"text":"`)
		for _, r := range text {
			fmt.Fprintf(&b, `\u%04x`, r)
		}
		b.WriteString(`"`)
		if cost != nil {
			fmt.Fprintf(&b, `,"cost_usd":%v`, *cost)
		}
		b.WriteString(`}`)
		return []byte(b.String())
	}
	raw := func(h *runLoopHarness, tok string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, RouteReply, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		mux := http.NewServeMux()
		h.loop.Mount(mux)
		mux.ServeHTTP(w, req)
		h.loop.WaitDeliveries()
		return w
	}
	t.Run("fits", func(t *testing.T) {
		h := newRunLoopHarness(t)
		h.consent(aliceID)
		h.text(aliceID, "hello")
		c := h.mustClaim()
		text := strings.Repeat("я", 7*4096) // 7 parts, > 64 KiB escaped
		if w := raw(h, c.Token, escaped(text, nil)); w.Code != http.StatusOK {
			t.Fatalf("reply: %d %s", w.Code, w.Body)
		}
		sent := h.sender.to(aliceID)
		if len(sent) != 1 || sent[0] == safetext.ServerText(safetext.TextReplyTooLong).String() {
			t.Fatal("an answer Render accepts was refused")
		}
	})
	t.Run("over the body cap", func(t *testing.T) {
		h := newRunLoopHarness(t)
		h.consent(aliceID)
		h.text(aliceID, "hello")
		c := h.mustClaim()
		text := strings.Repeat("я", maxReplyBody/6+100)
		if w := raw(h, c.Token, escaped(text, nil)); w.Code != http.StatusOK {
			t.Fatalf("reply: %d %s", w.Code, w.Body)
		}
		sent := h.sender.to(aliceID)
		if len(sent) != 1 || sent[0] != safetext.ServerText(safetext.TextReplyTooLong).String() {
			t.Fatalf("sent %d; an over-long body must get the server text", len(sent))
		}
		if js, us := h.jobStatus(c.JobID); js != "done" || us != "settled" {
			t.Fatalf("job %s usage %s, want finished", js, us)
		}
	})
}

// TestRunLoop_ReportedCostCapped: one absurd cost_usd cannot fill the
// global day window shared with the managed runtime: it settles at
// jobs.SettleFactor x the reservation, with the report kept.
func TestRunLoop_ReportedCostCapped(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	if c.Limits.MaxJobCostUSD != 0.25 {
		t.Fatalf("claim limits carry max_job_cost_usd %v, want the reservation", c.Limits.MaxJobCostUSD)
	}
	huge := 1e300
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "ok", CostUSD: &huge}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	var cost, reported float64
	if err := h.convoHarness.store.DB.QueryRow(`SELECT cost_usd, reported_cost_usd FROM pa_usage WHERE job_id = $1`, c.JobID).Scan(&cost, &reported); err != nil {
		t.Fatal(err)
	}
	if cost != 1.0 || reported != huge {
		t.Fatalf("settled at %v (reported %v), want 4x the reservation with the report kept", cost, reported)
	}
}

// TestRunLoop_TurnFloor: a run that reports $0 settles the server-side
// floor for the turns it took through /turn (owner decision 2026-11-19).
// Mutation: drop MinTurnUSD from the reply's FinishRequest.
func TestRunLoop_TurnFloor(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	for i := range 3 {
		if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 10}); w.Code != http.StatusOK {
			t.Fatalf("turn %d: %d", i+1, w.Code)
		}
	}
	zero := 0.0
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "ok", CostUSD: &zero}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	var cost, reported float64
	if err := h.convoHarness.store.DB.QueryRow(`SELECT cost_usd, reported_cost_usd FROM pa_usage WHERE job_id = $1`, c.JobID).Scan(&cost, &reported); err != nil {
		t.Fatal(err)
	}
	if math.Abs(cost-0.015) > 1e-9 || reported != 0 {
		t.Fatalf("settled %v (reported %v), want 3 turns x 0.005 with the report kept", cost, reported)
	}
}

// TestRunLoop_TurnFloorFromBudget: the reply settles with the configured
// floor, not the default.
// Mutation: pass jobs.DefaultMinTurnUSD instead of l.budget.MinTurnUSD.
func TestRunLoop_TurnFloorFromBudget(t *testing.T) {
	h := newRunLoopHarness(t, withBudget(jobs.Budget{PerJobUSD: 0.25, PrincipalDayUSD: 2, PrincipalMonthUSD: 20, GlobalDayUSD: 20, MinTurnUSD: 0.02}))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	for i := range 3 {
		if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 10}); w.Code != http.StatusOK {
			t.Fatalf("turn %d: %d", i+1, w.Code)
		}
	}
	zero := 0.0
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "ok", CostUSD: &zero}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	var cost float64
	if err := h.convoHarness.store.DB.QueryRow(`SELECT cost_usd FROM pa_usage WHERE job_id = $1`, c.JobID).Scan(&cost); err != nil {
		t.Fatal(err)
	}
	if math.Abs(cost-0.06) > 1e-9 {
		t.Fatalf("settled %v, want 3 turns x the configured 0.02", cost)
	}
}

// TestRunLoop_ClaimNotAfter: MANAGED_CLAIM_NOT_AFTER (Budget.ClaimNotAfter)
// ends PA claims with the refusal a managed claim gives past it: nothing
// handed out (204), nothing reserved, counted or backed off, nobody told.
func TestRunLoop_ClaimNotAfter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset time.Duration
		want   int
	}{
		{"before", time.Second, http.StatusOK},
		{"at", 0, http.StatusNoContent},
		{"after", -time.Second, http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRunLoopHarness(t)
			h.consent(aliceID)
			h.text(aliceID, "hello")
			sent := len(h.sender.to(aliceID))
			// Relative to the harness clock, which exists only now.
			h.loop.budget.ClaimNotAfter = h.now.Add(tc.offset)
			if _, code := h.claim(); code != tc.want {
				t.Fatalf("claim: %d, want %d", code, tc.want)
			}
			if tc.want != http.StatusNoContent {
				return
			}
			if h.count(`SELECT count(*) FROM pa_usage`) != 0 ||
				h.count(`SELECT count(*) FROM pa_jobs WHERE status = 'pending' AND claim_failures = 0 AND retry_at_ms = 0`) != 1 ||
				len(h.sender.to(aliceID)) != sent {
				t.Fatal("a claim past the cutoff reserved, counted, backed off or sent something")
			}
		})
	}
}

// aliceFragmentsDown fails every fragment load of Alice's with a store
// fault, and no one else's.
type aliceFragmentsDown struct{ *db.Store }

func (a aliceFragmentsDown) LoadPAFragments(ctx context.Context, p int64, c string, now time.Time) ([]convo.SealedFragment, error) {
	if p == aliceID {
		return nil, storeFault
	}
	return a.Store.LoadPAFragments(ctx, p, c, now)
}

// TestRunLoop_RecurringFaultDoesNotHoldTheQueue: Alice's fragment load
// keeps failing as a store fault. Each attempt counts nothing, but moves
// her job one backoff step out, so Bob's run is claimed meanwhile.
// Mutation: ReleaseRetry without a retry_at.
func TestRunLoop_RecurringFaultDoesNotHoldTheQueue(t *testing.T) {
	h := newRunLoopHarness(t, withStore(func(s *db.Store) RunLoopStore { return aliceFragmentsDown{s} }))
	h.consent(aliceID)
	h.consent(bobID)
	h.text(aliceID, "hello")
	h.text(bobID, "hello")
	if _, code := h.claim(); code != http.StatusServiceUnavailable {
		t.Fatalf("Alice's claim: %d", code)
	}
	c := h.mustClaim()
	var principal int64
	if err := h.convoHarness.store.DB.QueryRow(`SELECT principal FROM pa_jobs WHERE id = $1`, c.JobID).Scan(&principal); err != nil {
		t.Fatal(err)
	}
	if principal != bobID {
		t.Fatalf("claimed principal %d, want Bob behind Alice's fault", principal)
	}
	if h.count(`SELECT count(*) FROM pa_jobs WHERE principal = $1 AND status = 'pending' AND claim_failures = 0`, aliceID) != 1 {
		t.Fatal("Alice's store fault was counted")
	}
}

type failingMinter struct{}

func (failingMinter) MintPAJob(localjwt.PAJob, string, int64, time.Duration) (string, error) {
	return "", errors.New("signer down")
}

// TestRunLoop_MintFailureCountsNothing: a signer outage is a server fault:
// the claim is released as a retry, so repeated outages never cancel a
// request (P3, as the managed pool's ReleaseUnissued).
// Mutation: ReleaseBackoff on a Mint failure.
func TestRunLoop_MintFailureCountsNothing(t *testing.T) {
	h := newRunLoopHarness(t, withMinter(failingMinter{}))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	for i := range jobs.MaxClaimFailures + 1 {
		if _, code := h.claim(); code == http.StatusOK {
			t.Fatalf("claim %d without a signer succeeded", i+1)
		}
		h.now = h.now.Add(jobs.ClaimBackoff(jobs.MaxClaimFailures))
	}
	if h.count(`SELECT count(*) FROM pa_jobs WHERE status = 'pending' AND claim_failures = 0`) != 1 ||
		h.count(`SELECT count(*) FROM pa_usage`) != 0 {
		t.Fatal("signer outages counted against the job or left a reservation")
	}
}

// TestNewRunLoop_RefusesTurnFloorAboveReservation: the floor of a run at
// its turn cap (tool calls + 1) must fit the reservation, and a zero floor
// is no floor.
func TestNewRunLoop_RefusesTurnFloorAboveReservation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		floor float64
		ok    bool
	}{
		{"zero", 0, false},
		{"above", 0.03, false}, // 9 x 0.03 = 0.27 > 0.25
		{"fits", 0.025, true},  // 9 x 0.025 = 0.225
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := RunLoopConfig{
				Store: newStore(t), Sealer: mustSealer(t), Pool: noPool{}, Minter: failingMinter{}, Verifier: noVerifier{},
				Sender: &sendRecorder{}, Tools: NoTools, Limits: jobs.DefaultLimits(), Allowed: NewAllowlist(nil),
				Budget: jobs.Budget{PerJobUSD: 0.25, PrincipalDayUSD: 2, PrincipalMonthUSD: 20, GlobalDayUSD: 20, MinTurnUSD: tc.floor},
			}
			_, err := NewRunLoop(cfg)
			if tc.ok != (err == nil) {
				t.Fatalf("floor %v: %v", tc.floor, err)
			}
		})
	}
}

type noPool struct{}

func (noPool) Authenticate(*http.Request) (*auth.Identity, error) { return nil, errors.New("no") }

type noVerifier struct{}

func (noVerifier) VerifyRequest(*http.Request) (localjwt.PAJob, error) {
	return localjwt.PAJob{}, errors.New("no")
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
	h := newRunLoopHarness(t, withBudget(jobs.Budget{PerJobUSD: 0.25, PrincipalDayUSD: 0.25, PrincipalMonthUSD: 20, GlobalDayUSD: 20, MinTurnUSD: 0.005}))
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
	if len(sent) != 2 || sent[1] != safetext.ServerText(safetext.TextBudgetHold).String() {
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
	// A day later the conversation has expired: the held request is
	// dropped and Alice is told, instead of waiting silently (F3).
	h.now = h.now.Add(24 * time.Hour)
	h.consentStillOpen(t)
	sent = h.sender.to(aliceID)
	if len(sent) != 3 || sent[2] != safetext.ServerText(safetext.TextRequestDropped).String() {
		t.Fatalf("sent %q, want the dropped-request notice last", sent)
	}
}

// TestRunLoop_HeldDroppedBeforeWindowResets: a held job whose conversation
// expires is dropped (with a notice) when the conversation goes, not when
// the month window resets.
func TestRunLoop_HeldDroppedBeforeWindowResets(t *testing.T) {
	h := newRunLoopHarness(t, withBudget(jobs.Budget{PerJobUSD: 0.25, PrincipalDayUSD: 0.25, PrincipalMonthUSD: 0.25, GlobalDayUSD: 20, MinTurnUSD: 0.005}))
	h.consent(aliceID)
	h.text(aliceID, "one")
	c := h.mustClaim()
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "done"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	h.text(aliceID, "two")
	if _, code := h.claim(); code != http.StatusNoContent {
		t.Fatalf("claim over the month cap: %d", code)
	}
	if _, err := h.convoHarness.store.DB.Exec(`UPDATE pa_conversations SET expires_at_ms = $1 WHERE principal = $2`,
		h.now.Add(time.Hour).UnixMilli(), aliceID); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(2 * time.Hour) // well before the month resets
	if _, code := h.claim(); code != http.StatusNoContent {
		t.Fatalf("claim: %d", code)
	}
	sent := h.sender.to(aliceID)
	if len(sent) != 3 || sent[2] != safetext.ServerText(safetext.TextRequestDropped).String() {
		t.Fatalf("sent %q, want answer, hold, dropped", sent)
	}
	var st string
	_ = h.convoHarness.store.DB.QueryRow(`SELECT status FROM pa_jobs WHERE principal = $1 ORDER BY id DESC LIMIT 1`, aliceID).Scan(&st)
	if st != "cancelled" {
		t.Fatalf("held job %s", st)
	}
}

// TestRunLoop_ExpiredLeaseNotice is F5: a run whose lease ran out ends
// with a short server text, once.
func TestRunLoop_ExpiredLeaseNotice(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	h.now = h.now.Add(jobs.DefaultLease + time.Second)
	for range 2 {
		if _, code := h.claim(); code != http.StatusNoContent {
			t.Fatalf("claim: %d", code)
		}
	}
	sent := h.sender.to(aliceID)
	if len(sent) != 1 || sent[0] != safetext.ServerText(safetext.TextRunFailed).String() {
		t.Fatalf("sent %q, want one run-failed notice", sent)
	}
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "late"}); w.Code != http.StatusConflict {
		t.Fatalf("late reply: %d", w.Code)
	}
	if len(h.sender.to(aliceID)) != 1 {
		t.Fatal("a late reply was sent")
	}
}

// TestRunLoop_StateChangesBetweenClaimAndReply is M13: the reply route
// re-runs the gate, so a conversation that expired or a consent version
// that changed after the claim stops the reply.
func TestRunLoop_StateChangesBetweenClaimAndReply(t *testing.T) {
	for _, tc := range []struct {
		name, sql string
		notice    *safetext.Template
	}{
		{"conversation expired", `UPDATE pa_conversations SET expires_at_ms = 1 WHERE principal = $1`, &safetext.TextRequestDropped},
		{"conversation closed", `UPDATE pa_conversations SET closed_at_ms = 1 WHERE principal = $1`, &safetext.TextRequestDropped},
		{"consent version changed", `UPDATE pa_consents SET version = 'pa-data-flow/v0' WHERE principal = $1`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newRunLoopHarness(t)
			h.consent(aliceID)
			h.text(aliceID, "hello")
			c := h.mustClaim()
			if _, err := h.convoHarness.store.DB.Exec(tc.sql, aliceID); err != nil {
				t.Fatal(err)
			}
			if w := h.post(RouteReply, c.Token, replyRequest{Text: "secret"}); w.Code != http.StatusConflict {
				t.Fatalf("reply: %d", w.Code)
			}
			sent := h.sender.to(aliceID)
			want := 0
			if tc.notice != nil {
				want = 1
			}
			if len(sent) != want || (want == 1 && sent[0] != safetext.ServerText(*tc.notice).String()) {
				t.Fatalf("sent %q", sent)
			}
			if js, us := h.jobStatus(c.JobID); js != "cancelled" || us != "held" {
				t.Fatalf("job %s usage %s", js, us)
			}
			// A second step does not repeat the notice.
			_ = h.post(RouteReply, c.Token, replyRequest{Text: "secret"})
			if len(h.sender.to(aliceID)) != want {
				t.Fatal("notice repeated")
			}
		})
	}
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
	// F1: a context that does not validate (here a connection revision
	// the resolver should never produce) recurs on every attempt, so the
	// job is cancelled with a notice in the same claim that serves Bob.
	t.Run("invalid execution context", func(t *testing.T) {
		h2 := newRunLoopHarness(t)
		h2.conns = map[int64][]ConnectionRevision{aliceID: {{ConnectionID: "c1", AuthorityRevision: 0}}}
		h2.consent(aliceID)
		h2.consent(bobID)
		h2.text(aliceID, "hello")
		h2.now = h2.now.Add(time.Millisecond)
		h2.text(bobID, "hi")
		c := h2.mustClaim()
		if c.Token == "" {
			t.Fatal("Bob not claimed")
		}
		if n := h2.count(`SELECT count(*) FROM pa_jobs WHERE principal = $1 AND status = 'cancelled'`, aliceID); n != 1 {
			t.Fatalf("Alice cancelled = %d", n)
		}
		sent := h2.sender.to(aliceID)
		if len(sent) != 1 || sent[0] != safetext.ServerText(safetext.TextRunFailed).String() {
			t.Fatalf("Alice was sent %q", sent)
		}
	})
}

// TestRunLoop_S1X2Budget is the budget part of S1-X2: Bob's runs are not
// held by Alice's spend.
func TestRunLoop_S1X2Budget(t *testing.T) {
	h := newRunLoopHarness(t, withBudget(jobs.Budget{PerJobUSD: 0.25, PrincipalDayUSD: 0.25, PrincipalMonthUSD: 20, GlobalDayUSD: 20, MinTurnUSD: 0.005}))
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

// TestRunLoop_ReadErrorsFailClosed: a consent or status read error is
// never consent, never an open conversation, and reserves nothing (I9).
// The job is not claimed and not cancelled: it is backed off (F1), so it
// cannot block other principals' jobs.
func TestRunLoop_ReadErrorsFailClosed(t *testing.T) {
	for name, wrap := range map[string]func(*db.Store) RunLoopStore{
		"consent":      func(s *db.Store) RunLoopStore { return failingConsent{s} },
		"conversation": func(s *db.Store) RunLoopStore { return failingConversation{s} },
	} {
		t.Run(name, func(t *testing.T) {
			h := newRunLoopHarness(t, withStore(wrap))
			h.consent(aliceID) // the webhook path reads through the real store
			h.text(aliceID, "hello")
			if _, code := h.claim(); code != http.StatusNoContent {
				t.Fatalf("claim with an unreadable %s: %d", name, code)
			}
			if n := h.count(`SELECT count(*) FROM pa_jobs WHERE claim_failures = 1 AND retry_at_ms > 0`); n != 1 {
				t.Fatal("the failed claim was not backed off")
			}
			if len(h.sender.to(aliceID)) != 0 {
				t.Fatal("a notice after one transient failure")
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
	// /forget past the limit still runs (TestConversations_ErasureIsRateBounded
	// proves the deletion); only its confirmation is dropped.
	if code := h.text(aliceID, "/forget"); code != http.StatusOK {
		t.Fatalf("/forget past the limit: %d", code)
	}
	if len(h.replies.replies) != before {
		t.Fatal("/forget past the limit was confirmed: the window does not bound erasure replies")
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
	// A count at the cap together with an error: the error wins (M33).
	return MaxHandlerAttempts + 1, errors.New("down")
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
		Store: newStore(t), Sealer: mustSealer(t), TTL: time.Hour, Runs: &enqueueRecorder{}, Allowed: NewAllowlist(nil),
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

// storeFault is the error the db store returns for a failed read
// (db.storeFault): nothing was observed about the row.
var storeFault = fmt.Errorf("%w: %w: begin: driver: bad connection", convo.ErrUnreadable, convo.ErrStoreFault)

// flakyFragments fails the next n fragment loads with a store fault.
type flakyFragments struct {
	*db.Store
	n *int
}

func (f flakyFragments) LoadPAFragments(ctx context.Context, p int64, c string, now time.Time) ([]convo.SealedFragment, error) {
	if *f.n > 0 {
		*f.n--
		return nil, storeFault
	}
	return f.Store.LoadPAFragments(ctx, p, c, now)
}

// faultedConsent: every consent read is a store fault.
type faultedConsent struct{ *db.Store }

func (faultedConsent) GetPAConsent(context.Context, *sql.Tx, int64) (convo.ConsentRecord, error) {
	return convo.ConsentRecord{}, storeFault
}

// TestRunLoop_StoreFaultsChangeNothing: one DB hiccup must not cancel a
// request ("could not observe" is not "observed bad").
func TestRunLoop_StoreFaultsChangeNothing(t *testing.T) {
	t.Run("fragment load", func(t *testing.T) {
		n := 1
		h := newRunLoopHarness(t, withStore(func(s *db.Store) RunLoopStore { return flakyFragments{s, &n} }))
		h.consent(aliceID)
		h.text(aliceID, "hello")
		if _, code := h.claim(); code != http.StatusServiceUnavailable {
			t.Fatalf("claim with a failed fragment load: %d", code)
		}
		// Nothing counted; due again after the first backoff step.
		retryAt := h.now.Add(jobs.ClaimBackoff(1)).UnixMilli()
		if got := h.count(fmt.Sprintf(`SELECT count(*) FROM pa_jobs WHERE status = 'pending' AND claim_failures = 0 AND retry_at_ms = %d`, retryAt)); got != 1 {
			t.Fatal("a store fault counted a failure or was not retried after the first backoff step")
		}
		if h.count(`SELECT count(*) FROM pa_usage`) != 0 || len(h.sender.to(aliceID)) != 0 {
			t.Fatal("a store fault left usage or sent a notice")
		}
		h.now = h.now.Add(jobs.ClaimBackoff(1))
		if c := h.mustClaim(); c.Token == "" {
			t.Fatal("not claimed once the store recovered")
		}
	})
	t.Run("gate over many polls", func(t *testing.T) {
		h := newRunLoopHarness(t, withStore(func(s *db.Store) RunLoopStore { return faultedConsent{s} }))
		h.consent(aliceID)
		h.text(aliceID, "hello")
		for range 2 * jobs.MaxClaimFailures {
			h.now = h.now.Add(10 * time.Minute)
			if _, code := h.claim(); code != http.StatusServiceUnavailable {
				t.Fatalf("claim under a consent store fault: %d", code)
			}
		}
		if got := h.count(`SELECT count(*) FROM pa_jobs WHERE status = 'pending' AND claim_failures = 0`); got != 1 {
			t.Fatal("a sustained store fault counted against the job")
		}
		if len(h.sender.to(aliceID)) != 0 {
			t.Fatal("a store fault sent a notice")
		}
	})
}

// closingFinish closes the conversation after RunningPAJob passed and
// before the finish transaction runs.
type closingFinish struct{ *db.Store }

func (c closingFinish) FinishPAJob(ctx context.Context, ref jobs.Ref, req jobs.FinishRequest) (jobs.Job, error) {
	if _, err := c.DB.ExecContext(ctx, `UPDATE pa_conversations SET closed_at_ms = 1 WHERE principal = $1`, ref.Principal); err != nil {
		return jobs.Job{}, err
	}
	return c.Store.FinishPAJob(ctx, ref, req)
}

// TestRunLoop_FinishGate is M13 at finish time: state that changes after
// the reply's first check is caught by the gate in the finish transaction.
func TestRunLoop_FinishGate(t *testing.T) {
	h := newRunLoopHarness(t, withStore(func(s *db.Store) RunLoopStore { return closingFinish{s} }))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "secret"}); w.Code != http.StatusConflict {
		t.Fatalf("reply: %d", w.Code)
	}
	sent := h.sender.to(aliceID)
	if len(sent) != 1 || sent[0] != safetext.ServerText(safetext.TextRequestDropped).String() {
		t.Fatalf("sent %q, want only the dropped notice", sent)
	}
	if js, us := h.jobStatus(c.JobID); js != "cancelled" || us != "held" {
		t.Fatalf("job %s usage %s", js, us)
	}
}

// TestRunLoop_ContextNamesTheAcceptedText: the signed execution context
// names the consent text the principal accepted, Russian or English, not
// always the English one.
func TestRunLoop_ContextNamesTheAcceptedText(t *testing.T) {
	h := newRunLoopHarness(t)
	ruFrom := map[string]any{"id": aliceID, "is_bot": false, "first_name": "Alice", "language_code": "ru"}
	h.message(aliceID, map[string]any{"text": "/consent", "from": ruFrom})
	r := h.replies.last(aliceID)
	if r.reply != ReplyConsentPromptRU {
		t.Fatalf("reply %q, want the Russian prompt", r.reply)
	}
	h.press(aliceID, r.button)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	var raw string
	if err := h.convoHarness.store.DB.QueryRow(`SELECT execution_context FROM pa_jobs WHERE id = $1`, c.JobID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var rc runContext
	if err := json.Unmarshal([]byte(raw), &rc); err != nil {
		t.Fatal(err)
	}
	if rc.ConsentSHA256 != convo.ConsentTextSHA256RU() || rc.ConsentVersion != convo.ConsentVersion {
		t.Fatalf("context consent %s %s, want the Russian text's hash", rc.ConsentVersion, rc.ConsentSHA256)
	}
}

type fakePhotoFetcher struct {
	byID map[string]string
	err  error
}

func (f fakePhotoFetcher) FetchPhoto(_ context.Context, fileID string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	if u, ok := f.byID[fileID]; ok {
		return u, nil
	}
	return "", errors.New("photo not found")
}

func TestRunLoop_ClaimHydratesRecentPhotosAndTaints(t *testing.T) {
	const dataURI1 = "data:image/jpeg;base64,/9j/4AAQ"
	const dataURI2 = "data:image/png;base64,iVBORw0KGgo="
	const dataURI3 = "data:image/webp;base64,UklGRg=="
	h := newRunLoopHarness(t, func(c *RunLoopConfig, _ *runLoopHarness) {
		c.Photos = fakePhotoFetcher{byID: map[string]string{
			"photo_oldest_111": dataURI1,
			"photo_middle_222": dataURI2,
			"photo_latest_333": dataURI3,
		}}
	})
	h.consent(aliceID)
	for _, id := range []string{"photo_oldest_111", "photo_middle_222", "photo_latest_333"} {
		if code := h.message(aliceID, map[string]any{
			"caption": "look",
			"photo":   []any{map[string]any{"file_id": id, "width": 800, "height": 600, "file_size": 1000}},
		}); code != http.StatusOK {
			t.Fatalf("message %s: %d", id, code)
		}
	}
	c := h.mustClaim()
	var photos []wireFragment
	for _, f := range c.Fragments {
		if f.Kind == string(convo.KindPhoto) {
			photos = append(photos, f)
		}
	}
	if len(photos) != 3 {
		t.Fatalf("photo fragments = %d, want 3", len(photos))
	}
	if photos[0].ImageURL != "" || photos[0].Text != "[photo unavailable]" {
		t.Fatalf("oldest photo = %+v, want stripped placeholder", photos[0])
	}
	if photos[1].ImageURL != dataURI2 || photos[1].Text != "[photo]" {
		t.Fatalf("middle photo = %+v, want hydrated dataURI2", photos[1])
	}
	if photos[2].ImageURL != dataURI3 || photos[2].Text != "[photo]" {
		t.Fatalf("latest photo = %+v, want hydrated dataURI3", photos[2])
	}
	for _, f := range photos {
		if f.Provenance != string(convo.ProvenanceExternal) {
			t.Fatalf("photo provenance = %q, want external", f.Provenance)
		}
	}
}

type failRecorder struct {
	mu      sync.Mutex
	reasons []string
}

func (f *failRecorder) CountPAJobFailure(reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reasons = append(f.reasons, reason)
}

func TestPAFailureReasonLabelsAndAlertsComplete(t *testing.T) {
	reasons := jobs.FailureReasons()
	metricLabels := make([]string, 0, len(reasons))
	for _, r := range reasons {
		metricLabels = append(metricLabels, string(r))
		if tpl, ok := alertTemplates[r]; !ok || tpl == (safetext.Template{}) {
			t.Fatalf("missing alert template for %q", r)
		}
		if kind := jobs.OutboxKindForFailure(r); !jobs.IsFailureOutboxKind(kind) {
			t.Fatalf("OutboxKindForFailure(%q) = %q, not a failure kind", r, kind)
		}
		if _, ok := outboxTemplates[jobs.OutboxKindForFailure(r)]; !ok {
			t.Fatalf("missing outbox template for %q", r)
		}
	}
	slices.Sort(metricLabels)
	got := slices.Clone(metrics.PAFailureReasons)
	slices.Sort(got)
	if !slices.Equal(metricLabels, got) {
		t.Fatalf("failure reasons %v != metrics.PAFailureReasons %v", metricLabels, got)
	}
}

func TestRunLoop_FailReasonNotifiesUserAndAdmins(t *testing.T) {
	const adminID = int64(210408407)
	fc := &failRecorder{}
	h := newRunLoopHarness(t, func(c *RunLoopConfig, _ *runLoopHarness) {
		c.Admins = []int64{adminID, adminID, 0, -5}
		c.FailureMetrics = fc
	})
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()

	if w := h.post(RouteReply, c.Token, replyRequest{FailReason: string(jobs.FailureProviderRateLimit)}); w.Code != http.StatusOK {
		t.Fatalf("fail_reason status = %d, want 200 (%s)", w.Code, w.Body.String())
	}
	h.loop.WaitDeliveries()
	if js, us := h.jobStatus(c.JobID); js != "cancelled" || us != "held" {
		t.Fatalf("job %s usage %s, want cancelled/held", js, us)
	}
	sentUser := h.sender.to(aliceID)
	wantUser := safetext.ServerText(safetext.TextRunFailedRateLimit).String()
	if len(sentUser) != 1 || sentUser[0] != wantUser {
		t.Fatalf("user got %q, want %q", sentUser, wantUser)
	}
	sentAdmin := h.sender.to(adminID)
	wantAdmin := safetext.ServerText(safetext.TextAlertPARunFailedProviderRateLimit).String()
	if len(sentAdmin) != 1 || sentAdmin[0] != wantAdmin {
		t.Fatalf("admin got %q, want %q", sentAdmin, wantAdmin)
	}
	if !slices.Equal(fc.reasons, []string{string(jobs.FailureProviderRateLimit)}) {
		t.Fatalf("recorded failure reasons = %v", fc.reasons)
	}
}

func TestRunLoop_FailReasonRejectsInvalidAndMixedBodies(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	cost := 0.01
	for name, body := range map[string]replyRequest{
		"unknown reason":       {FailReason: "bogus"},
		"server-only reason":   {FailReason: string(jobs.FailureLeaseExpired)},
		"with text":            {Text: "answer", FailReason: string(jobs.FailureEmptyAnswer)},
		"with cost":            {CostUSD: &cost, FailReason: string(jobs.FailureEmptyAnswer)},
	} {
		if w := h.post(RouteReply, c.Token, body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, w.Code)
		}
	}
	if js, _ := h.jobStatus(c.JobID); js != "claimed" {
		t.Fatalf("job status = %s after rejected fail_reason, want claimed", js)
	}
}

func TestRunLoop_LeaseExpiryAlertsAdmins(t *testing.T) {
	const adminID = int64(210408407)
	fc := &failRecorder{}
	h := newRunLoopHarness(t, func(c *RunLoopConfig, _ *runLoopHarness) {
		c.Admins = []int64{adminID}
		c.FailureMetrics = fc
	})
	h.consent(aliceID)
	h.text(aliceID, "hello")
	_ = h.mustClaim()
	h.now = h.now.Add(jobs.DefaultLease + time.Second)
	if w := h.post(RouteClaim, h.pool, nil); w.Code != http.StatusNoContent {
		t.Fatalf("claim status = %d", w.Code)
	}
	h.loop.WaitDeliveries()
	if !slices.Equal(fc.reasons, []string{string(jobs.FailureLeaseExpired)}) {
		t.Fatalf("recorded failure reasons = %v", fc.reasons)
	}
	sentAdmin := h.sender.to(adminID)
	wantAdmin := safetext.ServerText(safetext.TextAlertPARunFailedLeaseExpired).String()
	if len(sentAdmin) != 1 || sentAdmin[0] != wantAdmin {
		t.Fatalf("admin got %q, want %q", sentAdmin, wantAdmin)
	}
}
