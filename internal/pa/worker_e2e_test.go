package pa

// worker_e2e_test.go runs the agent worker's PA mode (internal/agentworker,
// AGENT_WORKER_PA=1) against the real run loop over HTTP: the wire types,
// tokens and stop answers of both sides have to agree (#1313 slice d2).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
)

type e2eModel struct {
	mu      sync.Mutex
	results []*agentworker.ChatResult
	inputs  [][]agentworker.ChatMessage
}

func (m *e2eModel) ChatNoTools(_ context.Context, msgs []agentworker.ChatMessage) (*agentworker.ChatResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inputs = append(m.inputs, msgs)
	r := m.results[0]
	if len(m.results) > 1 {
		m.results = m.results[1:]
	}
	return r, nil
}

func e2eAnswer(text string, in, out int) *agentworker.ChatResult {
	return &agentworker.ChatResult{
		Message: agentworker.ChatMessage{Role: "assistant", Content: text},
		Usage:   agentworker.ChatUsage{PromptTokens: in, CompletionTokens: out}, UsageReported: in > 0 || out > 0,
	}
}

func newE2EWorker(t *testing.T, h *runLoopHarness, m agentworker.PAModel) *agentworker.PAWorker {
	t.Helper()
	mux := http.NewServeMux()
	h.loop.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &agentworker.PAWorker{
		BaseURL: srv.URL, PoolToken: h.pool, HTTP: srv.Client(), Model: m,
		Prices: agentworker.Prices{InputUSDPerMTok: 1, OutputUSDPerMTok: 1},
		Now:    func() time.Time { return h.now },
	}
}

func e2eUsage(t *testing.T, h *runLoopHarness, job int64) (cost float64, reported *float64) {
	t.Helper()
	if err := h.convoHarness.store.DB.QueryRow(`SELECT cost_usd, reported_cost_usd FROM pa_usage WHERE job_id = $1`, job).Scan(&cost, &reported); err != nil {
		t.Fatal(err)
	}
	return cost, reported
}

// TestPARoutesMatchServer: the worker's copies of the routes are the
// server's.
func TestPARoutesMatchServer(t *testing.T) {
	if agentworker.PARouteClaim != RouteClaim || agentworker.PARouteTurn != RouteTurn || agentworker.PARouteReply != RouteReply {
		t.Fatal("agentworker PA routes differ from the run loop's")
	}
	if agentworker.PAMaxToolCalls != jobs.DefaultMaxToolCalls || agentworker.PAMaxContextTokens != jobs.DefaultMaxContextTokens {
		t.Fatal("agentworker PA ceilings differ from the job defaults")
	}
}

// TestWorkerE2E_Reply: message, claim, turn, model, reply, delivered
// through Render; the reported cost is settled.
func TestWorkerE2E_Reply(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "what is on https://example.org/a ?")
	m := &e2eModel{results: []*agentworker.ChatResult{e2eAnswer("It is https://example.org/a, not https://evil.example/x", 20_000, 1_000)}}
	w := newE2EWorker(t, h, m)
	c, err := w.Claim(context.Background())
	if err != nil || c == nil {
		t.Fatalf("claim = %v, %v", c, err)
	}
	out, err := w.Run(context.Background(), c)
	if err != nil || out != agentworker.PAReplied {
		t.Fatalf("run = %s, %v", out, err)
	}
	if len(m.inputs) != 1 || m.inputs[0][1].Role != "user" || !strings.Contains(m.inputs[0][1].Content, "example.org/a") {
		t.Fatalf("model input = %+v", m.inputs)
	}
	sent := h.sentTo(aliceID)
	if len(sent) != 1 || !strings.Contains(sent[0], "https://example.org/a") || strings.Contains(sent[0], "evil.example") {
		t.Fatalf("sent = %q", sent)
	}
	if js, us := h.jobStatus(c.JobID); js != "done" || us != "settled" {
		t.Fatalf("job %s usage %s", js, us)
	}
	cost, reported := e2eUsage(t, h, c.JobID)
	if reported == nil || *reported < 0.0209 || *reported > 0.0211 || cost != *reported {
		t.Fatalf("settled %v reported %v, want 0.021", cost, reported)
	}
	// Nothing else is due.
	if c2, err := w.Claim(context.Background()); c2 != nil || err != nil {
		t.Fatalf("second claim = %v, %v", c2, err)
	}
}

// TestWorkerE2E_UnknownCostSettlesFull: a run whose usage was not reported
// is settled at the full reservation, not as free.
func TestWorkerE2E_UnknownCostSettlesFull(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	w := newE2EWorker(t, h, &e2eModel{results: []*agentworker.ChatResult{e2eAnswer("hi", 0, 0)}})
	c, err := w.Claim(context.Background())
	if err != nil || c == nil {
		t.Fatalf("claim = %v, %v", c, err)
	}
	if out, err := w.Run(context.Background(), c); out != agentworker.PAReplied || err != nil {
		t.Fatalf("run = %s, %v", out, err)
	}
	if cost, reported := e2eUsage(t, h, c.JobID); reported != nil || cost != 0.25 {
		t.Fatalf("settled %v reported %v, want the 0.25 reservation", cost, reported)
	}
}

// TestWorkerE2E_ToolCapEndsRun: the claim carries the server's tool cap;
// a model that keeps asking for tools hits it, nothing is replied, and the
// principal gets the run-failed notice once the lease runs out.
func TestWorkerE2E_ToolCapEndsRun(t *testing.T) {
	l := jobs.DefaultLimits()
	l.MaxToolCalls = 1
	h := newRunLoopHarness(t, withLimits(l))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	tc := e2eAnswer("", 10, 1)
	tc.Message.ToolCalls = []agentworker.ToolCall{{ID: "call_1", Name: "x", Arguments: "{}"}}
	m := &e2eModel{results: []*agentworker.ChatResult{tc}}
	w := newE2EWorker(t, h, m)
	c, err := w.Claim(context.Background())
	if err != nil || c == nil {
		t.Fatalf("claim = %v, %v", c, err)
	}
	out, err := w.Run(context.Background(), c)
	if out != agentworker.PAAbandoned || err == nil {
		t.Fatalf("run = %s, %v", out, err)
	}
	if len(h.sentTo(aliceID)) != 0 {
		t.Fatal("something was sent for an unfinished run")
	}
	h.now = h.now.Add(jobs.DefaultLease + time.Second)
	if c2, err := w.Claim(context.Background()); c2 != nil || err != nil {
		t.Fatalf("claim after expiry = %v, %v", c2, err)
	}
	sent := h.sentTo(aliceID)
	if len(sent) != 1 || sent[0] != output.ServerText(output.TextRunFailed).String() {
		t.Fatalf("sent %q, want one run-failed notice", sent)
	}
}

// TestWorkerE2E_StaleTokenStops: a token whose job was already answered is
// refused at the first turn, and the model is never called.
func TestWorkerE2E_StaleTokenStops(t *testing.T) {
	h := newRunLoopHarness(t)
	h.consent(aliceID)
	h.text(aliceID, "hello")
	m := &e2eModel{results: []*agentworker.ChatResult{e2eAnswer("hi", 10, 1)}}
	w := newE2EWorker(t, h, m)
	c, err := w.Claim(context.Background())
	if err != nil || c == nil {
		t.Fatalf("claim = %v, %v", c, err)
	}
	if out, err := w.Run(context.Background(), c); out != agentworker.PAReplied || err != nil {
		t.Fatalf("first run = %s, %v", out, err)
	}
	out, err := w.Run(context.Background(), c)
	if out != agentworker.PAStopped || err == nil || len(m.inputs) != 1 {
		t.Fatalf("replayed run = %s, %v, model calls %d", out, err, len(m.inputs))
	}
	if len(h.sentTo(aliceID)) != 1 {
		t.Fatal("a replayed run sent a second reply")
	}
}
