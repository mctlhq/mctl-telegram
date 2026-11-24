package pa_test

// The agent worker against the real run loop and a dispatcher that emits
// approval cards (#1320 slice P2-S13): an approval_pending answer has to
// mean the same on both sides. Nothing in a deployed service builds the
// card emitter, so the server half of this exists in tests only.

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/token"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// writeWorker is a worker on e's routes and the claim of e's run, offering
// the write tool. The claim is built here: the run loop signs no
// approve-tier tool into a job (TestRunLoopToolSetIsPhase1Reads), and the
// card env admits the write under the run's own token.
func writeWorker(t *testing.T, e *cardEnv, m agentworker.PAModel) (*agentworker.PAWorker, *agentworker.PAClaim) {
	t.Helper()
	mux := http.NewServeMux()
	e.h.Loop().Mount(mux)
	e.d.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	limits := jobs.DefaultLimits()
	raw, err := json.Marshal(map[string]any{
		"job_id": e.job, "attempt": 1, "token": e.token,
		"lease_until": e.h.Now().Add(5 * time.Minute),
		"tool_set":    []string{"tg/" + writeTool},
		"tools": []map[string]any{{
			"name": "tg/" + writeTool, "description": "Send a message.",
			"input_schema": json.RawMessage(`{"type":"object"}`),
		}},
		"limits": map[string]any{
			"max_job_cost_usd": 0.25, "max_tool_calls": limits.MaxToolCalls, "max_context_tokens": 32000,
		},
		"fragments": []map[string]string{{"kind": "text", "provenance": "user", "text": "please send it"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var c agentworker.PAClaim
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return &agentworker.PAWorker{
		BaseURL: srv.URL, PoolToken: e.h.PoolToken(), HTTP: srv.Client(), Model: m,
		Prices: agentworker.Prices{InputUSDPerMTok: 1, OutputUSDPerMTok: 1}, Now: e.h.Now,
	}, &c
}

func writeAsk(id string) *agentworker.ChatResult {
	return &agentworker.ChatResult{
		Message: agentworker.ChatMessage{Role: "assistant", ToolCalls: []agentworker.ToolCall{
			{ID: id, Name: "tg__" + writeTool, Arguments: writeArgs},
		}},
		Usage: agentworker.ChatUsage{PromptTokens: 10, CompletionTokens: 1}, UsageReported: true,
	}
}

// oneCard asserts the run left exactly one pending approval, one card and
// one counted call, made no downstream call and granted nothing.
func oneCard(t *testing.T, e *cardEnv) {
	t.Helper()
	e.h.Loop().WaitDeliveries()
	if rows := e.approvals(alice); len(rows) != 1 || rows[0].status != "pending" {
		t.Fatalf("approvals: %+v", rows)
	}
	if cards := e.sentCards(alice); len(cards) != 1 {
		t.Fatalf("%d cards sent, want 1", len(cards))
	}
	if n := e.toolCalls(e.job); n != 1 {
		t.Fatalf("tool_calls = %d, want 1", n)
	}
	e.noCalls()
	if n := e.h.Count(`SELECT COUNT(*) FROM pa_permissions`); n != 0 {
		t.Fatalf("%d permissions", n)
	}
}

// TestWorkerE2E_ApprovalPendingQueuesOneCard: a model that asks for the
// write on every call gets one card out of one run. The server answers
// approval_pending, the worker offers no tools on the one model call that
// follows, and the write asked for again ends the run unsent.
func TestWorkerE2E_ApprovalPendingQueuesOneCard(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		m := &toolLoopModel{results: []*agentworker.ChatResult{writeAsk("w1")}}
		w, c := writeWorker(t, e, m)
		out, err := w.Run(context.Background(), c)
		if out != agentworker.PAAbandoned || err == nil {
			t.Fatalf("run = %s, %v; want abandoned", out, err)
		}
		if len(m.inputs) != 2 || len(m.offered[0]) != 1 || len(m.offered[1]) != 0 {
			t.Fatalf("%d model calls, offered %+v", len(m.inputs), m.offered)
		}
		oneCard(t, e)
	})
}

// TestWorkerE2E_ApprovalPendingThenAnswer: the model reads the fixed
// sentence as the result of the write and its answer is the run's reply;
// the card is the only other thing the principal gets.
func TestWorkerE2E_ApprovalPendingThenAnswer(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newCardEnv(t, s)
		m := &toolLoopModel{results: []*agentworker.ChatResult{writeAsk("w1"), {
			Message: agentworker.ChatMessage{Role: "assistant", Content: "It waits for your approval."},
			Usage:   agentworker.ChatUsage{PromptTokens: 10, CompletionTokens: 1}, UsageReported: true,
		}}}
		w, c := writeWorker(t, e, m)
		out, err := w.Run(context.Background(), c)
		if err != nil || out != agentworker.PAReplied {
			t.Fatalf("run = %s, %v", out, err)
		}
		var tool []agentworker.ChatMessage
		for _, msg := range m.inputs[1] {
			if msg.Role == "tool" {
				tool = append(tool, msg)
			}
		}
		if len(tool) != 1 || tool[0].ToolCallID != "w1" || tool[0].Content != agentworker.PAToolApprovalPending {
			t.Fatalf("tool messages = %+v", tool)
		}
		oneCard(t, e)
		if sent := e.h.SentTo(alice); !slices.ContainsFunc(sent, func(s string) bool { return strings.Contains(s, "It waits for your approval.") }) {
			t.Fatalf("sent %q", sent)
		}
	})
}

// TestWorkerE2E_WritesOffOffersNoWriteTool: the claim a server makes with
// the write path unbuilt, the only state deployed, holds read-tier tools
// of the Phase 1 pin only, and none of them is an approve-tier tool of
// the Phase 2 pin. A write the model asks for anyway is answered by the
// worker and reaches no route.
func TestWorkerE2E_WritesOffOffersNoWriteTool(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		e.h.Consent(alice)
		e.h.Text(alice, "send Carol a message")
		mux := http.NewServeMux()
		e.h.Loop().Mount(mux)
		e.d.Mount(mux)
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		m := &toolLoopModel{results: []*agentworker.ChatResult{writeAsk("w1"), {
			Message: agentworker.ChatMessage{Role: "assistant", Content: "I cannot send messages."},
			Usage:   agentworker.ChatUsage{PromptTokens: 10, CompletionTokens: 1}, UsageReported: true,
		}}}
		w := &agentworker.PAWorker{
			BaseURL: srv.URL, PoolToken: e.h.PoolToken(), HTTP: srv.Client(), Model: m,
			Prices: agentworker.Prices{InputUSDPerMTok: 1, OutputUSDPerMTok: 1}, Now: e.h.Now,
		}
		c, err := w.Claim(context.Background())
		if err != nil || c == nil {
			t.Fatalf("claim = %v, %v", c, err)
		}
		p1, err := catalog.LoadPin()
		if err != nil {
			t.Fatal(err)
		}
		p2, err := catalog.LoadPinPhase2()
		if err != nil {
			t.Fatal(err)
		}
		if len(c.ToolSet) == 0 {
			t.Fatal("fixture: the claim signs no tool")
		}
		for _, name := range c.ToolSet {
			server, tool, _ := strings.Cut(name, "/")
			if pt, ok := p1.Servers[server].Tools[tool]; !ok || pt.Tier != catalog.TierAuto || pt.Class != catalog.ClassRead {
				t.Fatalf("claim signs %s, not a read of the Phase 1 pin", name)
			}
			if p2.Servers[server].Tools[tool].Tier == catalog.TierApprove {
				t.Fatalf("claim signs the approve-tier tool %s", name)
			}
		}
		out, err := w.Run(context.Background(), c)
		if err != nil || out != agentworker.PAReplied {
			t.Fatalf("run = %s, %v", out, err)
		}
		for i, offered := range m.offered {
			for _, tool := range offered {
				if !slices.Contains(c.ToolSet, strings.Replace(tool.Name, "__", "/", 1)) {
					t.Fatalf("model call %d was offered %s", i, tool.Name)
				}
			}
		}
		if calls, _, _ := e.tg.snapshot(); len(calls) != 0 || e.toolCalls(c.JobID) != 0 {
			t.Fatalf("calls %v, tool_calls %d", calls, e.toolCalls(c.JobID))
		}
		if n := e.h.Count(`SELECT COUNT(*) FROM pa_approvals`); n != 0 {
			t.Fatalf("%d approvals", n)
		}
	})
}

// TestS2A8_WorkerReachesOnlyTheDrivenJobRoutes is the worker half of
// S2-A8: every server route the agent worker's PA mode can name is one of
// the routes TestS2A8_NoJobRouteGrantsAPermission drives with grant
// payloads. The worker's tool path (#1318 C3) and its approval_pending
// handling (#1320 P2-S13) go through connector.RouteTool and add no route
// and no tool of their own: a tool call is a (server, tool) pair of the
// claim, executed by the server.
func TestS2A8_WorkerReachesOnlyTheDrivenJobRoutes(t *testing.T) {
	_, files := repoGoFiles(t)
	driven := jobRoutes()
	var named []string
	for name, f := range files {
		if !strings.HasPrefix(name, "internal/agentworker/") && !strings.HasPrefix(name, "cmd/agent-worker/") {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("%s: literal %s: %v", name, lit.Value, err)
			}
			// Any path under the PA API, however it is assembled from a
			// prefix: a literal that starts one is checked whole.
			if strings.Contains(s, "/api/pa") || strings.Contains(s, "pa/v1") {
				named = append(named, s)
				if !slices.Contains(driven, s) {
					t.Errorf("%s names the PA route %q, which no S2-A8 test drives", name, s)
				}
			}
			return true
		})
	}
	slices.Sort(named)
	named = slices.Compact(named)
	slices.Sort(driven)
	if !slices.Equal(named, driven) {
		t.Fatalf("the worker names %v, the driven routes are %v", named, driven)
	}
	for _, r := range []string{agentworker.PARouteClaim, agentworker.PARouteTurn, agentworker.PARouteReply, agentworker.PARouteTool} {
		if !slices.Contains(driven, r) {
			t.Fatalf("worker route %q is not driven", r)
		}
	}
	if agentworker.PARouteTool != connector.RouteTool {
		t.Fatalf("worker tool route %q", agentworker.PARouteTool)
	}
}
