package pa_test

// The agent worker's tool loop (#1318 slice C3) against the real run loop
// and connector dispatcher over HTTP: the claim's tools, the job token on
// /tool, the server-side execution and the external wrapping have to agree
// on both sides.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

type toolLoopModel struct {
	mu      sync.Mutex
	results []*agentworker.ChatResult
	inputs  [][]agentworker.ChatMessage
	offered [][]agentworker.PAModelTool
}

func (m *toolLoopModel) ChatPA(_ context.Context, msgs []agentworker.ChatMessage, tools []agentworker.PAModelTool) (*agentworker.ChatResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inputs = append(m.inputs, slices.Clone(msgs))
	m.offered = append(m.offered, slices.Clone(tools))
	r := m.results[0]
	if len(m.results) > 1 {
		m.results = m.results[1:]
	}
	return r, nil
}

func TestWorkerE2E_ToolLoopThroughDispatcher(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDispatchEnv(t, s)
		e.h.Consent(alice)
		e.h.Text(alice, "who wrote to me?")
		mux := http.NewServeMux()
		e.h.Loop().Mount(mux)
		e.d.Mount(mux)
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)

		call := &agentworker.ChatResult{
			Message:       agentworker.ChatMessage{Role: "assistant", ToolCalls: []agentworker.ToolCall{{ID: "c1", Name: "tg__list_dialogs", Arguments: "{}"}}},
			Usage:         agentworker.ChatUsage{PromptTokens: 10, CompletionTokens: 1},
			UsageReported: true,
		}
		final := &agentworker.ChatResult{
			Message:       agentworker.ChatMessage{Role: "assistant", Content: "Bob wrote to you."},
			Usage:         agentworker.ChatUsage{PromptTokens: 10, CompletionTokens: 1},
			UsageReported: true,
		}
		m := &toolLoopModel{results: []*agentworker.ChatResult{call, final}}
		w := &agentworker.PAWorker{
			BaseURL: srv.URL, PoolToken: e.h.PoolToken(), HTTP: srv.Client(), Model: m,
			Prices: agentworker.Prices{InputUSDPerMTok: 1, OutputUSDPerMTok: 1}, Now: e.h.Now,
		}
		c, err := w.Claim(context.Background())
		if err != nil || c == nil {
			t.Fatalf("claim = %v, %v", c, err)
		}
		out, err := w.Run(context.Background(), c)
		if err != nil || out != agentworker.PAReplied {
			t.Fatalf("run = %s, %v", out, err)
		}

		// The model was offered the signed set, described from the pin.
		pin, err := catalog.LoadPin()
		if err != nil {
			t.Fatal(err)
		}
		offered := m.offered[0]
		if len(offered) != 2 || offered[0].Name != "tg__get_messages" || offered[1].Name != "tg__list_dialogs" ||
			offered[1].Description != pin.Servers["tg"].Tools["list_dialogs"].CatalogDescription {
			t.Fatalf("offered %+v", offered)
		}
		// The call ran server-side with Alice's connection, once.
		calls, bearers, _ := e.tg.snapshot()
		if !slices.Equal(calls, []string{"list_dialogs"}) || slices.ContainsFunc(bearers, func(b string) bool { return b != "fake-at-acct-alice" }) {
			t.Fatalf("calls %v bearers %v", calls, bearers)
		}
		if n := e.toolCalls(c.JobID); n != 1 {
			t.Fatalf("tool_calls = %d", n)
		}
		// Its result reached the model as external data.
		var tool *agentworker.ChatMessage
		for i := range m.inputs[1] {
			if m.inputs[1][i].Role == "tool" {
				tool = &m.inputs[1][i]
			}
		}
		if tool == nil || tool.ToolCallID != "c1" || !strings.HasPrefix(tool.Content, `<external_data kind="tool_result">`) ||
			!strings.Contains(tool.Content, "result of list_dialogs") {
			t.Fatalf("tool message = %+v", tool)
		}
		if sent := e.h.SentTo(alice); len(sent) != 1 || !strings.Contains(sent[0], "Bob wrote to you.") {
			t.Fatalf("sent %q", sent)
		}
	})
}
