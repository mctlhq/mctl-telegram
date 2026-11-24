package pa_test

// A streamed run with a tool call, end to end (#1431): the real worker,
// the real run loop and the real connector dispatcher over HTTP, on SQLite
// and on Postgres. The chat shows the tool's status, then the growing
// answer, then exactly the message the same run sends without streaming.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// streamLoopModel is toolLoopModel that can stream: a streamed call hands
// its text to onText word by word, with a pause the drafts can use.
type streamLoopModel struct {
	toolLoopModel
	streamed int
}

func (m *streamLoopModel) ChatPAStream(ctx context.Context, msgs []agentworker.ChatMessage, tools []agentworker.PAModelTool, onText func(string)) (*agentworker.ChatResult, error) {
	res, err := m.ChatPA(ctx, msgs, tools)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.streamed++
	m.mu.Unlock()
	acc := ""
	for _, w := range strings.SplitAfter(res.Message.Content, " ") {
		if w == "" {
			continue
		}
		acc += w
		onText(acc)
		time.Sleep(15 * time.Millisecond)
	}
	return res, nil
}

type streamedToolRun struct {
	sent      []string
	drafts    []string
	streamed  int
	calls     []string
	toolCalls int
	fragments int
	outbox    int
	usage     int
}

func runStreamedToolLoop(t *testing.T, s *db.Store, flag string) streamedToolRun {
	t.Helper()
	const answer = "Bob wrote to you about https://example.org/plan and https://evil.example/x today. That is all of it."
	opt, drafts := pa.WithStreaming(flag)
	e := newDispatchEnv(t, s, opt)
	e.h.NoDraftPause()
	e.h.Consent(alice)
	e.h.Text(alice, "who wrote to me about https://example.org/plan ?")
	mux := http.NewServeMux()
	e.h.Loop().Mount(mux)
	e.d.Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	usage := agentworker.ChatUsage{PromptTokens: 10_000, CompletionTokens: 1_000}
	m := &streamLoopModel{toolLoopModel: toolLoopModel{results: []*agentworker.ChatResult{
		{
			Message: agentworker.ChatMessage{Role: "assistant", ToolCalls: []agentworker.ToolCall{
				{ID: "c1", Name: "tg__get_messages", Arguments: `{"chat":"Secret Plans with Carol"}`}}},
			Usage: usage, UsageReported: true,
		},
		{Message: agentworker.ChatMessage{Role: "assistant", Content: answer}, Usage: usage, UsageReported: true},
	}}}
	w := &agentworker.PAWorker{
		BaseURL: srv.URL, PoolToken: e.h.PoolToken(), HTTP: srv.Client(), Model: m,
		Prices: agentworker.Prices{InputUSDPerMTok: 1, OutputUSDPerMTok: 1}, Now: e.h.Now,
		Streaming: true, DraftInterval: time.Millisecond, DraftDelta: 1,
	}
	c, err := w.Claim(context.Background())
	if err != nil || c == nil {
		t.Fatalf("claim = %v, %v", c, err)
	}
	if c.Streaming != (flag == "true") {
		t.Fatalf("claim streaming = %v with the flag %q", c.Streaming, flag)
	}
	out, err := w.Run(context.Background(), c)
	if err != nil || out != agentworker.PAReplied {
		t.Fatalf("run = %s, %v", out, err)
	}
	res := streamedToolRun{sent: e.h.SentTo(alice)}
	// Whatever is sent after the reply was queued would show here.
	time.Sleep(50 * time.Millisecond)
	res.drafts = drafts.Texts()
	m.mu.Lock()
	res.streamed = m.streamed
	m.mu.Unlock()
	res.calls, _, _ = e.tg.snapshot()
	res.toolCalls = e.toolCalls(c.JobID)
	res.fragments = e.h.Count(`SELECT count(*) FROM pa_fragments`)
	res.outbox = e.h.Count(`SELECT count(*) FROM pa_outbox`)
	res.usage = e.h.Count(`SELECT count(*) FROM pa_usage WHERE status = 'settled' AND reported_cost_usd > 0.0219 AND reported_cost_usd < 0.0221`)
	return res
}

func TestStreamingE2E_ToolStatusThenAnswer(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		on := runStreamedToolLoop(t, s, "true")
		if on.streamed != 2 {
			t.Fatalf("streamed model calls = %d, want 2", on.streamed)
		}
		status := safetext.TextStatusReadingMessages.String()
		if len(on.drafts) < 3 || on.drafts[0] != status {
			t.Fatalf("drafts %q; want the tool status first, then the answer", on.drafts)
		}
		if len(on.sent) != 1 {
			t.Fatalf("sent %q, want one message", on.sent)
		}
		final := on.sent[0]
		if !strings.Contains(final, "https://example.org/plan") || strings.Contains(final, "://evil") {
			t.Fatalf("sent %q", final)
		}
		grew := false
		for i, d := range on.drafts {
			// Nothing of the call reaches the chat.
			if strings.Contains(d, "Secret") || strings.Contains(d, "Carol") || strings.Contains(d, "get_messages") {
				t.Fatalf("draft %d shows the call: %q", i, d)
			}
			if d == status {
				if grew {
					t.Fatalf("the tool status came back over the answer: %q", on.drafts)
				}
				continue
			}
			grew = true
			if !strings.HasPrefix(final, strings.TrimRight(d, " ")) {
				t.Fatalf("draft %d %q is not a prefix of the answer %q", i, d, final)
			}
			if strings.Contains(d, "://evil") || strings.Contains(d, "evil.example") {
				t.Fatalf("draft %d shows a link the principal did not type: %q", i, d)
			}
		}
		if !grew {
			t.Fatalf("no draft of the answer: %q", on.drafts)
		}
		if !slices.Equal(on.calls, []string{"get_messages"}) || on.toolCalls != 1 {
			t.Fatalf("calls %v, tool_calls %d", on.calls, on.toolCalls)
		}
		if on.outbox != 1 || on.usage != 1 {
			t.Fatalf("outbox rows %d, settled usage rows at 0.022: %d; want 1 and 1", on.outbox, on.usage)
		}
	})
}

// TestStreamingE2E_ToolRunSameAsWithoutStreaming: the same run with the
// flag off sends the same message and leaves the same rows. Each run has
// its own store of the same dialect.
func TestStreamingE2E_ToolRunSameAsWithoutStreaming(t *testing.T) {
	compare := func(t *testing.T, open func(*testing.T) *db.Store) {
		on := runStreamedToolLoop(t, open(t), "true")
		off := runStreamedToolLoop(t, open(t), "false")
		if off.streamed != 0 || len(off.drafts) != 0 {
			t.Fatalf("flag off: streamed %d, drafts %q", off.streamed, off.drafts)
		}
		if len(on.sent) != 1 || !slices.Equal(on.sent, off.sent) {
			t.Fatalf("sent %q with streaming, %q without", on.sent, off.sent)
		}
		if on.fragments != off.fragments || on.outbox != off.outbox || on.usage != off.usage || on.toolCalls != off.toolCalls || !slices.Equal(on.calls, off.calls) {
			t.Fatalf("with streaming %+v, without %+v", on, off)
		}
	}
	t.Run("sqlite", func(t *testing.T) { compare(t, sqliteStore) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		compare(t, func(t *testing.T) *db.Store { return postgresStore(t, dsn) })
	})
}
