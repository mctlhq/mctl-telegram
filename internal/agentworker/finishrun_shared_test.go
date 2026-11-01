package agentworker

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/audit"
)

// finishRunFake serves the Agent API endpoints finishRun touches and records
// the cost reports it receives.
type finishRunFake struct {
	mu    sync.Mutex
	costs []float64
}

func newFinishRunFake(t *testing.T, status string, attempt int) (*httptest.Server, *finishRunFake) {
	t.Helper()
	f := &finishRunFake{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/jobs/42":
			writeJSONFixture(w, JobStatus{JobID: 42, Status: status, Attempt: attempt})
		case r.Method == http.MethodGet && r.URL.Path == "/event/e":
			writeJSONFixture(w, map[string]any{"event_id": "e"})
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/42/cost":
			var b struct {
				CostUSD float64 `json:"cost_usd"`
			}
			_ = json.NewDecoder(r.Body).Decode(&b)
			f.mu.Lock()
			f.costs = append(f.costs, b.CostUSD)
			f.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, f
}

// TestFinishRun_SharedByBothRunners drives ClaudeInvoker and OpenAIRunner
// through identical scenarios and requires identical outcomes: cost reported
// before the result check, result classification, and durable terminal-state
// verification (status and attempt). A runner that grows its own tail and
// skips any of these diverges here.
func TestFinishRun_SharedByBothRunners(t *testing.T) {
	const claudeOK = `{"type":"result","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.25}`
	const claudeErr = `{"type":"result","subtype":"error_max_turns","is_error":true,"num_turns":1,"total_cost_usd":0.25}`
	const textReply = `{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":250000,"completion_tokens":0}}`
	const toolReply = `{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"x","type":"function","function":{"name":"get_event","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":250000,"completion_tokens":0}}`

	cases := []struct {
		name       string
		status     string
		attempt    int
		claudeOut  string
		openaiOut  string
		maxTurns   int
		wantErr    error
		wantReport bool
	}{
		{"terminal and same attempt", "completed", 1, claudeOK, textReply, 0, nil, true},
		{"job left non-terminal", "processing", 1, claudeOK, textReply, 0, ErrAgentDidNotCompleteJob, true},
		{"completed by a different attempt", "completed", 2, claudeOK, textReply, 0, ErrAgentDidNotCompleteJob, true},
		{"runner reports an error, cost still recorded", "completed", 1, claudeErr, toolReply, 1, ErrClaudeReportedError, true},
	}
	for _, tc := range cases {
		check := func(t *testing.T, err error, f *finishRunFake) {
			t.Helper()
			if tc.wantErr == nil && err != nil {
				t.Fatalf("err=%v want nil", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v want %v", err, tc.wantErr)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if tc.wantReport && (len(f.costs) != 1 || f.costs[0] != 0.25) {
				t.Fatalf("cost reports=%v want [0.25]", f.costs)
			}
		}
		t.Run("claude/"+tc.name, func(t *testing.T) {
			bin, _, _, _ := fakeClaudeScript(t, tc.claudeOut, 0)
			srv, f := newFinishRunFake(t, tc.status, tc.attempt)
			inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/agent-worker", APIBaseURL: srv.URL, APIToken: "tok"}
			check(t, inv.Run(context.Background(), JobEnvelope{JobID: 42, Attempt: 1}), f)
		})
		t.Run("openai/"+tc.name, func(t *testing.T) {
			srv, f := newFinishRunFake(t, tc.status, tc.attempt)
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.openaiOut))
			}))
			defer provider.Close()
			r := &OpenAIRunner{
				Client:     &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()},
				APIBaseURL: srv.URL, MaxTurns: tc.maxTurns, Prices: Prices{InputUSDPerMTok: 1},
			}
			job := JobEnvelope{JobID: 42, EventID: "e", Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}}
			check(t, r.Run(context.Background(), job), f)
		})
	}
}

// TestOpenAIRunner_LogsCarryNoContent runs a job whose prompt, tool arguments,
// provider error body and credentials all contain sentinels, with the
// production redacting handler as the default logger, and requires none of
// them in the log output.
func TestOpenAIRunner_LogsCarryNoContent(t *testing.T) {
	sentinels := []string{"SENT-PROMPT", "SENT-ARGS", "SENT-BODY", "SENT-APIKEY", "SENT-GATEWAY"}
	var buf syncBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(audit.NewRedactingHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	t.Cleanup(func() { slog.SetDefault(prev) })

	srv, _ := newFinishRunFake(t, "completed", 1)
	var calls int
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"x","type":"function","function":{"name":"get_event","arguments":"{\"q\":\"SENT-ARGS\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("SENT-BODY"))
	}))
	defer provider.Close()
	r := &OpenAIRunner{
		Client:     &OpenAIClient{BaseURL: provider.URL, APIKey: "SENT-APIKEY", GatewayToken: "SENT-GATEWAY", Model: "m", HTTP: provider.Client()},
		APIBaseURL: srv.URL, MaxTurns: 3,
	}
	_ = r.Run(context.Background(), JobEnvelope{JobID: 42, EventID: "e", Attempt: 1, JobToken: "j",
		Instructions: "SENT-PROMPT", Tools: []string{"get_event", "complete_agent_job"}})
	out := buf.String()
	for _, s := range sentinels {
		if strings.Contains(out, s) {
			t.Fatalf("log output carries %s: %s", s, out)
		}
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
