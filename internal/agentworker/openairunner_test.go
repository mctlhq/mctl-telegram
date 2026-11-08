package agentworker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpenAIRunner_ToolLoopCompletes(t *testing.T) {
	var completed atomic.Bool
	var cost float64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer job-token" {
			t.Fatalf("agent auth=%q", got)
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/event/e1":
			writeTestJSON(w, map[string]any{"event_id": "e1", "body": "hello"})
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/42/complete":
			completed.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/42/cost":
			var body struct {
				Cost float64 `json:"cost_usd"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			cost = body.Cost
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/jobs/42":
			writeTestJSON(w, map[string]any{"job_id": 42, "status": "ignored", "attempt": 1})
		default:
			t.Fatalf("unexpected agent request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer api.Close()

	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"get_event","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":100,"completion_tokens":10}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c2","type":"function","function":{"name":"complete_agent_job","arguments":"{\"status\":\"ignored\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":50,"completion_tokens":5}}`))
	}))
	defer provider.Close()

	r := &OpenAIRunner{
		Client:     &OpenAIClient{BaseURL: provider.URL, APIKey: "provider", Model: "qwen", HTTP: provider.Client()},
		APIBaseURL: api.URL, MaxTurns: 4,
		Prices: Prices{InputUSDPerMTok: 1, OutputUSDPerMTok: 2},
	}
	job := JobEnvelope{JobID: 42, EventID: "e1", ConversationID: 7, Attempt: 1, JobToken: "job-token", Tools: []string{"get_event", "complete_agent_job"}}
	if err := r.Run(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if !completed.Load() || calls.Load() != 2 {
		t.Fatalf("completed=%v provider_calls=%d", completed.Load(), calls.Load())
	}
	wantCost := (150.0*1 + 15.0*2) / 1_000_000
	if cost != wantCost {
		t.Fatalf("cost=%g want=%g", cost, wantCost)
	}
}

func TestOpenAIRunner_StopsOnCompleted(t *testing.T) {
	var eventCalls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/9/complete":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/9/cost":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/jobs/9":
			writeTestJSON(w, map[string]any{"job_id": 9, "status": "ignored", "attempt": 1})
		case r.Method == http.MethodGet && r.URL.Path == "/event/e":
			eventCalls.Add(1)
			writeTestJSON(w, map[string]any{"event_id": "e"})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer api.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"done","type":"function","function":{"name":"complete_agent_job","arguments":"{\"status\":\"ignored\"}"}},{"id":"late","type":"function","function":{"name":"get_event","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer provider.Close()
	r := &OpenAIRunner{Client: &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()}, APIBaseURL: api.URL}
	if err := r.Run(context.Background(), JobEnvelope{JobID: 9, EventID: "e", Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}}); err != nil {
		t.Fatal(err)
	}
	if eventCalls.Load() != 0 {
		t.Fatalf("tool ran after completion: %d", eventCalls.Load())
	}
}

func TestOpenAIRunner_MaxTurns(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/event/e":
			writeTestJSON(w, map[string]any{"event_id": "e"})
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/1/cost":
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer api.Close()
	var providerCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerCalls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"x","type":"function","function":{"name":"get_event","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer provider.Close()
	r := &OpenAIRunner{Client: &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()}, APIBaseURL: api.URL, MaxTurns: 2}
	err := r.Run(context.Background(), JobEnvelope{JobID: 1, EventID: "e", Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}})
	if !errors.Is(err, ErrClaudeReportedError) {
		t.Fatalf("err=%v", err)
	}
	if n := providerCalls.Load(); n != 2 {
		t.Fatalf("provider calls=%d want exactly MaxTurns=2", n)
	}
}

func TestOpenAIRunner_GivesUpWithinDeadline(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer provider.Close()
	r := &OpenAIRunner{Client: &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()}, APIBaseURL: "http://invalid"}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := r.Run(ctx, JobEnvelope{JobID: 1, Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}})
	// The 1s retry backoff does not fit the 40ms job window, so the runner
	// reports the provider failure at once instead of sleeping into an opaque
	// context deadline.
	if !errors.Is(err, ErrClaudeReportedError) {
		t.Fatalf("err=%v want a provider error result", err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("runner exceeded deadline by too much: %v", time.Since(start))
	}
}

func TestOpenAIRunner_UsesJobTokenOnly(t *testing.T) {
	// The happy-path test asserts every per-job API call carries job-token.
	// This test guards the fail-closed half: no job token means no provider or
	// API request at all.
	r := &OpenAIRunner{Client: &OpenAIClient{BaseURL: "http://invalid", APIKey: "k", Model: "m"}, APIBaseURL: "http://invalid"}
	if err := r.Run(context.Background(), JobEnvelope{JobID: 1}); !errors.Is(err, errNoJobToken) {
		t.Fatalf("err=%v", err)
	}
}

// completionTestAPI serves the per-job API for the completion tests. The job
// status stays "processing" until complete_agent_job is called, as on a real
// server.
func completionTestAPI(t *testing.T, jobID string, completed *atomic.Bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/"+jobID+"/complete":
			completed.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/"+jobID+"/cost":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/jobs/"+jobID:
			status := "processing"
			if completed.Load() {
				status = "ignored"
			}
			writeTestJSON(w, map[string]any{"job_id": 5, "status": status, "attempt": 1})
		default:
			t.Fatalf("unexpected agent request %s %s", r.Method, r.URL.Path)
		}
	}))
}

func TestOpenAIRunner_NudgesOnceThenCompletes(t *testing.T) {
	var completed atomic.Bool
	api := completionTestAPI(t, "5", &completed)
	defer api.Close()
	var calls atomic.Int32
	var sawNudge atomic.Bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"no reply needed"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":3}}`))
			return
		}
		var req struct {
			Messages []ChatMessage `json:"messages"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if last := req.Messages[len(req.Messages)-1]; last.Role == "user" && last.Content == completionNudge {
			sawNudge.Store(true)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c","type":"function","function":{"name":"complete_agent_job","arguments":"{\"status\":\"ignored\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":12,"completion_tokens":4}}`))
	}))
	defer provider.Close()
	r := &OpenAIRunner{Client: &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()}, APIBaseURL: api.URL, MaxTurns: 4}
	if err := r.Run(context.Background(), JobEnvelope{JobID: 5, EventID: "e", Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}}); err != nil {
		t.Fatalf("a reply without a tool call must be nudged within the same attempt: %v", err)
	}
	if calls.Load() != 2 || !completed.Load() || !sawNudge.Load() {
		t.Fatalf("provider_calls=%d completed=%v nudge_sent=%v", calls.Load(), completed.Load(), sawNudge.Load())
	}
}

func TestOpenAIRunner_NudgesOnlyOnce(t *testing.T) {
	var completed atomic.Bool
	api := completionTestAPI(t, "5", &completed)
	defer api.Close()
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"still text"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":3}}`))
	}))
	defer provider.Close()
	r := &OpenAIRunner{Client: &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()}, APIBaseURL: api.URL, MaxTurns: 8}
	err := r.Run(context.Background(), JobEnvelope{JobID: 5, EventID: "e", Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}})
	if !errors.Is(err, ErrAgentDidNotCompleteJob) {
		t.Fatalf("err=%v want ErrAgentDidNotCompleteJob after the single nudge", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("provider calls=%d want exactly 2 (reply, one nudge)", calls.Load())
	}
}

func TestOpenAIRunner_TruncatedReplyIsExplicit(t *testing.T) {
	var completed atomic.Bool
	api := completionTestAPI(t, "5", &completed)
	defer api.Close()
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) > 1 {
			// A later plain "stop" reply must never be reached: it would
			// mask the truncation as a success.
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"fine"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"cut o"},"finish_reason":"length"}],"usage":{"prompt_tokens":10,"completion_tokens":4096}}`))
	}))
	defer provider.Close()
	r := &OpenAIRunner{Client: &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()}, APIBaseURL: api.URL, MaxTurns: 8}
	err := r.Run(context.Background(), JobEnvelope{JobID: 5, EventID: "e", Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}})
	if !errors.Is(err, ErrClaudeReportedError) || !strings.Contains(err.Error(), "error_output_truncated") {
		t.Fatalf("err=%v want an explicit error_output_truncated result", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("provider calls=%d want 1: a truncated reply is not nudged", calls.Load())
	}
}

func TestOpenAIRunner_MissingUsageDoesNotPanicTurnLog(t *testing.T) {
	// A provider may omit "usage" (null or absent). The per-turn log reads the
	// token count from a value field, so it must log zero and carry on.
	for _, usage := range []string{``, `,"usage":null`} {
		var completed atomic.Bool
		api := completionTestAPI(t, "5", &completed)
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c","type":"function","function":{"name":"complete_agent_job","arguments":"{\"status\":\"ignored\"}"}}]},"finish_reason":"tool_calls"}]` + usage + `}`))
		}))
		r := &OpenAIRunner{Client: &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()}, APIBaseURL: api.URL, MaxTurns: 2}
		err := r.Run(context.Background(), JobEnvelope{JobID: 5, EventID: "e", Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}})
		provider.Close()
		api.Close()
		if err != nil || !completed.Load() {
			t.Fatalf("usage=%q err=%v completed=%v", usage, err, completed.Load())
		}
	}
}

func TestSummarizeToolCalls_KeepsOnlyNamesAndStatusEnum(t *testing.T) {
	names, status := summarizeToolCalls([]ToolCall{
		{Name: "get_event", Arguments: `{"event_id":"secret-body"}`},
		{Name: "complete_agent_job", Arguments: `{"status":"ignored"}`},
	})
	if len(names) != 2 || names[0] != "get_event" || status != "ignored" {
		t.Fatalf("names=%v status=%q", names, status)
	}
	if _, st := summarizeToolCalls([]ToolCall{{Name: "complete_agent_job", Arguments: `{"status":"free text from the model"}`}}); st != "other" {
		t.Fatalf("a non-enum status must be reported as other, got %q", st)
	}
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
