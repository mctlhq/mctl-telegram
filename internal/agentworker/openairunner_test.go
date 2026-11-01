package agentworker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
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
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"x","type":"function","function":{"name":"get_event","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer provider.Close()
	r := &OpenAIRunner{Client: &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()}, APIBaseURL: api.URL, MaxTurns: 2}
	err := r.Run(context.Background(), JobEnvelope{JobID: 1, EventID: "e", Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}})
	if !errors.Is(err, ErrClaudeReportedError) {
		t.Fatalf("err=%v", err)
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

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
