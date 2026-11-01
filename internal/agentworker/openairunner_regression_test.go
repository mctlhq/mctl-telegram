package agentworker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpenAIRunner_BudgetStop(t *testing.T) {
	var costReports atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/jobs/7/cost" {
			costReports.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		t.Fatalf("unexpected agent request %s %s", r.Method, r.URL.Path)
	}))
	defer api.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"stop"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":1000}}`))
	}))
	defer provider.Close()
	r := &OpenAIRunner{
		Client:     &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()},
		APIBaseURL: api.URL, MaxBudgetUSD: 0.0001,
		Prices: Prices{InputUSDPerMTok: 1, OutputUSDPerMTok: 1},
	}
	err := r.Run(context.Background(), JobEnvelope{JobID: 7, Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}})
	if !errors.Is(err, ErrClaudeReportedError) {
		t.Fatalf("err=%v want ErrClaudeReportedError", err)
	}
	if costReports.Load() != 1 {
		t.Fatalf("cost reports=%d want 1", costReports.Load())
	}
}

func TestOpenAIRunner_Retry429HonoursRetryAfter(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/8/complete":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/8/cost":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/jobs/8":
			writeTestJSON(w, map[string]any{"job_id": 8, "status": "ignored", "attempt": 1})
		default:
			t.Fatalf("unexpected agent request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer api.Close()
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("secret provider body"))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"done","type":"function","function":{"name":"complete_agent_job","arguments":"{\"status\":\"ignored\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer provider.Close()
	r := &OpenAIRunner{Client: &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()}, APIBaseURL: api.URL}
	start := time.Now()
	if err := r.Run(context.Background(), JobEnvelope{JobID: 8, Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("provider calls=%d want 2", calls.Load())
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond {
		t.Fatalf("Retry-After was not honoured: elapsed=%v", elapsed)
	}
}

func TestOpenAIRunner_NoSharedStateAcrossJobs(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && (r.URL.Path == "/jobs/11/complete" || r.URL.Path == "/jobs/12/complete"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && (r.URL.Path == "/jobs/11/cost" || r.URL.Path == "/jobs/12/cost"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/jobs/11":
			writeTestJSON(w, map[string]any{"job_id": 11, "status": "ignored", "attempt": 1})
		case r.Method == http.MethodGet && r.URL.Path == "/jobs/12":
			writeTestJSON(w, map[string]any{"job_id": 12, "status": "ignored", "attempt": 1})
		default:
			t.Fatalf("unexpected agent request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer api.Close()
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"done","type":"function","function":{"name":"complete_agent_job","arguments":"{\"status\":\"ignored\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer provider.Close()
	r := &OpenAIRunner{Client: &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()}, APIBaseURL: api.URL}
	for _, id := range []int64{11, 12} {
		if err := r.Run(context.Background(), JobEnvelope{JobID: id, Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}}); err != nil {
			t.Fatalf("job %d: %v", id, err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("provider calls=%d want 2; completion state leaked across jobs", calls.Load())
	}
}

func TestOpenAIRunner_Provider429ClassifiesAsUsageLimit(t *testing.T) {
	cost := 0.0
	res := &ClaudeResult{Subtype: "error_provider_429", IsError: true, TotalCostUSD: &cost}
	if err := CheckResult(res); !errors.Is(err, ErrClaudeUsageLimit) {
		t.Fatalf("err=%v want ErrClaudeUsageLimit", err)
	}
}
