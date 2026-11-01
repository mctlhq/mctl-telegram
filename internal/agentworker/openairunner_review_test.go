package agentworker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The job token expires at the claim deadline, which is also when a deadline
// cancellation fires. This fake API enforces that: /cost is accepted only
// with the account token, so a runner that reports with the job token loses
// the spend (the P2 on PR #1100).
func TestOpenAIRunner_DeadlineCancelReportsCostWithAccountToken(t *testing.T) {
	var accepted, rejected atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/event/e":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"event_id": "e", "body": "hello"})
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/23/cost":
			if r.Header.Get("Authorization") != "Bearer account-token" {
				rejected.Add(1)
				w.WriteHeader(http.StatusUnauthorized) // expired job token
				return
			}
			accepted.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected agent request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer api.Close()

	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"get_event","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":100,"completion_tokens":10}}`))
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer provider.Close()

	r := &OpenAIRunner{
		Client:     &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()},
		APIBaseURL: api.URL, APIToken: "account-token",
		Prices: Prices{InputUSDPerMTok: 1, OutputUSDPerMTok: 2},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	err := r.Run(ctx, JobEnvelope{JobID: 23, EventID: "e", Attempt: 1, JobToken: "job-token", Tools: []string{"get_event", "complete_agent_job"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v want context deadline exceeded", err)
	}
	if accepted.Load() != 1 || rejected.Load() != 0 {
		t.Fatalf("cost accepted=%d rejected(job token)=%d, want 1/0", accepted.Load(), rejected.Load())
	}
}

// A queued waiter must leave through its own context, not wait for every
// sleeper ahead of it (waitForTurn used to sleep while holding rateMu).
func TestOpenAIRunner_WaitForTurnCancelDoesNotQueueBehindSleepers(t *testing.T) {
	r := &OpenAIRunner{MinInterval: 400 * time.Millisecond}
	if err := r.waitForTurn(context.Background()); err != nil {
		t.Fatal(err)
	}
	sleeper := make(chan error, 1)
	go func() { sleeper <- r.waitForTurn(context.Background()) }() // reserves the +400ms slot and sleeps
	time.Sleep(30 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := r.waitForTurn(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v want deadline exceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("cancelled waiter took %v; it queued behind the sleeper", elapsed)
	}
	if err := <-sleeper; err != nil {
		t.Fatalf("sleeper err=%v", err)
	}
}

// Spacing must survive the reservation rewrite: back-to-back turns are
// MinInterval apart.
func TestOpenAIRunner_WaitForTurnSpacesRequests(t *testing.T) {
	r := &OpenAIRunner{MinInterval: 60 * time.Millisecond}
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := r.waitForTurn(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 110*time.Millisecond {
		t.Fatalf("3 turns took %v, want >= 2 intervals", elapsed)
	}
}

func noUsageRunner(t *testing.T, budget float64) (*OpenAIRunner, *atomic.Int32, func()) {
	t.Helper()
	var costs atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/cost"):
			costs.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/jobs/31":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"job_id":31,"attempt":1,"status":"completed"}`))
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	r := &OpenAIRunner{
		Client:     &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()},
		APIBaseURL: api.URL, MaxBudgetUSD: budget,
		Prices: Prices{InputUSDPerMTok: 1, OutputUSDPerMTok: 2},
	}
	return r, &costs, func() { api.Close(); provider.Close() }
}

func TestOpenAIRunner_MissingUsageFailsClosedWhenBudgetSet(t *testing.T) {
	r, costs, done := noUsageRunner(t, 1.0)
	defer done()
	err := r.Run(context.Background(), JobEnvelope{JobID: 31, EventID: "e", Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}})
	if err == nil || !strings.Contains(err.Error(), "error_provider_no_usage") {
		t.Fatalf("err=%v want error_provider_no_usage", err)
	}
	if costs.Load() != 0 {
		t.Fatalf("a fabricated $0 cost was reported %d times", costs.Load())
	}
}

func TestOpenAIRunner_MissingUsageWithoutBudgetDoesNotReportZeroCost(t *testing.T) {
	r, costs, done := noUsageRunner(t, 0)
	defer done()
	if err := r.Run(context.Background(), JobEnvelope{JobID: 31, EventID: "e", Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}}); err != nil {
		t.Fatal(err)
	}
	if costs.Load() != 0 {
		t.Fatalf("cost reported %d times for unknown spend", costs.Load())
	}
}

// The two entries previously added from init() in separate files now live in
// the existing literals; assert the classifier still knows the token.
func TestUsageLimitSubtypes_IncludesProvider429(t *testing.T) {
	if !isUsageLimitSubtype("error_provider_429") {
		t.Fatal("error_provider_429 must classify as a usage limit")
	}
}

// With the account token configured, model-reachable tool routes must still
// carry the conversation-bound job token; only /cost and the terminal-state
// GET carry the account token. Swapping buildToolSet onto the worker client
// would silently widen what the model can reach.
func TestOpenAIRunner_ToolRoutesKeepJobTokenWhenAccountTokenSet(t *testing.T) {
	seen := map[string]string{}
	var mu sync.Mutex
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Method+" "+r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/event/e1":
			writeTestJSON(w, map[string]any{"event_id": "e1", "body": "hello"})
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/42/complete", r.Method == http.MethodPost && r.URL.Path == "/jobs/42/cost":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/jobs/42":
			writeTestJSON(w, map[string]any{"job_id": 42, "status": "ignored", "attempt": 1})
		default:
			t.Errorf("unexpected agent request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer api.Close()
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"get_event","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c2","type":"function","function":{"name":"complete_agent_job","arguments":"{\"status\":\"ignored\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer provider.Close()
	r := &OpenAIRunner{
		Client:     &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()},
		APIBaseURL: api.URL, APIToken: "account-token", MaxTurns: 4,
	}
	job := JobEnvelope{JobID: 42, EventID: "e1", ConversationID: 7, Attempt: 1, JobToken: "job-token", Tools: []string{"get_event", "complete_agent_job"}}
	if err := r.Run(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"GET /event/e1":          "Bearer job-token",
		"POST /jobs/42/complete": "Bearer job-token",
		"POST /jobs/42/cost":     "Bearer account-token",
		"GET /jobs/42":           "Bearer account-token",
	}
	mu.Lock()
	defer mu.Unlock()
	for route, auth := range want {
		if seen[route] != auth {
			t.Errorf("%s auth=%q want %q", route, seen[route], auth)
		}
	}
}
