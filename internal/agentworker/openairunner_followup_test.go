package agentworker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestOpenAIClient_DefaultUserAgent(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "mctl-telegram-agent-worker" {
			t.Fatalf("User-Agent=%q want mctl-telegram-agent-worker", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`))
	}))
	defer provider.Close()

	c := &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()}
	if _, err := c.Chat(context.Background(), []ChatMessage{{Role: "user", Content: "hi"}}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestOpenAIRunner_RetryAfterBeyondDeadlineReturnsProvider429(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer provider.Close()

	r := &OpenAIRunner{
		Client:     &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()},
		APIBaseURL: "http://127.0.0.1:1",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	err := r.Run(ctx, JobEnvelope{JobID: 21, Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}})
	if !errors.Is(err, ErrClaudeUsageLimit) {
		t.Fatalf("err=%v want ErrClaudeUsageLimit", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("runner slept through Retry-After despite shorter deadline: %v", elapsed)
	}
}

func TestOpenAIRunner_CanceledRunReportsObservedCost(t *testing.T) {
	var reported atomic.Int32
	var gotCost float64
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/event/e":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"event_id": "e", "body": "hello"})
		case r.Method == http.MethodPost && r.URL.Path == "/jobs/22/cost":
			var body struct {
				Attempt int     `json:"attempt"`
				Cost    float64 `json:"cost_usd"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body.Attempt != 1 {
				t.Fatalf("attempt=%d want 1", body.Attempt)
			}
			gotCost = body.Cost
			reported.Add(1)
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
		// Drain the request body first: net/http only watches for the client
		// disconnect (and so cancels r.Context()) once the body is consumed.
		// Without this the handler outlives the canceled request and
		// httptest.Server.Close blocks forever.
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer provider.Close()

	r := &OpenAIRunner{
		Client:     &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()},
		APIBaseURL: api.URL,
		Prices:     Prices{InputUSDPerMTok: 1, OutputUSDPerMTok: 2},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	err := r.Run(ctx, JobEnvelope{JobID: 22, EventID: "e", Attempt: 1, JobToken: "j", Tools: []string{"get_event", "complete_agent_job"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v want context deadline exceeded", err)
	}
	if reported.Load() != 1 {
		t.Fatalf("cost reports=%d want 1", reported.Load())
	}
	want := (100.0*1 + 10.0*2) / 1_000_000
	if gotCost != want {
		t.Fatalf("cost=%g want %g", gotCost, want)
	}
}
