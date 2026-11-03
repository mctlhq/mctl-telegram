package agentworker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
)

func TestClaudeInvoker_PoolMode_NoFallback(t *testing.T) {
	inv := &ClaudeInvoker{APIBaseURL: "http://invalid", APIToken: "pool-token", PoolMode: true}
	if got := inv.mcpToken(JobEnvelope{}); got != "" {
		t.Fatalf("pool mode fell back to the pool token: %q", got)
	}
	if got := inv.mcpToken(JobEnvelope{JobToken: "job-token"}); got != "job-token" {
		t.Fatalf("mcpToken = %q", got)
	}
	if err := inv.Run(context.Background(), JobEnvelope{JobID: 1}); !errors.Is(err, errNoJobToken) {
		t.Fatalf("Run without a job token: %v, want errNoJobToken", err)
	}
}

func TestClaudeInvoker_OwnMode_Unchanged(t *testing.T) {
	inv := &ClaudeInvoker{APIToken: "account-token"}
	if got := inv.mcpToken(JobEnvelope{}); got != "account-token" {
		t.Fatalf("own mode must fall back to the account token, got %q", got)
	}
}

// workerCall is one request a runner sent to the agent API.
type workerCall struct{ method, path, auth string }

// authRecorder records every request the worker sends to the agent API and
// answers the per-job routes finishRun and a one-turn OpenAI run use.
func authRecorder(t *testing.T, jobID int64) (*httptest.Server, func() []workerCall) {
	t.Helper()
	var mu sync.Mutex
	var seen []workerCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, workerCall{r.Method, r.URL.Path, r.Header.Get("Authorization")})
		mu.Unlock()
		if r.Method == http.MethodGet {
			writeJSONFixture(w, JobStatus{JobID: jobID, Status: "ignored", Attempt: 1})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []workerCall { mu.Lock(); defer mu.Unlock(); return append([]workerCall(nil), seen...) }
}

// assertWorkerCalls checks that the worker-side status and cost calls were
// made, and that every call carried want.
func assertWorkerCalls(t *testing.T, calls []workerCall, jobID int64, want string) {
	t.Helper()
	status, cost := false, false
	for _, c := range calls {
		if c.auth != "Bearer "+want {
			t.Errorf("%s %s used %q, want the %s", c.method, c.path, c.auth, want)
		}
		status = status || (c.method == http.MethodGet && c.path == "/jobs/"+strconv.FormatInt(jobID, 10))
		cost = cost || (c.method == http.MethodPost && c.path == "/jobs/"+strconv.FormatInt(jobID, 10)+"/cost")
	}
	if !status || !cost {
		t.Fatalf("worker calls %+v: GET /jobs/%d seen=%v, POST /jobs/%d/cost seen=%v", calls, jobID, status, jobID, cost)
	}
}

// T15 (Claude runner): in pool mode GetJobStatus and ReportJobCost run on the
// job token. Mutation: keep APIToken for the finishRun client in pool mode.
func TestFinishRun_PoolMode_UsesJobToken(t *testing.T) {
	stdout := `{"type":"result","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.5}`
	bin, _, _, _ := fakeClaudeScript(t, stdout, 0)
	srv, seen := authRecorder(t, 42)
	inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/true", APIBaseURL: srv.URL, APIToken: "pool-token", PoolMode: true}
	if err := inv.Run(context.Background(), JobEnvelope{JobID: 42, Attempt: 1, JobToken: "job-token"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertWorkerCalls(t, seen(), 42, "job-token")
}

// Own mode keeps the account token for the Claude runner's worker calls.
func TestFinishRun_OwnMode_UsesAccountToken(t *testing.T) {
	stdout := `{"type":"result","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.5}`
	bin, _, _, _ := fakeClaudeScript(t, stdout, 0)
	srv, seen := authRecorder(t, 43)
	inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/true", APIBaseURL: srv.URL, APIToken: "account-token"}
	if err := inv.Run(context.Background(), JobEnvelope{JobID: 43, Attempt: 1, JobToken: "job-token"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertWorkerCalls(t, seen(), 43, "account-token")
}

// oneTurnProvider is an OpenAI-compatible endpoint whose model completes the
// job as ignored on its first turn.
func oneTurnProvider(t *testing.T) *httptest.Server {
	t.Helper()
	p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"complete_agent_job","arguments":"{\"status\":\"ignored\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":1}}`))
	}))
	t.Cleanup(p.Close)
	return p
}

// T15 (OpenAI runner): in pool mode the worker-side status and cost calls use
// the job token, never the pool credential in APIToken, and a job without a
// token is refused before any call. Mutation: drop "&& !r.PoolMode" in
// OpenAIRunner.Run.
func TestOpenAIRunner_PoolMode_UsesJobTokenForWorkerCalls(t *testing.T) {
	provider := oneTurnProvider(t)
	srv, seen := authRecorder(t, 44)
	r := &OpenAIRunner{
		Client:     &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()},
		APIBaseURL: srv.URL, APIToken: "pool-token", PoolMode: true, MaxTurns: 2,
	}
	if err := r.Run(context.Background(), JobEnvelope{JobID: 44, Attempt: 1, JobToken: "job-token", Tools: []string{"get_event", "complete_agent_job"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertWorkerCalls(t, seen(), 44, "job-token")
	if err := r.Run(context.Background(), JobEnvelope{JobID: 45}); !errors.Is(err, errNoJobToken) {
		t.Fatalf("pool-mode run without a job token: %v, want errNoJobToken", err)
	}
}

// Own mode keeps the account token for the OpenAI runner's worker calls.
func TestOpenAIRunner_OwnMode_UsesAccountToken(t *testing.T) {
	provider := oneTurnProvider(t)
	srv, seen := authRecorder(t, 46)
	r := &OpenAIRunner{
		Client:     &OpenAIClient{BaseURL: provider.URL, APIKey: "k", Model: "m", HTTP: provider.Client()},
		APIBaseURL: srv.URL, APIToken: "account-token", MaxTurns: 2,
	}
	if err := r.Run(context.Background(), JobEnvelope{JobID: 46, Attempt: 1, JobToken: "job-token", Tools: []string{"get_event", "complete_agent_job"}}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var worker []workerCall
	for _, c := range seen() {
		if c.path == "/jobs/46" || c.path == "/jobs/46/cost" {
			worker = append(worker, c)
		} else if c.auth != "Bearer job-token" {
			t.Errorf("model tool call %s %s used %q, want the job token", c.method, c.path, c.auth)
		}
	}
	assertWorkerCalls(t, worker, 46, "account-token")
}
