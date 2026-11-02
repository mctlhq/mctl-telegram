package agentworker

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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

// authRecorder records the Authorization header of every request.
func authRecorder(t *testing.T, jobID int64) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		if r.Method == http.MethodGet {
			writeJSONFixture(w, JobStatus{JobID: jobID, Status: "completed", Attempt: 1})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

func TestFinishRun_PoolMode_UsesJobToken(t *testing.T) {
	stdout := `{"type":"result","subtype":"success","is_error":false,"num_turns":1,"total_cost_usd":0.5}`
	bin, _, _, _ := fakeClaudeScript(t, stdout, 0)
	srv, seen := authRecorder(t, 42)
	inv := &ClaudeInvoker{ClaudeBin: bin, Self: "/bin/true", APIBaseURL: srv.URL, APIToken: "pool-token", PoolMode: true}
	if err := inv.Run(context.Background(), JobEnvelope{JobID: 42, Attempt: 1, JobToken: "job-token"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := seen()
	if len(got) == 0 {
		t.Fatal("no worker-side API calls observed")
	}
	for _, h := range got {
		if h != "Bearer job-token" {
			t.Fatalf("worker-side call used %q, want the job token", h)
		}
	}
}
