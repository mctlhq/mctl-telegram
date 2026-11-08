package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
)

func TestRequeueClientFunc_PoolModeUsesJobTokenWithoutAttempt(t *testing.T) {
	var auth, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
	defer srv.Close()
	pool := agentworker.NewClient(srv.URL, "pool-credential", nil)
	f := requeueClientFunc(pool, srv.URL, true)

	if f(agentworker.JobEnvelope{JobID: 1}) != nil {
		t.Fatal("pool job without a job token got a client")
	}
	c := f(agentworker.JobEnvelope{JobID: 1, JobToken: "job-token"})
	if c == nil {
		t.Fatal("pool job with a job token got no client")
	}
	if err := c.RetryJob(context.Background(), 1, 2, "invocation_failed"); err != nil {
		t.Fatalf("RetryJob: %v", err)
	}
	if auth != "Bearer job-token" {
		t.Fatalf("authorization = %q, want the job token, not the pool credential", auth)
	}
	if strings.Contains(body, "attempt") {
		t.Fatalf("job-scoped body carries attempt: %s", body)
	}
}

func TestRequeueClientFunc_OwnModeUsesAccountClient(t *testing.T) {
	account := agentworker.NewClient("http://example.invalid", "acct", nil)
	if got := requeueClientFunc(account, "http://example.invalid", false)(agentworker.JobEnvelope{JobID: 1}); got != account {
		t.Fatal("own mode must use the account client")
	}
}
