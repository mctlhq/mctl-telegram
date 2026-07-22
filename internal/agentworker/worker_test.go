package agentworker

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakePoller struct {
	mu    sync.Mutex
	calls int
	// results[i] is returned on the i-th call (clamped to the last entry
	// once exhausted), letting a test script a sequence of poll outcomes.
	results []pollResult
}

type pollResult struct {
	jobs []JobEnvelope
	err  error
}

func (f *fakePoller) PollEvents(ctx context.Context, limit int) ([]JobEnvelope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	idx := f.calls
	if idx >= len(f.results) {
		idx = len(f.results) - 1
	}
	f.calls++
	r := f.results[idx]
	return r.jobs, r.err
}

func (f *fakePoller) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeRunner struct {
	ran   int32
	jobs  []JobEnvelope
	mu    sync.Mutex
	toErr error
}

func (r *fakeRunner) Run(ctx context.Context, job JobEnvelope) error {
	atomic.AddInt32(&r.ran, 1)
	r.mu.Lock()
	r.jobs = append(r.jobs, job)
	r.mu.Unlock()
	return r.toErr
}

func TestWorker_Loop_RunsClaimedJobs(t *testing.T) {
	poller := &fakePoller{results: []pollResult{
		{jobs: []JobEnvelope{{JobID: 1, EventID: "evt:1"}}},
		{jobs: nil, err: nil}, // subsequent polls come up empty until ctx cancel
	}}
	runner := &fakeRunner{}
	w := NewWorker(poller, runner)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Loop(ctx)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&runner.ran) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Loop did not exit after cancel")
	}

	if atomic.LoadInt32(&runner.ran) != 1 {
		t.Fatalf("ran = %d, want 1", runner.ran)
	}
	if len(runner.jobs) != 1 || runner.jobs[0].JobID != 1 {
		t.Fatalf("jobs = %#v", runner.jobs)
	}
}

func TestWorker_Loop_BacksOffAndRecoversOnPollError(t *testing.T) {
	poller := &fakePoller{results: []pollResult{
		{err: errors.New("network blip")},
		{jobs: []JobEnvelope{{JobID: 2}}},
		{jobs: nil},
	}}
	runner := &fakeRunner{}
	w := NewWorker(poller, runner)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		w.Loop(ctx)
		close(done)
	}()

	// minPollBackoff (2s) is most of this budget on its own; give it a wide
	// margin above that rather than the bare minimum — a loaded CI runner
	// regularly ate the previous 5s deadline's ~3s of slack, tripping this
	// assertion before cancel() ever got scheduled.
	deadline := time.Now().Add(15 * time.Second)
	for atomic.LoadInt32(&runner.ran) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if atomic.LoadInt32(&runner.ran) != 1 {
		t.Fatalf("ran = %d, want 1 (worker should recover after the transient poll error)", runner.ran)
	}
}

// TestWorker_Loop_StopsRetryingOnFatalAuthError guards against a Codex
// finding: AGENT_API_TOKEN is read once at process start with no live
// credential-reload path, so a 401/403 from an expired or revoked token can
// never be resolved by retrying — yet the loop previously treated it like
// any other transient network blip and retried forever, silently
// accumulating unprocessed jobs while still looking "alive" (just noisy
// warnings) in logs. The loop must exit instead of retrying, and never call
// PollEvents again afterward.
func TestWorker_Loop_StopsRetryingOnFatalAuthError(t *testing.T) {
	poller := &fakePoller{results: []pollResult{
		{err: &APIError{StatusCode: 401, Message: "token expired"}},
	}}
	runner := &fakeRunner{}
	w := NewWorker(poller, runner)

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		w.Loop(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Loop did not exit promptly on a fatal auth error")
	}

	if got := poller.callCount(); got != 1 {
		t.Fatalf("PollEvents called %d times, want exactly 1 (no retry on a fatal auth error)", got)
	}
}

func TestIsFatalAuthError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"401", &APIError{StatusCode: 401}, true},
		{"403", &APIError{StatusCode: 403}, true},
		{"404", &APIError{StatusCode: 404}, false},
		{"500", &APIError{StatusCode: 500}, false},
		{"non-APIError", errors.New("network blip"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isFatalAuthError(c.err); got != c.want {
				t.Fatalf("isFatalAuthError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

func TestWorker_Loop_ExitsPromptlyOnContextCancel(t *testing.T) {
	poller := &fakePoller{results: []pollResult{{jobs: nil}}}
	w := NewWorker(poller, &fakeRunner{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Loop(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Loop did not exit promptly on cancel")
	}
}

func TestParseClaudeResult_ParsesSuccessAndError(t *testing.T) {
	ok, err := ParseClaudeResult([]byte(`{"type":"result","subtype":"success","is_error":false,"duration_ms":404,"num_turns":3,"total_cost_usd":0.01,"result":"done"}`))
	if err != nil {
		t.Fatalf("ParseClaudeResult: %v", err)
	}
	if ok.IsError || ok.NumTurns != 3 {
		t.Fatalf("ok = %#v", ok)
	}
	if err := CheckResult(ok); err != nil {
		t.Fatalf("CheckResult on success: %v", err)
	}

	bad, err := ParseClaudeResult([]byte(`{"type":"result","subtype":"error_max_turns","is_error":true,"result":"hit max turns"}`))
	if err != nil {
		t.Fatalf("ParseClaudeResult: %v", err)
	}
	checkErr := CheckResult(bad)
	if checkErr == nil {
		t.Fatal("expected CheckResult to report is_error=true")
	}
	if !errors.Is(checkErr, ErrClaudeReportedError) {
		t.Fatalf("checkErr = %v, want wrapping ErrClaudeReportedError", checkErr)
	}
}

func TestParseClaudeResult_MalformedJSONIsAnError(t *testing.T) {
	if _, err := ParseClaudeResult([]byte("not json")); err == nil {
		t.Fatal("expected an error for malformed stdout")
	}
}
