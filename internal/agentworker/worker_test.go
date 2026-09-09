package agentworker

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
// PollEvents again afterward. It must also return ErrFatalAuth rather than
// nil — a second Codex finding on #308: cmd/agent-worker's run() previously
// discarded Loop's outcome entirely, so main() always exited 0 even on this
// stop, indistinguishable to a process supervisor from an ordinary SIGTERM
// shutdown.
func TestWorker_Loop_StopsRetryingOnFatalAuthError(t *testing.T) {
	poller := &fakePoller{results: []pollResult{
		{err: &APIError{StatusCode: 401, Message: "token expired"}},
	}}
	runner := &fakeRunner{}
	w := NewWorker(poller, runner)

	ctx := context.Background()
	done := make(chan struct{})
	var loopErr error
	go func() {
		loopErr = w.Loop(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Loop did not exit promptly on a fatal auth error")
	}

	if !errors.Is(loopErr, ErrFatalAuth) {
		t.Fatalf("Loop err = %v, want ErrFatalAuth", loopErr)
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
	var loopErr error
	go func() {
		loopErr = w.Loop(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Loop did not exit promptly on cancel")
	}
	if loopErr != nil {
		t.Fatalf("Loop err = %v, want nil on an ordinary ctx-cancel shutdown", loopErr)
	}
}

func TestWorker_Loop_HealthReflectsFatalAuthError(t *testing.T) {
	poller := &fakePoller{results: []pollResult{
		{err: &APIError{StatusCode: 403, Message: "revoked"}},
	}}
	health := &Health{}
	w := NewWorker(poller, &fakeRunner{}).WithHealth(health)

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

	if health.Ready() {
		t.Fatal("health.Ready() after a fatal auth error = true, want false")
	}
	if health.Alive() {
		t.Fatal("health.Alive() after Loop returned = true, want false")
	}
}

func TestWorker_Loop_HealthBecomesReadyAfterFirstSuccessfulPoll(t *testing.T) {
	poller := &fakePoller{results: []pollResult{
		{err: errors.New("network blip")},
		{jobs: nil},
	}}
	health := &Health{}
	w := NewWorker(poller, &fakeRunner{}).WithHealth(health)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Loop(ctx)
		close(done)
	}()

	if health.Ready() {
		t.Fatal("health.Ready() before any poll = true, want false")
	}

	deadline := time.Now().Add(15 * time.Second)
	for !health.Ready() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !health.Ready() {
		t.Fatal("health.Ready() never became true after a successful poll")
	}
	cancel()
	<-done
	if health.Alive() {
		t.Fatal("health.Alive() after Loop returned = true, want false")
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

// TestCheckResult_ExcludesResultTextFromError guards against a Codex finding
// on #308: when is_error=true, res.Result can carry model-authored text
// derived from the private Telegram message the job was processing (e.g. a
// get_event/get_conversation_context tool result echoed back on a confused
// turn), and Worker.Loop logs CheckResult's returned error verbatim via
// slog.Warn — a path internal/audit/redact.go's key-based redaction cannot
// reach. The error must carry only bounded, content-free metadata
// (subtype, result length), never the result text itself.
func TestCheckResult_ExcludesResultTextFromError(t *testing.T) {
	const secret = "my SSN is 123-45-6789, please don't tell anyone"
	res := &ClaudeResult{
		Type: "result", Subtype: "error_during_execution", IsError: true, Result: secret,
	}
	err := CheckResult(res)
	if err == nil {
		t.Fatal("expected CheckResult to report is_error=true")
	}
	if !errors.Is(err, ErrClaudeReportedError) {
		t.Fatalf("err = %v, want wrapping ErrClaudeReportedError", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("err = %q, must not contain the raw result text", err.Error())
	}
	if !strings.Contains(err.Error(), "error_during_execution") {
		t.Fatalf("err = %q, want it to still carry the subtype", err.Error())
	}
}

func TestParseClaudeResult_MalformedJSONIsAnError(t *testing.T) {
	if _, err := ParseClaudeResult([]byte("not json")); err == nil {
		t.Fatal("expected an error for malformed stdout")
	}
}

// TestParseClaudeResult_TotalCostUSD_DistinguishesAbsentFromZero is the
// explicit "exercised with a payload that actually lacks the field, not
// merely a zero value" requirement: a missing key and a JSON null must both
// yield nil, while an explicit 0 must yield a non-nil pointer to 0. Reverting
// TotalCostUSD to a plain float64 makes the first two cases indistinguishable
// from the third and fails this test.
func TestParseClaudeResult_TotalCostUSD_DistinguishesAbsentFromZero(t *testing.T) {
	t.Run("key absent", func(t *testing.T) {
		res, err := ParseClaudeResult([]byte(`{"type":"result","subtype":"success","is_error":false}`))
		if err != nil {
			t.Fatalf("ParseClaudeResult: %v", err)
		}
		if res.TotalCostUSD != nil {
			t.Fatalf("TotalCostUSD = %v, want nil when the key is absent", *res.TotalCostUSD)
		}
	})
	t.Run("explicit null", func(t *testing.T) {
		res, err := ParseClaudeResult([]byte(`{"type":"result","subtype":"success","is_error":false,"total_cost_usd":null}`))
		if err != nil {
			t.Fatalf("ParseClaudeResult: %v", err)
		}
		if res.TotalCostUSD != nil {
			t.Fatalf("TotalCostUSD = %v, want nil for JSON null", *res.TotalCostUSD)
		}
	})
	t.Run("explicit zero", func(t *testing.T) {
		res, err := ParseClaudeResult([]byte(`{"type":"result","subtype":"success","is_error":false,"total_cost_usd":0}`))
		if err != nil {
			t.Fatalf("ParseClaudeResult: %v", err)
		}
		if res.TotalCostUSD == nil {
			t.Fatal("TotalCostUSD = nil, want a non-nil pointer to 0 for an explicit 0 value")
		}
		if *res.TotalCostUSD != 0 {
			t.Fatalf("TotalCostUSD = %v, want 0", *res.TotalCostUSD)
		}
	})
}

// TestCheckResult_ClassifiesUsageLimitSubtypes covers T6: a usage-limit
// subtype must satisfy errors.Is for BOTH ErrClaudeUsageLimit and the
// general ErrClaudeReportedError, and must never leak res.Result text.
// Unrelated is_error subtypes must satisfy only the general sentinel.
// Widening the match to any is_error result (not just a usage-limit
// subtype) fails the unrelated-fixture cases below.
func TestCheckResult_ClassifiesUsageLimitSubtypes(t *testing.T) {
	usageLimitCases := []string{
		"usage_limit", "rate_limit_error", "quota_exceeded",
		"credit_balance_too_low", "insufficient_credits", "USAGE_LIMIT_REACHED",
	}
	for _, subtype := range usageLimitCases {
		t.Run(subtype, func(t *testing.T) {
			const secret = "my SSN is 123-45-6789, please don't tell anyone"
			res := &ClaudeResult{Type: "result", Subtype: subtype, IsError: true, Result: secret}
			err := CheckResult(res)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, ErrClaudeUsageLimit) {
				t.Fatalf("err = %v, want errors.Is(err, ErrClaudeUsageLimit)", err)
			}
			if !errors.Is(err, ErrClaudeReportedError) {
				t.Fatalf("err = %v, want errors.Is(err, ErrClaudeReportedError) too", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("err = %q, must not contain the raw result text", err.Error())
			}
		})
	}

	unrelatedCases := []string{"error_max_turns", "error_during_execution"}
	for _, subtype := range unrelatedCases {
		t.Run(subtype, func(t *testing.T) {
			res := &ClaudeResult{Type: "result", Subtype: subtype, IsError: true}
			err := CheckResult(res)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !errors.Is(err, ErrClaudeReportedError) {
				t.Fatalf("err = %v, want errors.Is(err, ErrClaudeReportedError)", err)
			}
			if errors.Is(err, ErrClaudeUsageLimit) {
				t.Fatalf("err = %v, must NOT match ErrClaudeUsageLimit for an unrelated subtype", err)
			}
		})
	}
}

// TestWorker_Loop_TreatsUsageLimitAndGenericErrorsIdentically locks in that
// Worker.Loop's retry/backoff/dead-letter-adjacent behaviour (it has none of
// its own — see worker.go's doc comment; this only asserts the loop keeps
// polling, applies no extra sleep, and returns nil on ctx cancel) is
// byte-for-byte identical whether Runner.Run returns a usage-limit error or
// a generic ErrClaudeReportedError. Adding any early return or extra backoff
// for the usage-limit class fails this test.
func TestWorker_Loop_TreatsUsageLimitAndGenericErrorsIdentically(t *testing.T) {
	usageLimitErr := fmt.Errorf("job 1: %w: subtype=usage_limit (result: 0 bytes, see run logs)", ErrClaudeUsageLimit)
	genericErr := fmt.Errorf("job 2: %w: subtype=error_max_turns (result: 0 bytes, see run logs)", ErrClaudeReportedError)

	for _, tc := range []struct {
		name string
		err  error
	}{
		{"usage_limit", usageLimitErr},
		{"generic", genericErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			poller := &fakePoller{results: []pollResult{
				{jobs: []JobEnvelope{{JobID: 1}}},
				{jobs: []JobEnvelope{{JobID: 2}}},
				{jobs: nil},
			}}
			runner := &fakeRunner{toErr: tc.err}
			health := &Health{}
			w := NewWorker(poller, runner).WithHealth(health)

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			var loopErr error
			go func() {
				loopErr = w.Loop(ctx)
				close(done)
			}()

			deadline := time.Now().Add(2 * time.Second)
			for atomic.LoadInt32(&runner.ran) < 2 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Loop did not exit after cancel")
			}

			if loopErr != nil {
				t.Fatalf("Loop err = %v, want nil on an ordinary ctx-cancel shutdown", loopErr)
			}
			if errors.Is(loopErr, ErrFatalAuth) {
				t.Fatal("Loop must never treat a CheckResult-class error as fatal auth")
			}
			if health.Alive() {
				t.Fatal("health.Alive() after Loop returned = true, want false")
			}
			if atomic.LoadInt32(&runner.ran) < 2 {
				t.Fatalf("runner.ran = %d, want at least 2 (loop must keep polling and running jobs after a CheckResult-class error)", runner.ran)
			}
		})
	}
}
