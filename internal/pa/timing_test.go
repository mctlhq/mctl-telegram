package pa

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// phaseRecorder records the phase durations a run loop reported.
type phaseRecorder struct {
	mu  sync.Mutex
	got map[string][]time.Duration
}

func (r *phaseRecorder) ObservePARunPhase(phase string, d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.got == nil {
		r.got = map[string][]time.Duration{}
	}
	r.got[phase] = append(r.got[phase], d)
}

func (r *phaseRecorder) of(phase string) []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.got[phase])
}

func withPhases(r *phaseRecorder) rlOption {
	return func(c *RunLoopConfig, _ *runLoopHarness) { c.Phases = r }
}

func (r *phaseRecorder) want(t *testing.T, phase string, want ...time.Duration) {
	t.Helper()
	if got := r.of(phase); !slices.Equal(got, want) {
		t.Fatalf("phase %s = %v, want %v", phase, got, want)
	}
}

// TestRunLoop_TimingPhases: a run with one tool call reports its wait for a
// worker, its model time summed over both turns, its tool time, and the
// claim-to-reply and created-to-reply totals.
func TestRunLoop_TimingPhases(t *testing.T) {
	rec := &phaseRecorder{}
	h := newRunLoopHarness(t, withPhases(rec))
	h.tools = []string{"tg/get_messages"}
	h.consent(aliceID)
	h.text(aliceID, "what is new?")
	step := func(d time.Duration) { h.now = h.now.Add(d) }

	step(3 * time.Second)
	c := h.mustClaim()
	rec.want(t, PhaseQueue, 3*time.Second)
	turn := func() {
		t.Helper()
		if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 100}); w.Code != http.StatusOK {
			t.Fatalf("turn: %d %s", w.Code, w.Body)
		}
	}
	step(time.Second) // the worker's own time before its first turn
	turn()
	step(2 * time.Second) // model
	job := h.paJob(c.Token)
	if _, err := h.loop.AdmitToolCall(context.Background(), job, "tg", "get_messages"); err != nil {
		t.Fatal(err)
	}
	step(5 * time.Second) // tool
	if err := h.loop.StillRunning(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	step(time.Second) // between the tool result and the next turn: no phase
	turn()
	step(4 * time.Second) // model
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "nothing"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d %s", w.Code, w.Body)
	}
	rec.want(t, PhaseModel, 6*time.Second)
	rec.want(t, PhaseTool, 5*time.Second)
	rec.want(t, PhaseRun, 13*time.Second)
	rec.want(t, PhaseTotal, 16*time.Second)
	rec.want(t, PhaseQueue, 3*time.Second)
	if n := h.loop.timer.timed(); n != 0 {
		t.Fatalf("runs still timed after the reply = %d", n)
	}
}

// TestRunLoop_TimingNoToolPhaseWithoutTool: a run that called no tool
// reports no tool phase at all, not a zero.
func TestRunLoop_TimingNoToolPhaseWithoutTool(t *testing.T) {
	rec := &phaseRecorder{}
	h := newRunLoopHarness(t, withPhases(rec))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 100}); w.Code != http.StatusOK {
		t.Fatalf("turn: %d", w.Code)
	}
	h.now = h.now.Add(2 * time.Second)
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "hi"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	rec.want(t, PhaseModel, 2*time.Second)
	rec.want(t, PhaseTool)
	rec.want(t, PhaseRun, 2*time.Second)
}

// TestRunLoop_TimingStoppedRunReportsNothing: a run refused at a step is
// forgotten, and reports no model, tool, run or total time.
func TestRunLoop_TimingStoppedRunReportsNothing(t *testing.T) {
	rec := &phaseRecorder{}
	h := newRunLoopHarness(t, withPhases(rec))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	if _, err := h.convoHarness.store.DB.Exec(`UPDATE pa_conversations SET closed_at_ms = 1 WHERE principal = $1`, aliceID); err != nil {
		t.Fatal(err)
	}
	if w := h.post(RouteTurn, c.Token, turnRequest{ContextTokens: 100}); w.Code != http.StatusConflict {
		t.Fatalf("turn: %d", w.Code)
	}
	if n := h.loop.timer.timed(); n != 0 {
		t.Fatalf("runs still timed after the stop = %d", n)
	}
	for _, p := range []string{PhaseModel, PhaseTool, PhaseRun, PhaseTotal} {
		rec.want(t, p)
	}
}

// TestRunLoop_TimingUnseenClaimReportsNothing: a reply for a run this
// replica did not claim (here: its timing was dropped) reports nothing
// rather than a duration measured from one end.
func TestRunLoop_TimingUnseenClaimReportsNothing(t *testing.T) {
	rec := &phaseRecorder{}
	h := newRunLoopHarness(t, withPhases(rec))
	h.consent(aliceID)
	h.text(aliceID, "hello")
	c := h.mustClaim()
	h.loop.timer.drop(c.JobID)
	h.now = h.now.Add(2 * time.Second)
	if w := h.post(RouteReply, c.Token, replyRequest{Text: "hi"}); w.Code != http.StatusOK {
		t.Fatalf("reply: %d", w.Code)
	}
	for _, p := range []string{PhaseModel, PhaseTool, PhaseRun, PhaseTotal} {
		rec.want(t, p)
	}
}

// TestRunLoop_NoTimingWithoutObserver: Phases is optional.
func TestRunLoop_NoTimingWithoutObserver(t *testing.T) {
	h := newRunLoopHarness(t)
	if h.loop.timer != nil {
		t.Fatal("a run timer without an observer")
	}
	h.consent(aliceID)
	h.text(aliceID, "hello")
	h.finishRun("hi")
}

// TestRunTimer_ForgetsOldRuns: a run that never ended here is forgotten at
// a later claim, so the map does not grow without bound.
func TestRunTimer_ForgetsOldRuns(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	tm := newRunTimer(&phaseRecorder{}, func() time.Time { return now })
	tm.claimed(1, now)
	now = now.Add(timingKeep + time.Second)
	tm.claimed(2, now)
	if n := tm.timed(); n != 1 {
		t.Fatalf("timed runs = %d, want 1", n)
	}
}

// TestPARunPhaseLabels: the phases reported are the histogram's label set.
func TestPARunPhaseLabels(t *testing.T) {
	if !slices.Equal(slices.Sorted(slices.Values(RunPhases())), slices.Sorted(slices.Values(metrics.PARunPhases))) {
		t.Fatalf("phases %v, metrics label set %v", RunPhases(), metrics.PARunPhases)
	}
}
