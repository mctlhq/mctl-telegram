package pa

// timing.go measures where a run's time goes: waiting for a worker, in the
// model, in tools. It only observes: it decides nothing, and a run it
// cannot see end to end is not reported at all.
//
// The run loop sees every boundary. A turn admission opens a model phase,
// a tool admission closes it and opens a tool phase, the recorded tool
// result closes that, and the reply closes the run. The state is in this
// replica's memory, so a run whose requests reach several replicas is
// observed by none of them: a phase is reported only when this replica saw
// both of its ends, never from one end and a guess.

import (
	"log/slog"
	"sync"
	"time"
)

// Run phases, the closed label set of the phase histogram
// (metrics.PARunPhases).
const (
	// PhaseQueue is from the job's creation to its claim.
	PhaseQueue = "queue"
	// PhaseModel is the time between a turn admission and the tool
	// admission or reply that follows it, summed over the run.
	PhaseModel = "model"
	// PhaseTool is the time between a tool admission and its recorded
	// result, summed over the run. Not reported for a run with no tool.
	PhaseTool = "tool"
	// PhaseRun is from the claim to the reply.
	PhaseRun = "run"
	// PhaseTotal is from the job's creation to the reply.
	PhaseTotal = "total"
)

// RunPhases is every phase label.
func RunPhases() []string {
	return []string{PhaseQueue, PhaseModel, PhaseTool, PhaseRun, PhaseTotal}
}

// PhaseObserver records one phase duration (*metrics.Registry).
type PhaseObserver interface {
	ObservePARunPhase(phase string, d time.Duration)
}

// timingKeep bounds how long an unfinished run's timing is kept. A run
// cannot outlive its lease, so anything older was stopped elsewhere.
const timingKeep = time.Hour

type timingPhase int

const (
	timingIdle timingPhase = iota
	timingModel
	timingTool
)

type runTiming struct {
	created, claimed, mark time.Time
	phase                  timingPhase
	model, tool            time.Duration
	turns, tools           int
}

// close ends the open phase at now.
func (r *runTiming) close(now time.Time) {
	switch r.phase {
	case timingModel:
		r.model += now.Sub(r.mark)
	case timingTool:
		r.tool += now.Sub(r.mark)
	}
	r.phase = timingIdle
}

// runTimer times the runs this replica claimed.
type runTimer struct {
	obs PhaseObserver
	now func() time.Time

	mu   sync.Mutex
	runs map[int64]*runTiming // by job id
}

func newRunTimer(obs PhaseObserver, now func() time.Time) *runTimer {
	if obs == nil {
		return nil
	}
	return &runTimer{obs: obs, now: now, runs: map[int64]*runTiming{}}
}

// claimed starts timing job, created at created, and reports its wait.
func (t *runTimer) claimed(job int64, created time.Time) {
	if t == nil {
		return
	}
	now := t.now()
	t.mu.Lock()
	for id, r := range t.runs {
		if now.Sub(r.claimed) > timingKeep {
			delete(t.runs, id)
		}
	}
	t.runs[job] = &runTiming{created: created, claimed: now}
	t.mu.Unlock()
	if !created.IsZero() && !now.Before(created) {
		t.obs.ObservePARunPhase(PhaseQueue, now.Sub(created))
	}
}

// turn opens a model phase.
func (t *runTimer) turn(job int64) {
	t.step(job, timingModel)
}

// toolStart closes the model phase and opens a tool phase.
func (t *runTimer) toolStart(job int64) {
	t.step(job, timingTool)
}

// toolEnd closes the tool phase.
func (t *runTimer) toolEnd(job int64) {
	t.step(job, timingIdle)
}

func (t *runTimer) step(job int64, next timingPhase) {
	if t == nil {
		return
	}
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.runs[job]
	if !ok {
		return
	}
	r.close(now)
	r.phase, r.mark = next, now
	switch next {
	case timingModel:
		r.turns++
	case timingTool:
		r.tools++
	}
}

// replied reports the finished run. A job this replica never claimed has
// no timing here and reports nothing.
func (t *runTimer) replied(job int64) {
	if t == nil {
		return
	}
	now := t.now()
	t.mu.Lock()
	r, ok := t.runs[job]
	delete(t.runs, job)
	if ok {
		r.close(now)
	}
	t.mu.Unlock()
	if !ok {
		return
	}
	run := now.Sub(r.claimed)
	t.obs.ObservePARunPhase(PhaseModel, r.model)
	if r.tools > 0 {
		t.obs.ObservePARunPhase(PhaseTool, r.tool)
	}
	t.obs.ObservePARunPhase(PhaseRun, run)
	// No principal and no text: ids and durations only. The wait and the
	// total are logged only when the creation time is usable, as in the
	// histogram: a zero or later creation time is unknown, not zero.
	attrs := []any{"job_id", job, "turns", r.turns, "tool_calls", r.tools,
		"model_ms", r.model.Milliseconds(), "tool_ms", r.tool.Milliseconds(), "run_ms", run.Milliseconds()}
	if !r.created.IsZero() && !r.claimed.Before(r.created) {
		total := now.Sub(r.created)
		t.obs.ObservePARunPhase(PhaseTotal, total)
		attrs = append(attrs, "queue_ms", r.claimed.Sub(r.created).Milliseconds(), "total_ms", total.Milliseconds())
	}
	slog.Info("pa run timing", attrs...)
}

// drop forgets a run that ended without a reply.
func (t *runTimer) drop(job int64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	delete(t.runs, job)
	t.mu.Unlock()
}

// timed reports how many runs are being timed (tests).
func (t *runTimer) timed() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.runs)
}
