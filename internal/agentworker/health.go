package agentworker

import "sync/atomic"

// Health tracks Worker.Loop's liveness/readiness state so cmd/agent-worker
// can expose it over HTTP for Kubernetes probes. All methods are safe for
// concurrent use, and a nil *Health is valid — every method degrades to a
// permissive no-op/true, so a Worker with no Health attached (e.g. in tests
// that don't care about probe state) behaves exactly as it did before this
// existed.
type Health struct {
	stopped    atomic.Bool
	polledOnce atomic.Bool
	pollOK     atomic.Bool
	fatal      atomic.Bool
}

// SetPollResult records the outcome of the most recent PollEvents attempt.
func (h *Health) SetPollResult(ok bool) {
	if h == nil {
		return
	}
	h.polledOnce.Store(true)
	h.pollOK.Store(ok)
}

// SetFatal marks the worker as permanently unready — called once, right
// before Loop returns ErrFatalAuth. There is no corresponding "unset": a
// fatal auth error means the process is expected to exit and be restarted
// with a fresh token, not to self-heal in place.
func (h *Health) SetFatal() {
	if h == nil {
		return
	}
	h.fatal.Store(true)
}

// SetStopped marks the poll loop as no longer running — called via defer at
// the top of Loop, covering every return path (clean shutdown or fatal).
func (h *Health) SetStopped() {
	if h == nil {
		return
	}
	h.stopped.Store(true)
}

// Alive reports whether the poll loop is still actively running. This is
// the /livez signal: false means the process itself is wedged or has
// already exited its main loop, independent of whether it's currently able
// to reach the Agent API.
func (h *Health) Alive() bool {
	if h == nil {
		return true
	}
	return !h.stopped.Load()
}

// Ready reports whether the worker currently has a working connection to
// the Agent API: it has completed at least one poll attempt, that attempt
// succeeded, no fatal auth error has occurred since, and the poll loop
// hasn't already stopped. This is the /readyz signal — false during startup
// (before the first poll completes), after a transient poll failure (until
// the next successful one), permanently after a fatal auth error, or during
// the shutdown grace period between Loop returning and the health server
// itself closing (without the stopped check, a probe request racing that
// window would see 200 despite the process already being on its way out).
func (h *Health) Ready() bool {
	if h == nil {
		return true
	}
	return h.polledOnce.Load() && h.pollOK.Load() && !h.fatal.Load() && !h.stopped.Load()
}
