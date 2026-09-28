package mcp

import (
	"context"
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// mediaGateWait bounds how long a media operation (fetchMediaInline call, or
// a get_media download) waits for a free admission-gate slot before being
// refused. See requirements.md's admission-control acceptance criteria
// (issue #705).
const mediaGateWait = 2 * time.Second

// errMediaBusy is returned by mediaGate.acquire when no slot became free
// within mediaGateWait, and is the exact text surfaced to the MCP caller —
// classified as ReasonMediaCapacity by classifyToolResultReason.
var errMediaBusy = errors.New("media downloads are at capacity - retry shortly")

// mediaGate bounds how many media operations (one per fetchMediaInline call,
// one per get_media download) may be in flight at once, via a buffered
// channel used as a counting semaphore. A nil *mediaGate imposes no limit at
// all — every method below is a no-op on a nil receiver — which is exactly
// what every existing test and any *Server built without
// WithMediaConcurrency (MEDIA_MAX_CONCURRENT=0 or unset) gets.
type mediaGate struct {
	slots chan struct{}
	// inFlight, when non-nil, is set to the current number of held slots on
	// every acquire/release. Optional: a *Server built without a
	// *metrics.Registry (WithMetrics never called) leaves this nil, and every
	// use below is nil-guarded.
	inFlight prometheus.Gauge
}

// newMediaGate builds a mediaGate with n slots. n must be positive; callers
// (WithMediaConcurrency) treat n<=0 as "no gate" and leave Server.mediaGate
// nil instead of calling this.
func newMediaGate(n int, inFlight prometheus.Gauge) *mediaGate {
	return &mediaGate{slots: make(chan struct{}, n), inFlight: inFlight}
}

// acquire reserves one slot, waiting up to mediaGateWait for one to free up.
// It returns nil once a slot is held, errMediaBusy on timeout, or ctx's own
// error if ctx is done first. A nil receiver always returns nil immediately
// (unlimited). Every acquire that returns nil must be paired with exactly one
// release (typically via defer).
func (g *mediaGate) acquire(ctx context.Context) error {
	if g == nil {
		return nil
	}
	select {
	case g.slots <- struct{}{}:
		if g.inFlight != nil {
			g.inFlight.Inc()
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(mediaGateWait):
		return errMediaBusy
	}
}

// release frees the slot held by the matching acquire call. A nil receiver
// is a no-op. Safe to call at most once per successful acquire — callers use
// defer immediately after a successful acquire so every exit path (success,
// per-item error, systemic error, context cancellation) releases exactly
// once.
func (g *mediaGate) release() {
	if g == nil {
		return
	}
	<-g.slots
	if g.inFlight != nil {
		g.inFlight.Dec()
	}
}
