package mcp

import (
	"context"
	"errors"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// mediaGateWait bounds how long a media operation (fetchMediaInline call, or
// a get_media download) waits for a free admission-gate slot before being
// refused. See requirements.md's admission-control acceptance criteria
// (issue #705).
// A package var, not a const, so tests can shrink it instead of sleeping the
// full production wait.
var mediaGateWait = 2 * time.Second

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
	// A stoppable timer rather than time.After: the common case acquires a
	// slot immediately, and time.After would keep a live 2s timer per call.
	timer := time.NewTimer(mediaGateWait)
	defer timer.Stop()
	select {
	case g.slots <- struct{}{}:
		if g.inFlight != nil {
			g.inFlight.Inc()
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
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

// mediaGateRefused renders a failed mediaGate.acquire for tool. Only
// errMediaBusy is a capacity refusal: it is counted in
// MediaGateRejectionsTotal and returned as the retryable capacity message.
// Any other error is the caller's own context ending while it waited for a
// slot; that is audited with the real error and never counted or reported as
// capacity, so the rejection metric and the audit trail keep measuring
// saturation rather than client disconnects.
func (s *Server) mediaGateRefused(ctx context.Context, id *auth.Identity, tool, peer string, gerr error, startedAt time.Time) *mcplib.CallToolResult {
	if !errors.Is(gerr, errMediaBusy) {
		// ctx is already done here, so audit detached, as the fmErr branch
		// in the handlers does for the same reason.
		s.auditDetached(ctx, id, tool, peer, gerr, startedAt)
		return borrowErrResult(tool, gerr)
	}
	if s.Metrics != nil {
		s.Metrics.MediaGateRejectionsTotal.WithLabelValues(tool).Inc()
	}
	s.audit(ctx, id, tool, peer, errMediaBusy, startedAt)
	return mcplib.NewToolResultError(errMediaBusy.Error())
}
