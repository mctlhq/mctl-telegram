package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// ErrNoDaemonConnected is returned by Hub.Call when the target user has
// no Local Bridge daemon currently registered. The MCP tool surface
// should translate this into a clean "user is offline" response to
// Claude.ai instead of waiting for a deadline.
var ErrNoDaemonConnected = errors.New("local-bridge daemon not connected")

// ErrCallTimeout is returned when a daemon accepted the envelope but
// did not respond within DeadlineCall.
var ErrCallTimeout = errors.New("local-bridge call timed out")

// ErrDaemonOverloaded is returned by Hub.Call when the daemon already has
// maxPendingCalls in-flight calls. The MCP surface should translate this
// into a human-readable error that asks the user to retry.
var ErrDaemonOverloaded = errors.New("local-bridge daemon overloaded")

// maxPendingCalls is the per-daemon cap on concurrent in-flight calls.
// When the count reaches this limit, new Hub.Call invocations are
// rejected with ErrDaemonOverloaded rather than queuing unboundedly.
const maxPendingCalls = 100

// daemonConn is the in-memory handle for one connected daemon.
//
// Callers never write directly to send. They enqueue onto outbound instead;
// a single pump goroutine owns all writes to send and is also the only code
// that closes send. Teardown therefore cannot race a concurrent Hub.Call with
// close(send): it only closes done and waits for the pump to stop.
type daemonConn struct {
	send         chan Envelope
	outbound     chan Envelope
	done         chan struct{}
	stopped      chan struct{}
	retireOnce   sync.Once
	pending      sync.Map // map[string]chan Envelope
	pendingCount atomic.Int64
	// deviceID is the Local Bridge device this connection authenticated as
	// (issue-483), empty for a connection whose credential predates device
	// binding (a rolling-deploy transitional window). EvictDevice only
	// evicts when this matches the caller's target, mirroring
	// UnregisterSend's "only touch the entry if it's still the one we
	// mean" discipline.
	deviceID string
}

func newDaemonConn(deviceID string) *daemonConn {
	dc := &daemonConn{
		send:     make(chan Envelope, 16),
		outbound: make(chan Envelope, 16),
		done:     make(chan struct{}),
		stopped:  make(chan struct{}),
		deviceID: deviceID,
	}
	go dc.pump()
	return dc
}

// pump is the sole owner of dc.send. That single-writer ownership is what
// makes retirement safe: teardown signals dc.done; pump stops forwarding and
// then closes dc.send after no sender can still be using it.
func (dc *daemonConn) pump() {
	defer close(dc.stopped)
	defer close(dc.send)
	for {
		select {
		case <-dc.done:
			return
		case env := <-dc.outbound:
			select {
			case <-dc.done:
				return
			case dc.send <- env:
			}
		}
	}
}

// retire is idempotent and synchronous: when it returns, pump has stopped and
// send has been closed. This gives teardown paths a clear happens-before
// boundary and prevents any envelope from being forwarded after retirement
// completes.
func (dc *daemonConn) retire() {
	dc.retireOnce.Do(func() {
		close(dc.done)
		<-dc.stopped
	})
}

// Hub multiplexes per-user daemon connections. There is at most one
// active daemon per user_id; a new Register evicts the previous one.
// Hub does not own the websocket transport — it sees only Envelopes —
// so the same Hub is exercised by tests via in-process channels and
// by the real /bridge endpoint via the websocket adapter.
type Hub struct {
	mu      sync.Mutex
	conn    map[int64]*daemonConn
	now     func() time.Time
	metrics *metrics.Registry
}

// NewHub builds an empty hub. Wire it into cmd/server/main.go and a
// future internal/bridge/server.go websocket adapter.
func NewHub() *Hub {
	return &Hub{
		conn: map[int64]*daemonConn{},
		now:  time.Now,
	}
}

// WithMetrics wires a *metrics.Registry so daemon connection events are
// reflected in the mctl_bridge_active_daemons gauge. Returns the receiver
// for chaining.
func (h *Hub) WithMetrics(m *metrics.Registry) *Hub {
	h.metrics = m
	return h
}

// Register adds a daemon connection for the user. Any previous connection is
// retired. The returned channel is the daemon's outbound queue — the transport
// writes frames pulled from it onto the websocket. The channel is closed by
// the connection's single pump goroutine after retirement.
//
// deviceID names which local_bridge_devices row authenticated this
// connection (issue-483); empty when the connecting identity carries no
// device binding (a legacy/admin-minted bridge token). It is stored on the
// entry so EvictDevice can later find and close this specific connection
// without disturbing a different device's live session for the same user.
//
// Cap of 16 is intentional: a daemon falling behind on reads will
// back-pressure the hub rather than blow memory.
func (h *Hub) Register(userID int64, deviceID string) chan Envelope {
	h.mu.Lock()
	prev, replaced := h.conn[userID]
	dc := newDaemonConn(deviceID)
	h.conn[userID] = dc
	if !replaced && h.metrics != nil {
		h.metrics.BridgeActiveDaemons.Inc()
	}
	if h.metrics != nil {
		h.metrics.BridgeConnectionsTotal.WithLabelValues(strconv.FormatInt(userID, 10)).Inc()
	}
	h.mu.Unlock()

	// Retire outside h.mu: retire waits for the pump to stop, and holding the
	// hub mutex across that wait would unnecessarily serialize unrelated hub
	// operations. The map already points at the replacement before retirement
	// begins, so new Calls cannot choose the old connection.
	if replaced {
		prev.retire()
	}
	return dc.send
}

// Unregister drops the user's daemon connection. Idempotent. The
// transport calls this when the websocket closes for any reason.
func (h *Hub) Unregister(userID int64) {
	h.mu.Lock()
	dc, ok := h.conn[userID]
	if ok {
		delete(h.conn, userID)
		if h.metrics != nil {
			h.metrics.BridgeActiveDaemons.Dec()
		}
	}
	h.mu.Unlock()
	if ok {
		dc.retire()
	}
}

// UnregisterSend is like Unregister but only removes the entry when it
// still holds the given send channel. This prevents a reconnect race
// where an old websocket handler's cleanup path calls Unregister after
// Hub.Register has already replaced the entry with a new daemon
// connection, which would evict the live connection.
func (h *Hub) UnregisterSend(userID int64, send chan Envelope) {
	h.mu.Lock()
	dc, ok := h.conn[userID]
	if !ok || dc.send != send {
		h.mu.Unlock()
		return
	}
	delete(h.conn, userID)
	if h.metrics != nil {
		h.metrics.BridgeActiveDaemons.Dec()
	}
	h.mu.Unlock()
	dc.retire()
}

// EvictDevice closes and removes userID's live connection ONLY if it is
// currently registered as deviceID (issue-483: device revocation's active
// disconnect). Returns true when a connection was evicted.
//
// Mirrors UnregisterSend's "only touch the entry if it's still the one we
// mean" discipline: without the deviceID match, a revoke racing a
// legitimate reconnect from a DIFFERENT, non-revoked device belonging to
// the same user could evict the wrong session. An empty deviceID never
// matches, and repeated eviction after removal is an idempotent no-op.
func (h *Hub) EvictDevice(userID int64, deviceID string) bool {
	if deviceID == "" {
		return false
	}
	h.mu.Lock()
	dc, ok := h.conn[userID]
	if !ok || dc.deviceID != deviceID {
		h.mu.Unlock()
		return false
	}
	delete(h.conn, userID)
	if h.metrics != nil {
		h.metrics.BridgeActiveDaemons.Dec()
	}
	h.mu.Unlock()
	dc.retire()
	return true
}

// Call queues an envelope for the daemon and waits up to DeadlineCall
// for a matching response. Returns ErrNoDaemonConnected when there is
// no registered daemon or when that connection is retired while the call is
// in flight; ErrCallTimeout on no response; ErrDaemonOverloaded when more
// than maxPendingCalls are already in flight for this daemon.
func (h *Hub) Call(ctx context.Context, userID int64, env Envelope) (Envelope, error) {
	h.mu.Lock()
	dc, ok := h.conn[userID]
	h.mu.Unlock()
	if !ok {
		return Envelope{}, ErrNoDaemonConnected
	}

	select {
	case <-dc.done:
		return Envelope{}, ErrNoDaemonConnected
	default:
	}

	// Backpressure: reject the call immediately if the daemon is already
	// saturated. This prevents unbounded memory growth when a daemon is
	// slow or stuck.
	if dc.pendingCount.Add(1) > maxPendingCalls {
		dc.pendingCount.Add(-1)
		return Envelope{}, ErrDaemonOverloaded
	}
	defer dc.pendingCount.Add(-1)

	reply := make(chan Envelope, 1)
	dc.pending.Store(env.ID, reply)
	defer dc.pending.Delete(env.ID)

	select {
	case dc.outbound <- env:
	case <-dc.done:
		return Envelope{}, ErrNoDaemonConnected
	case <-ctx.Done():
		return Envelope{}, ctx.Err()
	}

	select {
	case got := <-reply:
		return got, nil
	case <-dc.done:
		return Envelope{}, ErrNoDaemonConnected
	case <-time.After(DeadlineFor(env.Tool)):
		return Envelope{}, ErrCallTimeout
	case <-ctx.Done():
		return Envelope{}, ctx.Err()
	}
}

// Deliver is called by the transport when a frame arrives from the
// daemon. Response/Error envelopes are routed to the matching Call;
// other frames (Ping/Pong) are handled by the transport directly,
// not delivered here.
func (h *Hub) Deliver(userID int64, env Envelope) {
	h.mu.Lock()
	dc, ok := h.conn[userID]
	h.mu.Unlock()
	if !ok {
		return
	}
	if env.Type != TypeResponse && env.Type != TypeError {
		return
	}
	v, ok := dc.pending.Load(env.ID)
	if !ok {
		return
	}
	if ch, ok := v.(chan Envelope); ok {
		select {
		case ch <- env:
		default:
			// Caller already left — drop.
		}
	}
}

// HasDaemon reports whether a daemon is currently registered for the
// user. Used by the MCP tool dispatcher to decide between hosted-mode
// Borrow and bridge-mode Call.
func (h *Hub) HasDaemon(userID int64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, ok := h.conn[userID]
	return ok
}

// MarshalCall is a small convenience: build a TypeCall envelope and
// hand back the JSON-encoded bytes the transport will write. Useful
// for tests that don't want to wire a fake transport.
func MarshalCall(id, tool string, args any) ([]byte, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	return json.Marshal(EncodeCall(id, tool, raw))
}
