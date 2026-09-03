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

// daemonConn is the in-memory handle for one connected daemon. The
// actual websocket connection is held by the transport layer; here we
// abstract over a send-channel + a pending-call map keyed by envelope ID.
type daemonConn struct {
	send         chan Envelope
	pending      sync.Map // map[string]chan Envelope
	pendingCount atomic.Int64
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

// Register adds a daemon connection for the user. Any previous
// connection is evicted (its send channel is closed). The returned
// channel is the daemon's outbound queue — the transport writes
// frames pulled from it onto the websocket.
//
// Cap of 16 is intentional: a daemon falling behind on reads will
// back-pressure the hub rather than blow memory.
func (h *Hub) Register(userID int64) chan Envelope {
	h.mu.Lock()
	defer h.mu.Unlock()
	if prev, ok := h.conn[userID]; ok {
		close(prev.send)
		// Eviction of an existing daemon: the gauge stays at 1 for this user
		// because a new one is about to be registered. Net change = 0 — which
		// is exactly why a flap alert cannot be built on the gauge. The
		// counter below still counts this as a connection, because it is one.
	} else {
		// Brand-new connection for this user.
		if h.metrics != nil {
			h.metrics.BridgeActiveDaemons.Inc()
		}
	}
	// Counted on every registration, both branches. A daemon in a reconnect
	// loop increments this once per cycle no matter which branch it takes.
	if h.metrics != nil {
		h.metrics.BridgeConnectionsTotal.WithLabelValues(strconv.FormatInt(userID, 10)).Inc()
	}
	dc := &daemonConn{send: make(chan Envelope, 16)}
	h.conn[userID] = dc
	return dc.send
}

// Unregister drops the user's daemon connection. Idempotent. The
// transport calls this when the websocket closes for any reason.
func (h *Hub) Unregister(userID int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if dc, ok := h.conn[userID]; ok {
		delete(h.conn, userID)
		close(dc.send)
		if h.metrics != nil {
			h.metrics.BridgeActiveDaemons.Dec()
		}
	}
}

// UnregisterSend is like Unregister but only removes the entry when it
// still holds the given send channel. This prevents a reconnect race
// where an old websocket handler's cleanup path calls Unregister after
// Hub.Register has already replaced the entry with a new daemon
// connection, which would evict the live connection.
func (h *Hub) UnregisterSend(userID int64, send chan Envelope) {
	h.mu.Lock()
	defer h.mu.Unlock()
	dc, ok := h.conn[userID]
	if !ok {
		return
	}
	// Only unregister if the map entry still belongs to this connection.
	// If a newer daemon already called Register, dc.send is a different
	// channel; leave the new entry intact.
	if dc.send == send {
		delete(h.conn, userID)
		close(dc.send)
		if h.metrics != nil {
			h.metrics.BridgeActiveDaemons.Dec()
		}
	}
}

// Call queues an envelope for the daemon and waits up to DeadlineCall
// for a matching response. Returns ErrNoDaemonConnected when there is
// no registered daemon; ErrCallTimeout on no response;
// ErrDaemonOverloaded when more than maxPendingCalls are already in
// flight for this daemon. Concurrent Calls for the same user are fine
// — each gets its own pending entry keyed by env.ID.
func (h *Hub) Call(ctx context.Context, userID int64, env Envelope) (Envelope, error) {
	h.mu.Lock()
	dc, ok := h.conn[userID]
	h.mu.Unlock()
	if !ok {
		return Envelope{}, ErrNoDaemonConnected
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
	case dc.send <- env:
	case <-ctx.Done():
		return Envelope{}, ctx.Err()
	}

	select {
	case got := <-reply:
		return got, nil
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
