package bridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

const pingInterval = 25 * time.Second

// pongDeadline is how long the reader waits for any frame after the writer
// has sent a ping before considering the peer dead and closing the connection.
const pongDeadline = 5 * time.Second

// identityLabel returns a stable, log-safe label for an Identity across
// auth providers. localjwt issues Identity.Subject (e.g. "tg:<id>"), the
// shared-hmac and localdev providers populate GitHubLogin. We prefer the
// Subject string when both are set so the log stays consistent regardless
// of which provider authenticated the caller.
func identityLabel(id *auth.Identity) string {
	if id == nil {
		return ""
	}
	if id.Subject != "" {
		return id.Subject
	}
	return id.GitHubLogin
}

// NewBridgeHandler returns an http.HandlerFunc that upgrades HTTP connections
// to websockets and wires them into the Hub as Local Bridge daemon connections.
//
// Authentication: the handler verifies a bearer JWT using the supplied
// provider, which MUST be configured with AudienceRequired=true and
// ExpectedAudience="bridge" so that regular MCP tokens are rejected.
//
// Only accounts whose telegram_accounts.mode is 'local' are accepted; a
// hosted-mode account attempting to register here receives HTTP 400.
//
// serverCtx should be the process-level shutdown context (from
// signal.NotifyContext). Using r.Context() would inherit the HTTP server's
// Timeout middleware and close daemon connections every 60 s.
func NewBridgeHandler(hub *Hub, provider auth.Provider, store *db.Store, serverCtx context.Context) http.HandlerFunc {
	return newBridgeHandler(hub, provider, store, serverCtx, nil, nil)
}

// NewBridgeHandlerWithMetrics is NewBridgeHandler with authentication
// failures counted in m.AuthFailuresTotal under provider="bridge". The
// bridge endpoint does not sit behind auth.Middleware (it upgrades to a
// websocket), so without this the one failure mode a daemon has -- being
// refused at the door -- produced no metric and could not alert (#612).
func NewBridgeHandlerWithMetrics(hub *Hub, provider auth.Provider, store *db.Store, serverCtx context.Context, m *metrics.Registry) http.HandlerFunc {
	return newBridgeHandler(hub, provider, store, serverCtx, nil, m)
}

// NewBridgeHandlerWithAdmissionHook is used by deterministic race tests to
// pause after durable device verification and immediately before hub
// registration. Production callers should use NewBridgeHandler.
func NewBridgeHandlerWithAdmissionHook(hub *Hub, provider auth.Provider, store *db.Store, serverCtx context.Context, hook func()) http.HandlerFunc {
	return newBridgeHandler(hub, provider, store, serverCtx, hook, nil)
}

func newBridgeHandler(hub *Hub, provider auth.Provider, store *db.Store, serverCtx context.Context, beforeRegister func(), m *metrics.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate before upgrading — upgrading first wastes resources if
		// the token is invalid and makes error reporting harder.
		// Every way this handler refuses a daemon goes through refuse(): one
		// counter under provider="bridge" with a bounded reason set, and one
		// log line naming the daemon. A daemon refused here is the one
		// incident this endpoint has, and a refusal that moves no counter
		// and names nobody is how one ran unnoticed for two days (#612).
		// Numeric claims are read unverified, as identifiers for the
		// operator; they decide nothing, and the token itself is never
		// logged.
		refuse := func(reason string, err error, id *auth.Identity) {
			if m != nil {
				m.AuthFailuresTotal.WithLabelValues(reason, "bridge").Inc()
			}
			c := claimedIdentity(r)
			attrs := []any{"reason", reason,
				"claimed_tg_id", c.TelegramID, "claimed_exp", c.ExpiresAt, "claimed_iat", c.IssuedAt}
			if id != nil {
				attrs = append(attrs, "user_id", id.UserID, "device_id", id.DeviceID)
			}
			if err != nil {
				// Do not echo err.Error() to the client: JWT parsers include
				// algorithm names, claim paths and token fragments.
				attrs = append(attrs, "err", err)
			}
			slog.Warn("bridge: authentication failed", attrs...)
		}

		id, err := provider.Authenticate(r)
		if err != nil {
			refuse(auth.ClassifyAuthError(err.Error()), err, nil)
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		if id == nil {
			refuse("no_token", nil, nil)
			w.Header().Set("WWW-Authenticate", `Bearer realm="mctl-telegram-bridge"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if id.DeviceID == "" {
			// The device-binding variant of #612: a bridge token that still
			// verifies but was minted for a credential without a device.
			refuse("no_device_binding", nil, id)
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		// Guard: only local-mode accounts may connect as a bridge daemon.
		mode, err := store.GetAccountMode(r.Context(), id.UserID)
		if err != nil {
			slog.Error("bridge: account mode lookup failed", "user_id", id.UserID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if mode != "local" {
			http.Error(w, "account is in hosted mode", http.StatusBadRequest)
			return
		}
		active, err := store.IsActiveDeviceForUser(r.Context(), id.UserID, id.DeviceID)
		if err != nil {
			slog.Error("bridge: device lookup failed", "user_id", id.UserID, "device_id", id.DeviceID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !active {
			refuse("device_inactive", nil, id)
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			// Allow any origin — the token provides authentication; CORS origin
			// checks would reject legitimate CLI daemons running on any host.
			InsecureSkipVerify: true,
		})
		if err != nil {
			// websocket.Accept already wrote an HTTP error response.
			slog.Warn("bridge: websocket upgrade failed", "user_id", id.UserID, "err", err)
			return
		}

		// Daemon responses carry get_media payloads (base64 of up to
		// MEDIA_DOWNLOAD_MAX_BYTES); coder/websocket's default 32 KiB read
		// limit would close the connection on the first real download.
		conn.SetReadLimit(MaxMediaFrameBytes)

		if beforeRegister != nil {
			beforeRegister()
		}
		send, registered := hub.TryRegister(id.UserID, id.DeviceID)
		if !registered {
			// The hub's in-memory block set is the one refusal after the
			// upgrade: the device was revoked while this process ran and the
			// daemon is still dialling. It is a refusal like the others and
			// is counted and named like them, or it would loop unseen.
			refuse("device_revoked", nil, id)
			_ = conn.Close(websocket.StatusPolicyViolation, "device revoked")
			return
		}
		// Logged after registration: a connection the hub refused never
		// connected, and must not read as if it had.
		slog.Info("bridge: daemon connected", "user_id", id.UserID, "login", identityLabel(id), "device_id", id.DeviceID)

		// Parent context for both goroutines. Cancelling it stops the
		// reader and the writer cleanly without leaking goroutines.
		ctx, cancel := context.WithCancel(serverCtx)
		defer cancel()

		done := make(chan struct{}, 2)

		// pingPending is atomically set to 1 by the writer after sending a
		// ping, and cleared to 0 by the reader after receiving any frame.
		// The reader enforces a pongDeadline-long context timeout while
		// pingPending is 1 so a silent daemon is detected quickly.
		var pingPending atomic.Int32

		// reader goroutine: receive frames from the daemon.
		go func() {
			defer func() { done <- struct{}{} }()
			for {
				// Every read is bounded by a deadline so a silent daemon can
				// never block the reader indefinitely — even when the ping is
				// sent by the writer *after* this read has already begun (in
				// which case pingPending is still 0 at this point). The base
				// bound is pingInterval+pongDeadline, the maximum gap between
				// frames on a healthy connection (the writer pings every
				// pingInterval and a live daemon answers within pongDeadline).
				// When a ping is already outstanding we tighten the bound to
				// pongDeadline for fast detection. readCancel is called
				// explicitly (not via defer) so each iteration gets a fresh
				// context rather than accumulating cancelled ones.
				readTimeout := pingInterval + pongDeadline
				if pingPending.Load() != 0 {
					readTimeout = pongDeadline
				}
				readCtx, readCancel := context.WithTimeout(ctx, readTimeout)
				var env Envelope
				err := wsjson.Read(readCtx, conn, &env)
				readCancel()
				if err != nil {
					// Connection closed, context cancelled, or pong deadline
					// exceeded — any of these terminates the connection.
					return
				}
				// Any frame resets the ping-pending flag, including pong.
				pingPending.Store(0)
				switch env.Type {
				case TypePing:
					pong := Envelope{Type: TypePong, ID: env.ID}
					_ = wsjson.Write(ctx, conn, pong)
				case TypeResponse, TypeError:
					hub.Deliver(id.UserID, env)
				default:
					// Unexpected frame types are silently dropped.
				}
			}
		}()

		// writer goroutine: forward Hub-queued envelopes to the daemon plus
		// send periodic pings to detect a dead connection.
		go func() {
			defer func() { done <- struct{}{} }()
			ticker := time.NewTicker(pingInterval)
			defer ticker.Stop()
			for {
				select {
				case env, ok := <-send:
					if !ok {
						// Channel closed by Hub.Unregister or a newer Register.
						return
					}
					if err := wsjson.Write(ctx, conn, env); err != nil {
						return
					}
				case <-ticker.C:
					ping := Envelope{Type: TypePing, ID: "ping"}
					// Mark the pong as expected BEFORE writing the ping. If the
					// daemon's reply were processed by the reader before this
					// store, the reader could clear a flag that was never set,
					// leaving pingPending=1 with no outstanding ping. Setting it
					// first closes that (sub-microsecond) window; a spurious
					// extra pong only re-clears an already-clear flag.
					pingPending.Store(1)
					if err := wsjson.Write(ctx, conn, ping); err != nil {
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		// Wait for either goroutine to finish, then clean up.
		// Use UnregisterSend instead of Unregister: if a new daemon already
		// called Register(userID) and replaced the map entry, this leaves the
		// new connection intact rather than evicting it.
		<-done
		cancel()
		hub.UnregisterSend(id.UserID, send)
		_ = conn.Close(websocket.StatusNormalClosure, "done")
		slog.Info("bridge: daemon disconnected", "user_id", id.UserID, "login", identityLabel(id))
	}
}

// claimedIdentityFields is what the bridge handler logs about a token it
// refused: the numeric identifiers among its claims, read without verifying
// anything. The bearer verifier has already rejected the token, so nothing
// here is trusted; it is context for an operator reading the log. Only
// numbers are taken on purpose -- tg_id names the account as well as sub
// ("tg:<id>") would, and a number cannot carry free text from an
// unauthenticated caller into the log.
type claimedIdentityFields struct {
	TelegramID int64
	ExpiresAt  string
	IssuedAt   string
}

// maxClaimedPayloadLen bounds what an unauthenticated caller can make this
// decode: /bridge sits in front of any credential check and behind no rate
// limiter. A real payload is a few hundred bytes.
const maxClaimedPayloadLen = 4096

// claimedIdentity decodes the payload of the bearer JWT on r, if any, into
// the fields above. It is total on purpose -- it runs on the failure path:
// an oversized payload, a non-JWT bearer or a claim of the wrong type yields
// zero values for what could not be read and never an error, and every
// field is decoded on its own so one odd claim does not drop the others.
func claimedIdentity(r *http.Request) claimedIdentityFields {
	var out claimedIdentityFields
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return out
	}
	parts := strings.Split(strings.TrimSpace(h[len(prefix):]), ".")
	if len(parts) != 3 || len(parts[1]) > maxClaimedPayloadLen {
		return out
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return out
	}
	var c map[string]any
	if json.Unmarshal(payload, &c) != nil {
		return out
	}
	// NumericDate and tg_id are JSON numbers (RFC 7519 §2); a fraction or an
	// exponent form is still a number.
	if v, ok := c["tg_id"].(float64); ok {
		out.TelegramID = int64(v)
	}
	if v, ok := c["exp"].(float64); ok && v > 0 {
		out.ExpiresAt = time.Unix(int64(v), 0).UTC().Format(time.RFC3339)
	}
	if v, ok := c["iat"].(float64); ok && v > 0 {
		out.IssuedAt = time.Unix(int64(v), 0).UTC().Format(time.RFC3339)
	}
	return out
}
