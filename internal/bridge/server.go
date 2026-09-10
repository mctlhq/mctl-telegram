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
		id, err := provider.Authenticate(r)
		if err != nil {
			// Do not echo err.Error(): JWT parsers include algorithm names,
			// claim paths and token fragments. Log server-side only.
			//
			// The claims are logged unverified, as identifiers for the
			// operator: a daemon that is refused here is the one incident
			// this endpoint has, and the line naming which daemon is the
			// difference between a minute and two days of looking (#612).
			// They are never used for a decision; the token itself is not
			// logged.
			reason := auth.ClassifyAuthError(err.Error())
			if m != nil {
				m.AuthFailuresTotal.WithLabelValues(reason, "bridge").Inc()
			}
			c := claimedIdentity(r)
			slog.Info("bridge: authentication failed", "err", err, "reason", reason,
				"claimed_sub", c.Subject, "claimed_tg_id", c.TelegramID, "claimed_device_id", c.DeviceID,
				"claimed_exp", c.ExpiresAt, "claimed_iat", c.IssuedAt)
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		if id == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mctl-telegram-bridge"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if id.DeviceID == "" {
			slog.Info("bridge: credential missing device binding", "user_id", id.UserID)
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

		slog.Info("bridge: daemon connected", "user_id", id.UserID, "login", identityLabel(id), "device_id", id.DeviceID)
		if beforeRegister != nil {
			beforeRegister()
		}
		send, registered := hub.TryRegister(id.UserID, id.DeviceID)
		if !registered {
			_ = conn.Close(websocket.StatusPolicyViolation, "device revoked")
			return
		}

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
// refused: the identifying claims, read without verifying anything. The
// bearer verifier has already rejected the token, so nothing here is
// trusted; it is context for an operator reading the log.
type claimedIdentityFields struct {
	Subject    string
	TelegramID int64
	DeviceID   string
	ExpiresAt  string
	IssuedAt   string
}

// claimedIdentity decodes the payload of the bearer JWT on r, if any, into
// the identifying fields above. Malformed input yields zero values; it
// never fails, because it runs on the failure path.
func claimedIdentity(r *http.Request) claimedIdentityFields {
	var out claimedIdentityFields
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return out
	}
	parts := strings.Split(strings.TrimSpace(h[len(prefix):]), ".")
	if len(parts) != 3 {
		return out
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return out
	}
	var c struct {
		Sub      string `json:"sub"`
		TgID     int64  `json:"tg_id"`
		DeviceID string `json:"device_id"`
		Exp      int64  `json:"exp"`
		Iat      int64  `json:"iat"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return out
	}
	out.Subject, out.TelegramID, out.DeviceID = c.Sub, c.TgID, c.DeviceID
	if c.Exp > 0 {
		out.ExpiresAt = time.Unix(c.Exp, 0).UTC().Format(time.RFC3339)
	}
	if c.Iat > 0 {
		out.IssuedAt = time.Unix(c.Iat, 0).UTC().Format(time.RFC3339)
	}
	return out
}
