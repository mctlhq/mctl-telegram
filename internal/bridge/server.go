package bridge

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

const pingInterval = 25 * time.Second

// NewBridgeHandler returns an http.HandlerFunc that upgrades HTTP connections
// to websockets and wires them into the Hub as Local Bridge daemon connections.
//
// Authentication: the handler verifies a bearer JWT using the supplied
// provider, which MUST be configured with AudienceRequired=true and
// ExpectedAudience="bridge" so that regular MCP tokens are rejected.
//
// Only accounts whose telegram_accounts.mode is 'local' are accepted; a
// hosted-mode account attempting to register here receives HTTP 400.
func NewBridgeHandler(hub *Hub, provider auth.Provider, store *db.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate before upgrading — upgrading first wastes resources if
		// the token is invalid and makes error reporting harder.
		id, err := provider.Authenticate(r)
		if err != nil {
			http.Error(w, "invalid credentials: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if id == nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mctl-telegram-bridge"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
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

		slog.Info("bridge: daemon connected", "user_id", id.UserID, "login", id.GitHubLogin)
		send := hub.Register(id.UserID)

		// Parent context for both goroutines. Cancelling it stops the
		// reader and the writer cleanly without leaking goroutines.
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		done := make(chan struct{}, 2)

		// reader goroutine: receive frames from the daemon.
		go func() {
			defer func() { done <- struct{}{} }()
			for {
				var env Envelope
				if err := wsjson.Read(ctx, conn, &env); err != nil {
					// Connection closed or context cancelled — either is expected.
					return
				}
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
		slog.Info("bridge: daemon disconnected", "user_id", id.UserID, "login", id.GitHubLogin)
	}
}
