package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/gotd/td/telegram"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	tg "github.com/mctlhq/mctl-telegram/internal/telegram"
)

const (
	localUserID     = int64(1)
	reconnectBase   = 2 * time.Second
	reconnectMax    = 60 * time.Second
	pingInterval    = 25 * time.Second
	tokenRefreshAdv = 5 * time.Minute // refresh bridge token this far before expiry
)

// runDaemon runs the persistent websocket loop against the bridge server.
// It reconnects with exponential backoff when the connection drops.
func runDaemon(ctx context.Context, cfg *localConfig, bt *bridgeTokenFile, pool *tg.ClientPool) error {
	backoff := reconnectBase
	for {
		err := daemonSession(ctx, cfg, bt, pool)
		if err == nil || ctx.Err() != nil {
			return ctx.Err()
		}
		slog.Warn("bridge connection lost, reconnecting", "err", err, "wait", backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		backoff *= 2
		if backoff > reconnectMax {
			backoff = reconnectMax
		}
	}
}

// daemonSession runs one websocket connection to the bridge server until it
// drops or ctx is cancelled. Returns nil on clean disconnect, error otherwise.
func daemonSession(ctx context.Context, cfg *localConfig, bt *bridgeTokenFile, pool *tg.ClientPool) error {
	wsURL := bridgeWSURL(cfg.Server)
	slog.Info("connecting to bridge", "url", wsURL)

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: map[string][]string{
			"Authorization": {"Bearer " + bt.BridgeToken},
		},
	})
	if err != nil {
		return fmt.Errorf("dial bridge: %w", err)
	}
	defer conn.CloseNow()

	slog.Info("bridge connected")

	// Expiry-aware token refresh ticker: fire tokenRefreshAdv before expiry.
	expiry, err := bridgeTokenExpiry(bt)
	if err != nil {
		slog.Warn("could not parse bridge token expiry; auto-refresh disabled", "err", err)
		expiry = time.Time{}
	}

	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

	// Read frames and dispatch.
	for {
		// Check if token refresh is needed before blocking on receive.
		if !expiry.IsZero() && time.Until(expiry) <= tokenRefreshAdv {
			slog.Warn("bridge token nearing expiry; cannot auto-refresh without MCP token (run connect again)",
				"expires_at", expiry.Format(time.RFC3339),
				"remaining", time.Until(expiry).Round(time.Second))
		}

		// We need a non-blocking path for ping and context cancellation.
		// Use a short read timeout and handle ErrDeadlineExceeded inline.
		readCtx, readCancel := context.WithTimeout(ctx, 5*time.Second)
		var env bridge.Envelope
		readErr := wsjson.Read(readCtx, conn, &env)
		readCancel()

		if readErr != nil {
			if ctx.Err() != nil {
				// Graceful shutdown.
				_ = conn.Close(websocket.StatusNormalClosure, "shutdown")
				return nil
			}
			if isTimeoutError(readErr) {
				// Timeout — send ping and re-loop.
				select {
				case <-pingTicker.C:
					ping := bridge.Envelope{Type: bridge.TypePing, ID: "ping"}
					if werr := wsjson.Write(ctx, conn, ping); werr != nil {
						return fmt.Errorf("write ping: %w", werr)
					}
				default:
				}
				continue
			}
			return fmt.Errorf("read: %w", readErr)
		}

		switch env.Type {
		case bridge.TypePing:
			pong := bridge.Envelope{Type: bridge.TypePong, ID: env.ID}
			if werr := wsjson.Write(ctx, conn, pong); werr != nil {
				return fmt.Errorf("write pong: %w", werr)
			}

		case bridge.TypeCall:
			// Dispatch in a goroutine so the read loop stays unblocked.
			go func(e bridge.Envelope) {
				resp := dispatchCall(ctx, pool, e)
				if werr := wsjson.Write(ctx, conn, resp); werr != nil {
					slog.Warn("write response failed", "id", e.ID, "err", werr)
				}
			}(env)

		default:
			// Unexpected frame — ignore.
			slog.Debug("unexpected frame type", "type", env.Type, "id", env.ID)
		}
	}
}

// dispatchCall routes a TypeCall envelope to the appropriate Telegram function
// and returns a TypeResponse or TypeError envelope.
func dispatchCall(ctx context.Context, pool *tg.ClientPool, env bridge.Envelope) bridge.Envelope {
	slog.Info("dispatch", "tool", env.Tool, "id", env.ID)

	var (
		result json.RawMessage
		dispErr error
	)

	switch env.Tool {
	case "list_dialogs":
		var args struct {
			Limit int    `json:"limit"`
			Query string `json:"query"`
		}
		if err := json.Unmarshal(envArgs(env), &args); err != nil {
			return bridge.EncodeError(env.ID, fmt.Sprintf("list_dialogs: bad args: %v", err))
		}
		if args.Limit <= 0 {
			args.Limit = 50
		}
		var dialogs []tg.Dialog
		dispErr = pool.Borrow(ctx, localUserID, func(ctx context.Context, c *telegram.Client) error {
			var err error
			dialogs, err = tg.ListDialogs(ctx, c, args.Limit, args.Query)
			return err
		})
		if dispErr == nil {
			result, dispErr = json.Marshal(map[string]any{"dialogs": dialogs})
		}

	case "get_unread_messages":
		var args struct {
			Peer  string `json:"peer"`
			Limit int    `json:"limit"`
		}
		if err := json.Unmarshal(envArgs(env), &args); err != nil {
			return bridge.EncodeError(env.ID, fmt.Sprintf("get_unread_messages: bad args: %v", err))
		}
		if args.Limit <= 0 {
			args.Limit = 50
		}
		var msgs []tg.Message
		dispErr = pool.Borrow(ctx, localUserID, func(ctx context.Context, c *telegram.Client) error {
			var err error
			msgs, err = tg.GetUnreadMessages(ctx, c, args.Peer, args.Limit)
			return err
		})
		if dispErr == nil {
			result, dispErr = json.Marshal(map[string]any{"messages": msgs})
		}

	case "get_messages":
		var args struct {
			Peer  string `json:"peer"`
			Limit int    `json:"limit"`
		}
		if err := json.Unmarshal(envArgs(env), &args); err != nil {
			return bridge.EncodeError(env.ID, fmt.Sprintf("get_messages: bad args: %v", err))
		}
		if args.Limit <= 0 {
			args.Limit = 50
		}
		var msgs []tg.Message
		dispErr = pool.Borrow(ctx, localUserID, func(ctx context.Context, c *telegram.Client) error {
			var err error
			msgs, err = tg.GetMessages(ctx, c, args.Peer, args.Limit)
			return err
		})
		if dispErr == nil {
			result, dispErr = json.Marshal(map[string]any{"messages": msgs})
		}

	case "send_message":
		var args struct {
			Peer      string `json:"peer"`
			Text      string `json:"text"`
			Mode      string `json:"mode"`
			DryReason string `json:"dry_reason"`
		}
		if err := json.Unmarshal(envArgs(env), &args); err != nil {
			return bridge.EncodeError(env.ID, fmt.Sprintf("send_message: bad args: %v", err))
		}
		realSend := args.Mode == "send"
		dryReason := args.DryReason
		if !realSend && dryReason == "" {
			dryReason = "mode=draft"
		}
		var sendResult *tg.SendResult
		dispErr = pool.Borrow(ctx, localUserID, func(ctx context.Context, c *telegram.Client) error {
			var err error
			sendResult, err = tg.SendMessage(ctx, c, args.Peer, args.Text, realSend, dryReason)
			return err
		})
		if dispErr == nil {
			result, dispErr = json.Marshal(sendResult)
		}

	case "pin_message":
		var args struct {
			Peer      string `json:"peer"`
			MessageID int    `json:"message_id"`
			Unpin     bool   `json:"unpin"`
		}
		if err := json.Unmarshal(envArgs(env), &args); err != nil {
			return bridge.EncodeError(env.ID, fmt.Sprintf("pin_message: bad args: %v", err))
		}
		dispErr = pool.Borrow(ctx, localUserID, func(ctx context.Context, c *telegram.Client) error {
			return tg.PinMessage(ctx, c, args.Peer, args.MessageID, args.Unpin)
		})
		if dispErr == nil {
			action := "pinned"
			if args.Unpin {
				action = "unpinned"
			}
			result, dispErr = json.Marshal(map[string]any{
				"status":     action,
				"peer":       args.Peer,
				"message_id": args.MessageID,
			})
		}

	default:
		return bridge.EncodeError(env.ID, fmt.Sprintf("unknown tool: %q", env.Tool))
	}

	if dispErr != nil {
		slog.Warn("dispatch error", "tool", env.Tool, "id", env.ID, "err", dispErr)
		return bridge.EncodeError(env.ID, dispErr.Error())
	}
	slog.Info("dispatch ok", "tool", env.Tool, "id", env.ID)
	return bridge.EncodeResponse(env.ID, result)
}

// envArgs returns the args raw JSON from an envelope, substituting an empty
// object when Args is nil so json.Unmarshal always has something to parse.
func envArgs(env bridge.Envelope) json.RawMessage {
	if len(env.Args) == 0 {
		return json.RawMessage("{}")
	}
	return env.Args
}

// bridgeWSURL converts an https:// server URL to a wss:// websocket URL.
func bridgeWSURL(server string) string {
	// Replace scheme for websocket.
	s := server
	switch {
	case strings.HasPrefix(s, "https://"):
		s = "wss://" + s[len("https://"):]
	case strings.HasPrefix(s, "http://"):
		s = "ws://" + s[len("http://"):]
	}
	// Strip trailing slash.
	s = strings.TrimRight(s, "/")
	return s + "/bridge"
}

// isTimeoutError checks whether an error is a context deadline exceeded /
// websocket read deadline error. We use a timeout on each read to be able
// to send pings without a dedicated goroutine.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "i/o timeout")
}
