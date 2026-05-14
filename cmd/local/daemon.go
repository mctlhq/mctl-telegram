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
	reconnectBase   = 2 * time.Second
	reconnectMax    = 60 * time.Second
	pingInterval    = 25 * time.Second
	tokenRefreshAdv = 5 * time.Minute
)

// runDaemon runs the persistent websocket loop against the bridge server.
// It reloads the bridge token on every attempt (picks up a freshly rotated
// token) and reconnects with exponential backoff when the connection drops.
func runDaemon(ctx context.Context, cfg *localConfig, pool *tg.ClientPool, userID int64) error {
	backoff := reconnectBase
	for {
		bt, err := loadBridgeToken()
		if err != nil {
			return fmt.Errorf("load bridge token: %w", err)
		}
		err = daemonSession(ctx, cfg, bt, pool, userID)
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
//
// coder/websocket ties the connection lifetime to the context passed to
// wsjson.Read — cancelling or timing out that context closes the underlying
// connection. We therefore use a plain blocking read in a dedicated goroutine
// and handle pings in a separate ticker goroutine, communicating via channels.
func daemonSession(ctx context.Context, cfg *localConfig, bt *bridgeTokenFile, pool *tg.ClientPool, userID int64) error {
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

	if expiry, err := bridgeTokenExpiry(bt); err != nil {
		slog.Warn("could not parse bridge token expiry; auto-refresh disabled", "err", err)
	} else if !expiry.IsZero() && time.Until(expiry) <= tokenRefreshAdv {
		slog.Warn("bridge token nearing expiry; run connect again",
			"expires_at", expiry.Format(time.RFC3339),
			"remaining", time.Until(expiry).Round(time.Second))
	}

	recv := make(chan bridge.Envelope, 8)
	readErr := make(chan error, 1)

	go func() {
		for {
			var env bridge.Envelope
			if err := wsjson.Read(ctx, conn, &env); err != nil {
				select {
				case readErr <- err:
				default:
				}
				return
			}
			select {
			case recv <- env:
			case <-ctx.Done():
				return
			}
		}
	}()

	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()
	pingErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-pingTicker.C:
				ping := bridge.Envelope{Type: bridge.TypePing, ID: "ping"}
				if werr := wsjson.Write(ctx, conn, ping); werr != nil {
					select {
					case pingErr <- fmt.Errorf("write ping: %w", werr):
					default:
					}
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			_ = conn.Close(websocket.StatusNormalClosure, "shutdown")
			return nil
		case err := <-pingErr:
			return err
		case err := <-readErr:
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read: %w", err)
		case env := <-recv:
			switch env.Type {
			case bridge.TypePing:
				pong := bridge.Envelope{Type: bridge.TypePong, ID: env.ID}
				if werr := wsjson.Write(ctx, conn, pong); werr != nil {
					return fmt.Errorf("write pong: %w", werr)
				}
			case bridge.TypeCall:
				go func(e bridge.Envelope) {
					resp := dispatchCall(ctx, pool, userID, e)
					if werr := wsjson.Write(ctx, conn, resp); werr != nil {
						slog.Warn("write response failed", "id", e.ID, "err", werr)
					}
				}(env)
			default:
				slog.Debug("unexpected frame type", "type", env.Type, "id", env.ID)
			}
		}
	}
}

// dispatchCall routes a TypeCall envelope to the appropriate Telegram function
// and returns a TypeResponse or TypeError envelope.
func dispatchCall(ctx context.Context, pool *tg.ClientPool, userID int64, env bridge.Envelope) bridge.Envelope {
	slog.Info("dispatch", "tool", env.Tool, "id", env.ID)

	var (
		result  json.RawMessage
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
		dispErr = pool.Borrow(ctx, userID, func(ctx context.Context, c *telegram.Client) error {
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
		dispErr = pool.Borrow(ctx, userID, func(ctx context.Context, c *telegram.Client) error {
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
		dispErr = pool.Borrow(ctx, userID, func(ctx context.Context, c *telegram.Client) error {
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
		dispErr = pool.Borrow(ctx, userID, func(ctx context.Context, c *telegram.Client) error {
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
		dispErr = pool.Borrow(ctx, userID, func(ctx context.Context, c *telegram.Client) error {
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
	s := server
	switch {
	case strings.HasPrefix(s, "https://"):
		s = "wss://" + s[len("https://"):]
	case strings.HasPrefix(s, "http://"):
		s = "ws://" + s[len("http://"):]
	}
	s = strings.TrimRight(s, "/")
	return s + "/bridge"
}
