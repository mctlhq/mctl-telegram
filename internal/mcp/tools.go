package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

func (s *Server) toolListDialogs() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("list_dialogs",
		mcplib.WithTitleAnnotation("List Telegram Dialogs"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription(`List the operator's Telegram dialogs with type, title, username and unread count.

Inputs:
  limit — int, default 50, max 200
  query — optional substring filter, case-insensitive, matches title or @username.

Output: JSON array of {id, type, title, username, unread_count, last_message_date}.
Dialog ids are returned in canonical form ("user:<id>", "chat:<id>", "channel:<id>") usable by the other tools.`),
		mcplib.WithNumber("limit",
			mcplib.Description("Max number of dialogs to return (default 50, max 200)."),
		),
		mcplib.WithString("query",
			mcplib.Description("Case-insensitive substring filter on title or @username."),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := auth.From(ctx)
		if err := requireScope(id, "telegram:dialogs:read"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		args := req.GetArguments()
		limit := intArg(args, "limit", 50)
		query := stringArg(args, "query", "")
		var dialogs []telegram.Dialog
		err := s.Pool.Borrow(ctx, id.UserID, func(ctx context.Context, c *gotdtelegram.Client) error {
			var err error
			dialogs, err = telegram.ListDialogs(ctx, c, limit, query)
			return err
		})
		s.audit(ctx, id, "list_dialogs", "", err)
		if err != nil {
			return toolErr("list_dialogs: %v", err), nil
		}
		return jsonResult(map[string]any{"dialogs": dialogs})
	}
	return tool, handler
}

func (s *Server) toolGetUnreadMessages() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("get_unread_messages",
		mcplib.WithTitleAnnotation("Get Unread Messages"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription(`Fetch unread messages, optionally scoped to one peer.

Inputs:
  peer — optional: "@username", "user:<id>", "chat:<id>", "channel:<id>".
  limit — int, default 50, max 200.

Output: JSON array of {id, peer, peer_title, from, text, date}.
Empty result means no unread messages match (including: peer has unread but text was a media-only message).`),
		mcplib.WithString("peer",
			mcplib.Description("Optional peer to scope to (@username or user/chat/channel id)."),
		),
		mcplib.WithNumber("limit",
			mcplib.Description("Max messages to return across all peers (default 50, max 200)."),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := auth.From(ctx)
		if err := requireScope(id, "telegram:messages:read"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		args := req.GetArguments()
		peer := stringArg(args, "peer", "")
		limit := intArg(args, "limit", 50)
		var msgs []telegram.Message
		err := s.Pool.Borrow(ctx, id.UserID, func(ctx context.Context, c *gotdtelegram.Client) error {
			var err error
			msgs, err = telegram.GetUnreadMessages(ctx, c, peer, limit)
			return err
		})
		s.audit(ctx, id, "get_unread_messages", telegram.RedactPeer(peer), err)
		if err != nil {
			return toolErr("get_unread_messages: %v", err), nil
		}
		return jsonResult(map[string]any{"messages": msgs})
	}
	return tool, handler
}

func (s *Server) toolSendMessage() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("send_message",
		mcplib.WithTitleAnnotation("Send Telegram Message"),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithDescription(`Send a Telegram message OR preview the send as a dry-run draft.

Inputs (required):
  peer — "@username", "user:<id>", "chat:<id>", or "channel:<id>".
  text — message body (plain text).
Inputs (optional):
  mode — "draft" (default) or "send". Default is dry-run.

Real sending requires ALL of: ALLOW_SEND=true on server, identity has "telegram:messages:send" scope, mode="send". Otherwise the response is a dry-run preview with reason in dry_reason.`),
		mcplib.WithString("peer",
			mcplib.Required(),
			mcplib.Description("Peer to send to."),
		),
		mcplib.WithString("text",
			mcplib.Required(),
			mcplib.Description("Message text to send."),
		),
		mcplib.WithString("mode",
			mcplib.Description("draft (default) or send."),
			mcplib.Enum("draft", "send"),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := auth.From(ctx)
		args := req.GetArguments()
		peer := stringArg(args, "peer", "")
		text := stringArg(args, "text", "")
		mode := stringArg(args, "mode", "draft")
		if peer == "" || text == "" {
			return mcplib.NewToolResultError("peer and text are required"), nil
		}
		realSend, dryReason := evaluateSendGate(id, mode, s.AllowSend)
		var result *telegram.SendResult
		var err error
		if !realSend {
			// Dry-run never touches Telegram so we don't require TG_API_* configured.
			result, err = telegram.SendMessage(ctx, nil, peer, text, false, dryReason)
		} else {
			err = s.Pool.Borrow(ctx, id.UserID, func(ctx context.Context, c *gotdtelegram.Client) error {
				var inner error
				result, inner = telegram.SendMessage(ctx, c, peer, text, true, dryReason)
				return inner
			})
		}
		status := "draft"
		if realSend && err == nil {
			status = "sent"
		}
		s.audit(ctx, id, "send_message:"+status, telegram.RedactPeer(peer), err)
		if err != nil {
			return toolErr("send_message: %v", err), nil
		}
		return jsonResult(result)
	}
	return tool, handler
}

func (s *Server) toolGetMessages() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("get_messages",
		mcplib.WithTitleAnnotation("Get Messages"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDescription(`Fetch recent messages from a specific peer (full history, not just unread).

Inputs:
  peer — required: "@username", "user:<id>", "chat:<id>", "channel:<id>".
  limit — int, default 50, max 200.

Output: JSON array of {id, peer, peer_title, text, date}.`),
		mcplib.WithString("peer",
			mcplib.Required(),
			mcplib.Description("Peer to fetch messages from (@username or user/chat/channel id)."),
		),
		mcplib.WithNumber("limit",
			mcplib.Description("Max messages to return (default 50, max 200)."),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := auth.From(ctx)
		if err := requireScope(id, "telegram:messages:read"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		args := req.GetArguments()
		peer := stringArg(args, "peer", "")
		limit := intArg(args, "limit", 50)
		if peer == "" {
			return mcplib.NewToolResultError("peer is required"), nil
		}
		var msgs []telegram.Message
		err := s.Pool.Borrow(ctx, id.UserID, func(ctx context.Context, c *gotdtelegram.Client) error {
			var err error
			msgs, err = telegram.GetMessages(ctx, c, peer, limit)
			return err
		})
		s.audit(ctx, id, "get_messages", telegram.RedactPeer(peer), err)
		if err != nil {
			return toolErr("get_messages: %v", err), nil
		}
		return jsonResult(map[string]any{"messages": msgs})
	}
	return tool, handler
}

func (s *Server) toolPinMessage() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("pin_message",
		mcplib.WithTitleAnnotation("Pin / Unpin Telegram Message"),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithDescription(`Pin or unpin a message in a Telegram chat. Requires the operator to have "Pin Messages" admin rights in the target chat.

Inputs:
  peer — required: "@username", "user:<id>", "chat:<id>", "channel:<id>".
  message_id — required: integer ID of the message to pin/unpin.
  unpin — optional bool, default false. Set to true to unpin.

Use get_messages to find message IDs before calling this tool.`),
		mcplib.WithString("peer",
			mcplib.Required(),
			mcplib.Description("Peer (chat/group/channel) containing the message."),
		),
		mcplib.WithNumber("message_id",
			mcplib.Required(),
			mcplib.Description("ID of the message to pin or unpin."),
		),
		mcplib.WithBoolean("unpin",
			mcplib.Description("Set to true to unpin instead of pin (default: false)."),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := auth.From(ctx)
		if err := requireScope(id, "telegram:messages:pin"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		args := req.GetArguments()
		peer := stringArg(args, "peer", "")
		messageID := intArg(args, "message_id", 0)
		unpin := boolArg(args, "unpin", false)
		if peer == "" || messageID == 0 {
			return mcplib.NewToolResultError("peer and message_id are required"), nil
		}
		var err error
		poolErr := s.Pool.Borrow(ctx, id.UserID, func(ctx context.Context, c *gotdtelegram.Client) error {
			return telegram.PinMessage(ctx, c, peer, messageID, unpin)
		})
		err = poolErr
		action := "pinned"
		if unpin {
			action = "unpinned"
		}
		s.audit(ctx, id, "pin_message:"+action, telegram.RedactPeer(peer), err)
		if err != nil {
			return toolErr("pin_message: %v", err), nil
		}
		return jsonResult(map[string]any{"status": action, "peer": peer, "message_id": messageID})
	}
	return tool, handler
}

func evaluateSendGate(id *auth.Identity, mode string, allowSend bool) (real bool, reason string) {
	if mode != "send" {
		return false, "mode=draft (default) — call with mode:'send' to send for real"
	}
	if !allowSend {
		return false, "server flag ALLOW_SEND=false — flip in deployment env to allow real sends"
	}
	if id == nil {
		return false, "no authenticated identity (send requires auth)"
	}
	if !id.HasScope("telegram:messages:send") {
		return false, "identity missing telegram:messages:send scope"
	}
	return true, ""
}

func requireScope(id *auth.Identity, scope string) error {
	if id == nil {
		return errors.New("authentication required")
	}
	if !id.HasScope(scope) {
		return fmt.Errorf("identity missing scope %s", scope)
	}
	return nil
}

func jsonResult(v any) (*mcplib.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcplib.NewToolResultError("encode: " + err.Error()), nil
	}
	return mcplib.NewToolResultText(string(b)), nil
}

func (s *Server) audit(ctx context.Context, id *auth.Identity, tool, peer string, err error) {
	uid := int64(0)
	if id != nil {
		uid = id.UserID
	}
	status := "ok"
	msg := ""
	if err != nil {
		status = "error"
		msg = err.Error()
	}
	s.Store.LogToolCall(ctx, uid, tool, peer, status, msg)
}

func stringArg(args map[string]any, key, def string) string {
	if v, ok := args[key].(string); ok && v != "" {
		return v
	}
	return def
}

func boolArg(args map[string]any, key string, def bool) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return def
}

func intArg(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	}
	return def
}
