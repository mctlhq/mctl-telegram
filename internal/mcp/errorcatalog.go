package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/gotd/td/tgerr"
	mcplib "github.com/mark3labs/mcp-go/mcp"
)

type catalogEntry struct {
	message string
	action  string
}

var mtprotoErrCatalog = map[string]catalogEntry{
	"PEER_ID_INVALID": {
		message: "The peer ID is not valid for this account. Use @username, user:<id>, chat:<id>, or channel:<id>.",
		action:  "Check the peer argument and retry.",
	},
	"USERNAME_INVALID": {
		message: "The username is not valid.",
		action:  "Verify the @username and retry.",
	},
	"USERNAME_NOT_OCCUPIED": {
		message: "No Telegram account or channel has that username.",
		action:  "Verify the @username and retry.",
	},
	"CHAT_FORBIDDEN": {
		message: "The connected Telegram account does not have access to that chat.",
		action:  "Confirm the account is a member of the chat.",
	},
	"CHAT_WRITE_FORBIDDEN": {
		message: "The connected Telegram account cannot send messages to that chat.",
		action:  "Confirm the account has send permission.",
	},
	"USER_BANNED_IN_CHANNEL": {
		message: "The connected account has been banned from that channel.",
		action:  "The account cannot be used with this channel.",
	},
	"MESSAGE_ID_INVALID": {
		message: "That message ID does not exist in the chat.",
		action:  "Verify the message ID and retry.",
	},
	"MSG_ID_INVALID": {
		message: "That message ID does not exist in the chat.",
		action:  "Verify the message ID and retry.",
	},
	"INPUT_USER_DEACTIVATED": {
		message: "The target account has been deactivated.",
		action:  "",
	},
	"PHONE_NUMBER_INVALID": {
		message: "The phone number format is not valid.",
		action:  "Use E.164 format (e.g. +12025551234).",
	},
	"CHANNEL_PRIVATE": {
		message: "That channel is private and the account is not a member.",
		action:  "The account must be invited before it can access this channel.",
	},
	"USER_NOT_PARTICIPANT": {
		message: "The account is not a participant of that chat or channel.",
		action:  "Confirm the account has been added to the chat.",
	},
}

// floodWaitSeconds parses a FLOOD_WAIT_N or SLOWMODE_WAIT_N error code and
// returns the number of seconds to wait. Returns (0, false) if the code does
// not match either prefix or the suffix is not a valid integer.
func floodWaitSeconds(code string) (int, bool) {
	var suffix string
	switch {
	case strings.HasPrefix(code, "FLOOD_WAIT_"):
		suffix = strings.TrimPrefix(code, "FLOOD_WAIT_")
	case strings.HasPrefix(code, "SLOWMODE_WAIT_"):
		suffix = strings.TrimPrefix(code, "SLOWMODE_WAIT_")
	default:
		return 0, false
	}
	if suffix == "" {
		return 0, false
	}
	n, err := strconv.Atoi(suffix)
	if err != nil {
		return 0, false
	}
	return n, true
}

// mtprotoErrResult maps a known MTProto RPC error to a user-friendly MCP
// CallToolResult. Returns nil when err is not a tgerr.Error or the error code
// is not recognised, allowing callers to fall through to their generic handler.
func mtprotoErrResult(tool string, err error) *mcplib.CallToolResult {
	var rpcErr *tgerr.Error
	if !errors.As(err, &rpcErr) {
		return nil
	}

	slog.Warn("mcp mtproto error", "tool", tool, "message", rpcErr.Message, "code", rpcErr.Code)

	if n, ok := floodWaitSeconds(rpcErr.Message); ok {
		var errKey, msg string
		if strings.HasPrefix(rpcErr.Message, "FLOOD_WAIT_") {
			errKey = "flood_wait"
			msg = fmt.Sprintf("Telegram rate limit reached. Wait %d seconds before retrying.", n)
		} else {
			errKey = "slowmode_wait"
			msg = fmt.Sprintf("Telegram slow mode is active. Wait %d seconds before retrying.", n)
		}
		action := fmt.Sprintf("Wait %d seconds, then retry the same tool call.", n)
		envelope := map[string]any{
			"error":               errKey,
			"message":             msg,
			"retry_after_seconds": n,
			"action":              action,
		}
		b, err := json.Marshal(envelope)
		if err != nil {
			return mcplib.NewToolResultError(msg + " " + action)
		}
		return mcplib.NewToolResultError(string(b))
	}

	if entry, ok := mtprotoErrCatalog[rpcErr.Message]; ok {
		if entry.action == "" {
			return mcplib.NewToolResultError(entry.message)
		}
		return mcplib.NewToolResultError(entry.message + " " + entry.action)
	}

	return nil
}
