package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gotd/td/tgerr"
	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/audit"
)

type catalogEntry struct {
	message string
	action  string
}

type transientEntry struct {
	message           string
	action            string
	retryAfterSeconds int
}

var mtprotoErrCatalog = map[string]catalogEntry{
	// A frozen account (https://core.telegram.org/api/auth#frozen-accounts)
	// keeps read access while Telegram reviews it; most writes fail with
	// FROZEN_METHOD_INVALID. Retrying cannot help and only adds to the
	// traffic that got the account frozen (#853).
	"FROZEN_METHOD_INVALID": {
		message: "Telegram has frozen this account: it can still read, but Telegram refuses this action.",
		action:  "Do not retry. The account owner can appeal in the Telegram app or by messaging @SpamBot (https://t.me/spambot).",
	},
	"FROZEN_PARTICIPANT_MISSING": {
		message: "Telegram has frozen this account and removed it from that chat's participants, so it cannot act there.",
		action:  "Do not retry. The account owner can appeal in the Telegram app or by messaging @SpamBot (https://t.me/spambot).",
	},
	"PEER_ID_INVALID": {
		message: "The peer ID is not valid for this account. Use @username, user:<id>, chat:<id>, or channel:<id>.",
		action:  "Call list_dialogs and pass the id exactly as returned there — a bare numeric id copied from a link or forwarded-message header carries no access hash.",
	},
	"CHANNEL_INVALID": {
		message: "The channel or supergroup reference is not valid for this account.",
		action:  "Call list_dialogs and pass the id exactly as returned there — a bare numeric id copied from a link or forwarded-message header carries no access hash.",
	},
	"CHAT_ID_INVALID": {
		message: "The chat reference is not valid for this account.",
		action:  "Call list_dialogs and pass the id exactly as returned there — a bare numeric id copied from a link or forwarded-message header carries no access hash.",
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

// mtprotoTransientCatalog lists MTProto error codes that are not permanent
// permission failures and should be surfaced with a structured RISK_GATED
// envelope, so callers back off instead of treating them as a bad argument.
var mtprotoTransientCatalog = map[string]transientEntry{
	// PEER_FLOOD is Telegram's anti-spam verdict on the account, not a rate
	// limit with a wait: repeating the refused call is what gets accounts
	// banned. The server pauses writes from the account for
	// audit.PeerFloodHold (#849), and retry_after_seconds says when that
	// pause ends, not when Telegram will lift its restriction.
	"PEER_FLOOD": {
		message:           "Telegram's anti-spam system has restricted this account from starting new conversations or messaging this peer.",
		action:            "Do not retry. Writes from this account are paused for " + peerFloodHoldText + ". The account owner can check the restriction by messaging @SpamBot in Telegram.",
		retryAfterSeconds: int(audit.PeerFloodHold / time.Second),
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

	slog.Warn("mcp mtproto error", "tool", tool, "mtproto_code", rpcErr.Message, "http_code", rpcErr.Code)

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

	if entry, ok := mtprotoTransientCatalog[rpcErr.Message]; ok {
		envelope := map[string]any{
			"error":               "RISK_GATED",
			"message":             entry.message,
			"retry_after_seconds": entry.retryAfterSeconds,
			"action":              entry.action,
		}
		b, err := json.Marshal(envelope)
		if err != nil {
			return mcplib.NewToolResultError(entry.message + " " + entry.action)
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
