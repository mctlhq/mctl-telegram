package mcp

// hidden.go enforces the account's hidden chats (mctl-telegram#1152): the
// dialogs the owner hid on the manage page are invisible to every connected
// client. Three layers:
//
//  1. hiddenScopeGuard (tool-handler middleware) reads the account's set,
//     fails closed when it cannot, and refuses a call whose peer argument is
//     a hidden chat before the handler runs. It does this for every mode,
//     so a Local Bridge account is covered without the daemon's help.
//  2. The same middleware puts the set into ctx, where the telegram package
//     refuses a hidden chat however the peer was spelled (@username,
//     cached resolution, dialog scans) and leaves it out of listings.
//  3. On the way out it drops hidden chats from dialogs, messages, search
//     matches and sponsored entries, which is what covers the bridge's own
//     listings.
//
// No MCP tool writes the set; only the manage page does.

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// dialogScope says how a tool relates to the hidden-chat scope.
type dialogScope int

const (
	// scopeDialogs: the tool reads or writes Telegram dialogs, so it runs
	// under the account's hidden set.
	scopeDialogs dialogScope = iota + 1
	// scopeExempt: the tool touches no dialog (account controls, audit,
	// assistants, admin tools, folder metadata).
	scopeExempt
)

// toolDialogScope classifies every registered tool;
// TestToolDialogScope_CoversRegistry fails for a tool missing here, so a new
// tool cannot silently bypass the scope.
var toolDialogScope = map[string]dialogScope{
	"delete_messages":      scopeDialogs,
	"draft_reply":          scopeDialogs,
	"edit_message":         scopeDialogs,
	"forward_messages":     scopeDialogs,
	"get_media":            scopeDialogs,
	"get_messages":         scopeDialogs,
	"get_unread_messages":  scopeDialogs,
	"list_dialogs":         scopeDialogs,
	"list_topics":          scopeDialogs,
	"pin_message":          scopeDialogs,
	"prepare_get_media":    scopeDialogs,
	"prepare_pin_message":  scopeDialogs,
	"prepare_send_message": scopeDialogs,
	"search_messages":      scopeDialogs,
	"send_media":           scopeDialogs,
	"send_message":         scopeDialogs,
	"send_reply":           scopeDialogs,
	"save_draft":           scopeDialogs,
	"set_reaction":         scopeDialogs,

	// list_folders returns folder names and member counts, never members.
	"list_folders": scopeExempt,

	"cancel_broadcast":                scopeExempt,
	"delete_fork":                     scopeExempt,
	"delete_telegram_account":         scopeExempt,
	"disconnect_telegram_account":     scopeExempt,
	"fork_assistant":                  scopeExempt,
	"get_acquisition_report":          scopeExempt,
	"get_broadcast":                   scopeExempt,
	"get_my_audit_log":                scopeExempt,
	"get_my_identity":                 scopeExempt,
	"get_my_notification_preferences": scopeExempt,
	"get_my_send_status":              scopeExempt,
	"get_user_audit_log":              scopeExempt,
	"install_assistant":               scopeExempt,
	"list_assistants":                 scopeExempt,
	"list_broadcasts":                 scopeExempt,
	"list_telegram_identities":        scopeExempt,
	"mint_worker_token":               scopeExempt,
	"prepare_broadcast":               scopeExempt,
	"provision_local_account":         scopeExempt,
	"revoke_local_bridge_device":      scopeExempt,
	"revoke_telegram_session":         scopeExempt,
	"revoke_worker_token":             scopeExempt,
	"set_account_mode":                scopeExempt,
	"set_account_send":                scopeExempt,
	"set_my_notification_preferences": scopeExempt,
	"set_send_consent":                scopeExempt,
	"set_telegram_access":             scopeExempt,
	"update_fork":                     scopeExempt,
	"update_install":                  scopeExempt,
}

// peerArgKeys are the arguments that name a dialog.
var peerArgKeys = []string{"peer", "from_peer", "to_peer"}

// hiddenStore is the part of db.Store the guard needs.
type hiddenStore interface {
	ListHiddenDialogs(ctx context.Context, userID int64) ([]db.HiddenDialog, error)
	GetAccountMode(ctx context.Context, userID int64) (string, error)
}

// msgHiddenUnreadable is the refusal when the set cannot be read: running
// the call without it would show chats the owner hid.
const msgHiddenUnreadable = "blocked: could not read this account's hidden chats; try again"

// hiddenRefusalText is the refusal for a hidden chat. The " blocked: "
// infix is what classifyToolResultReason reads as a refusal.
func hiddenRefusalText(tool string) string {
	return tool + " blocked: " + telegram.ErrPeerHidden.Error() +
		" (the account owner hid it on the manage page; only they can show it again)"
}

// msgHiddenNeedsID is the refusal for a Local Bridge call that names a chat
// by username while chats are hidden: the server cannot resolve it, so it
// cannot tell whether it is hidden.
func msgHiddenNeedsID(tool string) string {
	return tool + " blocked: this account hides some chats, so a Local Bridge call must name the chat by id " +
		`("user:<id>", "chat:<id>", "channel:<id>" from list_dialogs), not by username`
}

// hiddenScopeGuard is tool-handler middleware; see the file comment.
func (s *Server) hiddenScopeGuard(next mcpserver.ToolHandlerFunc) mcpserver.ToolHandlerFunc {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := auth.From(ctx)
		name := req.Params.Name
		if id == nil || s.Store == nil || toolDialogScope[name] != scopeDialogs {
			return next(ctx, req)
		}
		return s.runHiddenScoped(ctx, s.Store, id, name, req, next)
	}
}

func (s *Server) runHiddenScoped(ctx context.Context, store hiddenStore, id *auth.Identity, name string, req mcplib.CallToolRequest, next mcpserver.ToolHandlerFunc) (*mcplib.CallToolResult, error) {
	rows, err := store.ListHiddenDialogs(ctx, id.UserID)
	if err != nil {
		hintReason(ctx, ReasonStoreError)
		return mcplib.NewToolResultError(name + " " + msgHiddenUnreadable), nil
	}
	set := make(telegram.HiddenPeers, len(rows))
	for _, r := range rows {
		set[r.Peer] = true
	}
	if len(set) > 0 {
		local := false
		args := req.GetArguments()
		for _, key := range peerArgKeys {
			raw := peerArgString(args[key])
			if strings.TrimSpace(raw) == "" {
				continue
			}
			if ref, ok := argDialogRef(raw); ok {
				if set[ref] {
					hintReason(ctx, ReasonRefused)
					return mcplib.NewToolResultError(hiddenRefusalText(name)), nil
				}
				continue
			}
			// A username. Hosted calls resolve it under the set (layer 2);
			// a Local Bridge daemon resolves it where the server cannot see.
			if !local {
				mode, err := store.GetAccountMode(ctx, id.UserID)
				if err != nil {
					hintReason(ctx, ReasonStoreError)
					return mcplib.NewToolResultError(name + " " + msgHiddenUnreadable), nil
				}
				local = mode == "local"
			}
			if local {
				hintReason(ctx, ReasonRefused)
				return mcplib.NewToolResultError(msgHiddenNeedsID(name)), nil
			}
		}
	}
	res, err := next(telegram.WithHiddenPeers(ctx, set), req)
	if err != nil || res == nil {
		return res, err
	}
	if res.IsError {
		if strings.Contains(firstResultText(res), telegram.ErrPeerHidden.Error()) {
			hintReason(ctx, ReasonRefused)
		}
		return res, nil
	}
	if len(set) > 0 {
		dropHiddenFromResult(res, set)
	}
	return res, nil
}

// argDialogRef maps a peer argument to its canonical ref the way
// telegram.ResolvePeer reads it: "user:/chat:/channel:<id>", or a bare
// positive number as a user id. ok=false means anything else.
func argDialogRef(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if ref, ok := db.CanonicalDialogRef(raw); ok {
		return ref, true
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
		return fmt.Sprintf("user:%d", n), true
	}
	// Anything else (a username, a malformed or non-positive id) is not
	// checked here: a hosted call resolves it under the hidden set, and a
	// Local Bridge call is refused while anything is hidden.
	return "", false
}

// peerArgString reads a peer argument sent as a JSON string or number.
func peerArgString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	}
	return ""
}

// hiddenResultFields lists the result arrays that carry dialogs, and the
// field naming each entry's chat.
var hiddenResultFields = map[string]string{
	"dialogs":   "id",
	"messages":  "peer",
	"matches":   "peer",
	"sponsored": "channel",
}

// dropHiddenFromResult removes hidden chats from a successful JSON result,
// rewriting both the text and the structured content when anything went.
func dropHiddenFromResult(res *mcplib.CallToolResult, set telegram.HiddenPeers) {
	idx := -1
	var text string
	for i, c := range res.Content {
		if tc, ok := mcplib.AsTextContent(c); ok {
			idx, text = i, tc.Text
			break
		}
	}
	if idx < 0 {
		return
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(text), &body); err != nil {
		return
	}
	changed := false
	for field, key := range hiddenResultFields {
		items, ok := body[field].([]any)
		if !ok {
			continue
		}
		kept := make([]any, 0, len(items))
		for _, it := range items {
			if m, ok := it.(map[string]any); ok {
				if ref, _ := m[key].(string); set[ref] {
					changed = true
					continue
				}
			}
			kept = append(kept, it)
		}
		body[field] = kept
	}
	if !changed {
		return
	}
	b, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return
	}
	res.Content[idx] = mcplib.NewTextContent(string(b))
	res.StructuredContent = body
}
