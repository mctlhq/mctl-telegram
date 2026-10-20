package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// toolScopes is the access contract of the tool surface: for every tool, the
// scopes of which an identity must hold at least one to see the tool in
// tools/list AND to call it. An empty, non-nil list means "any authenticated
// identity". A tool missing from this map is visible to nobody and callable
// by nobody, so a newly added tool fails closed until it is classified here;
// TestToolScopes_CoverEveryRegisteredTool turns that into a test failure
// rather than a silently hidden tool.
//
// It is enforced through mcpserver.WithToolFilter, which mcp-go applies on
// tools/list and again on tools/call before any handler runs. Before this
// existed, discovery was global: a read-only token was shown the admin and
// broadcast tools, and tools whose handler routed a missing scope through
// the send gate (send_message, edit_message, delete_messages,
// forward_messages, set_reaction) answered a successful dry-run preview
// instead of a refusal.
//
// The handlers keep their own requireScope checks. This table is the outer
// boundary, not a replacement for them.
var toolScopes = map[string][]string{
	// Reads.
	"list_dialogs":        {"telegram:dialogs:read"},
	"get_unread_messages": {"telegram:messages:read"},
	"get_messages":        {"telegram:messages:read"},
	"search_messages":     {"telegram:messages:read"},
	"prepare_get_media":   {"telegram:messages:read"},
	"get_media":           {"telegram:messages:read"},

	// Writes to Telegram. prepare_send_message issues the confirmation a
	// send consumes, so it is offered only to an identity that could send.
	"prepare_send_message": {"telegram:messages:send"},
	"send_message":         {"telegram:messages:send"},
	"send_media":           {"telegram:messages:send"},
	"edit_message":         {"telegram:messages:send"},
	"delete_messages":      {"telegram:messages:send"},
	"forward_messages":     {"telegram:messages:send"},
	"set_reaction":         {"telegram:messages:send"},
	"prepare_pin_message":  {"telegram:messages:pin"},
	"pin_message":          {"telegram:messages:pin"},

	// The caller's own state. Every credential may inspect itself.
	"get_my_identity":    {},
	"get_my_audit_log":   {},
	"get_my_send_status": {},
	// Ungated by a deliberate owner decision (2026-09-12, mctlhq/.github#35,
	// recorded in docs/portal-allowlist.json): the blast radius is the
	// caller's own row. Requiring account:manage here is a separate decision.
	"disconnect_telegram_account": {},
	"delete_telegram_account":     {},

	// The caller's own account, changed. account:manage is granted by
	// oauth.ResolveScopes (admin and client tiers) and by the local-dev
	// provider. sharedhmac's default groups grant none, so in that mode these
	// tools are not listed unless an operator maps a group to it; the send
	// hint (sendDisabledHint) does not point at them there.
	// account:manage is never carried by
	// a worker or device credential (see internal/oauth/scopes.go), so none
	// of these can be reached by one: a read-only credential cannot grant
	// itself send consent or revoke its owner's devices.
	"get_my_notification_preferences": {"account:manage"},
	"set_my_notification_preferences": {"account:manage"},
	"set_send_consent":                {"account:manage"},
	"revoke_local_bridge_device":      {"account:manage"},

	// Operator lookups: the lookup tier's admin:users:read is accepted here
	// and nowhere else (see requireAnyScope).
	"list_telegram_identities": {"admin:users", "admin:users:read"},
	"get_user_audit_log":       {"admin:users", "admin:users:read"},

	// Operator writes.
	"set_telegram_access":     {"admin:users"},
	"set_account_send":        {"admin:users"},
	"set_account_mode":        {"admin:users"},
	"provision_local_account": {"admin:users"},
	"revoke_telegram_session": {"admin:users"},
	"revoke_worker_token":     {"admin:users"},
	"mint_worker_token":       {"admin:users"},

	// Broadcast operators.
	"prepare_broadcast": {BroadcastScope},
	"list_broadcasts":   {BroadcastScope},
	"get_broadcast":     {BroadcastScope},
	"cancel_broadcast":  {BroadcastScope},
}

// toolAllowed reports whether id may see and call the named tool. A nil
// identity is allowed nothing: every handler refuses an anonymous caller
// anyway, so listing tools to one would advertise a surface it cannot use.
func toolAllowed(id *auth.Identity, name string) bool {
	if id == nil {
		return false
	}
	scopes, ok := toolScopes[name]
	if !ok {
		return false
	}
	if len(scopes) == 0 {
		return true
	}
	for _, sc := range scopes {
		if id.HasScope(sc) {
			return true
		}
	}
	return false
}

// scopeToolFilter is the mcpserver.ToolFilterFunc that applies toolScopes to
// the identity auth.Middleware put in ctx.
func scopeToolFilter(ctx context.Context, tools []mcplib.Tool) []mcplib.Tool {
	id := auth.From(ctx)
	out := make([]mcplib.Tool, 0, len(tools))
	for _, t := range tools {
		if toolAllowed(id, t.Name) {
			out = append(out, t)
		}
	}
	return out
}
