package mcp

import (
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// TestToolOutputSchemas locks in that every MCP tool advertises an
// outputSchema. The ChatGPT App Directory submission flags any tool without
// one ("Recommended: Add an outputSchema..."), and per the MCP spec a tool
// that declares an outputSchema must also return matching structuredContent
// (jsonResult / the bridge path handle that). WithOutputSchema[T] always sets
// OutputSchema.Type = "object", so an empty Type means the option was dropped.
func TestToolOutputSchemas(t *testing.T) {
	s := &Server{}

	tools := []struct {
		name string
		tool mcplib.Tool
	}{
		{"list_dialogs", first(s.toolListDialogs())},
		{"get_unread_messages", first(s.toolGetUnreadMessages())},
		{"get_messages", first(s.toolGetMessages())},
		{"prepare_pin_message", first(s.toolPreparePinMessage())},
		{"list_telegram_identities", first(s.toolListIdentities())},
		{"get_user_audit_log", first(s.toolGetUserAuditLog())},
		{"get_my_audit_log", first(s.toolGetMyAuditLog())},
		{"disconnect_telegram_account", first(s.toolDisconnectAccount())},
		{"delete_telegram_account", first(s.toolDeleteAccount())},
		{"revoke_telegram_session", first(s.toolRevokeSession())},
		{"set_telegram_access", first(s.toolSetAccess())},
		{"set_account_send", first(s.toolSetAccountSend())},
		{"send_message", first(s.toolSendMessage())},
		{"pin_message", first(s.toolPinMessage())},
		{"edit_message", first(s.toolEditMessage())},
		{"delete_messages", first(s.toolDeleteMessages())},
		{"forward_messages", first(s.toolForwardMessages())},
		{"search_messages", first(s.toolSearchMessages())},
		{"set_reaction", first(s.toolSetReaction())},
	}

	for _, tc := range tools {
		t.Run(tc.name, func(t *testing.T) {
			if tc.tool.OutputSchema.Type == "" {
				t.Errorf("%s: OutputSchema.Type is empty — WithOutputSchema is missing or failed to reflect", tc.name)
			}
		})
	}
}
