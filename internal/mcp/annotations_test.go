package mcp

import (
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// TestToolAnnotations locks the MCP tool annotation hints that the ChatGPT App
// submission depends on. mcp-go's NewTool defaults are
// readOnly=false, destructive=true, openWorld=true, so any tool that does not
// explicitly override a hint silently ships the default — these assertions fail
// if that drift is reintroduced.
func TestToolAnnotations(t *testing.T) {
	s := &Server{}

	cases := []struct {
		name                             string
		tool                             mcplib.Tool
		readOnly, destructive, openWorld bool
	}{
		{"list_dialogs", first(s.toolListDialogs()), false, false, false},
		{"get_unread_messages", first(s.toolGetUnreadMessages()), false, false, false},
		{"get_messages", first(s.toolGetMessages()), false, false, false},
		{"prepare_pin_message", first(s.toolPreparePinMessage()), false, false, false},
		{"list_telegram_identities", first(s.toolListIdentities()), false, false, false},
		{"get_user_audit_log", first(s.toolGetUserAuditLog()), false, false, false},
		{"get_my_audit_log", first(s.toolGetMyAuditLog()), true, false, false},
		{"disconnect_telegram_account", first(s.toolDisconnectAccount()), false, true, false},
		{"delete_telegram_account", first(s.toolDeleteAccount()), false, true, false},
		{"revoke_telegram_session", first(s.toolRevokeSession()), false, true, false},
		{"set_telegram_access", first(s.toolSetAccess()), false, true, false},
		{"set_account_send", first(s.toolSetAccountSend()), false, true, false},
		{"send_message", first(s.toolSendMessage()), false, false, false},
		{"pin_message", first(s.toolPinMessage()), false, true, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := c.tool.Annotations
			assertHint(t, c.name, "readOnly", a.ReadOnlyHint, c.readOnly)
			assertHint(t, c.name, "destructive", a.DestructiveHint, c.destructive)
			assertHint(t, c.name, "openWorld", a.OpenWorldHint, c.openWorld)
		})
	}
}

// first drops the handler returned alongside a tool builder.
func first(tool mcplib.Tool, _ mcpserver.ToolHandlerFunc) mcplib.Tool { return tool }

func assertHint(t *testing.T, tool, hint string, got *bool, want bool) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: %s hint is nil (expected an explicit value)", tool, hint)
	}
	if *got != want {
		t.Errorf("%s: %sHint = %v, want %v", tool, hint, *got, want)
	}
}
