package mcp

import (
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// TestToolAnnotations is a regression guard: it asserts that every MCP tool
// carries explicit readOnly/destructive/openWorld annotation hints so no tool
// silently ships the mcp-go defaults (readOnly=false, destructive=true,
// openWorld=true).
func TestToolAnnotations(t *testing.T) {
	s := &Server{}

	cases := []struct {
		name                             string
		tool                             mcplib.Tool
		readOnly, destructive, openWorld bool
	}{
		{"list_dialogs", first(s.toolListDialogs()), true, false, true},
		{"get_unread_messages", first(s.toolGetUnreadMessages()), true, false, true},
		{"get_messages", first(s.toolGetMessages()), true, false, true},
		{"prepare_pin_message", first(s.toolPreparePinMessage()), false, false, false},
		{"prepare_get_media", first(s.toolPrepareGetMedia()), true, false, true},
		{"get_media", first(s.toolGetMedia()), true, false, true},
		{"list_telegram_identities", first(s.toolListIdentities()), true, false, false},
		{"get_user_audit_log", first(s.toolGetUserAuditLog()), true, false, false},
		{"get_my_audit_log", first(s.toolGetMyAuditLog()), true, false, false},
		{"disconnect_telegram_account", first(s.toolDisconnectAccount()), false, true, false},
		{"delete_telegram_account", first(s.toolDeleteAccount()), false, true, false},
		{"revoke_telegram_session", first(s.toolRevokeSession()), false, true, false},
		{"set_telegram_access", first(s.toolSetAccess()), false, true, false},
		{"set_account_send", first(s.toolSetAccountSend()), false, true, false},
		{"set_account_mode", first(s.toolSetAccountMode()), false, true, false},
		{"send_message", first(s.toolSendMessage()), false, true, true},
		{"send_media", first(s.toolSendMedia()), false, true, true},
		{"pin_message", first(s.toolPinMessage()), false, true, true},
		{"edit_message", first(s.toolEditMessage()), false, true, true},
		{"delete_messages", first(s.toolDeleteMessages()), false, true, true},
		{"forward_messages", first(s.toolForwardMessages()), false, true, true},
		{"search_messages", first(s.toolSearchMessages()), true, false, true},
		{"set_reaction", first(s.toolSetReaction()), false, false, true},
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

// TestToolFilter verifies that toolPassesFilter respects the "read-only" mode.
func TestToolFilter(t *testing.T) {
	s := &Server{}
	trueVal := true
	falseVal := false

	readOnlyTool := mcplib.Tool{Annotations: mcplib.ToolAnnotation{ReadOnlyHint: &trueVal}}
	writeTool := mcplib.Tool{Annotations: mcplib.ToolAnnotation{ReadOnlyHint: &falseVal}}
	noHintTool := mcplib.Tool{}

	cases := []struct {
		tool   mcplib.Tool
		filter string
		want   bool
	}{
		{readOnlyTool, "all", true},
		{writeTool, "all", true},
		{noHintTool, "all", true},
		{readOnlyTool, "read-only", true},
		{writeTool, "read-only", false},
		{noHintTool, "read-only", false},
		{readOnlyTool, "", true}, // empty filter treated as "all"
		{writeTool, "", true},
	}

	_ = s // kept to avoid "declared but not used" in future where we test via Server

	for _, c := range cases {
		got := toolPassesFilter(c.tool, c.filter)
		if got != c.want {
			t.Errorf("toolPassesFilter(filter=%q, readOnly=%v) = %v, want %v",
				c.filter, c.tool.Annotations.ReadOnlyHint, got, c.want)
		}
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
