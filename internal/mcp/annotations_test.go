package mcp

import (
	"encoding/json"
	"os"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// allRuntimeTools returns every MCP tool keyed by name — the single source of
// truth the parity test compares the submission JSON against.
func allRuntimeTools(s *Server) map[string]mcplib.Tool {
	return map[string]mcplib.Tool{
		"list_dialogs":                first(s.toolListDialogs()),
		"get_unread_messages":         first(s.toolGetUnreadMessages()),
		"get_messages":                first(s.toolGetMessages()),
		"send_message":                first(s.toolSendMessage()),
		"prepare_pin_message":         first(s.toolPreparePinMessage()),
		"pin_message":                 first(s.toolPinMessage()),
		"get_my_audit_log":            first(s.toolGetMyAuditLog()),
		"disconnect_telegram_account": first(s.toolDisconnectAccount()),
		"delete_telegram_account":     first(s.toolDeleteAccount()),
		"list_telegram_identities":    first(s.toolListIdentities()),
		"set_telegram_access":         first(s.toolSetAccess()),
		"set_account_send":            first(s.toolSetAccountSend()),
		"get_user_audit_log":          first(s.toolGetUserAuditLog()),
		"revoke_telegram_session":     first(s.toolRevokeSession()),
	}
}

// TestAnnotationsMatchSubmissionJSON enforces the G-PARITY gate: the annotation
// hints in chatgpt-app-submission.json (what ChatGPT/Claude reviewers read) must
// exactly match the runtime tool annotations for every tool. If they ever drift,
// a reviewer sees behavior that contradicts the submitted JSON — a review failure.
func TestAnnotationsMatchSubmissionJSON(t *testing.T) {
	const jsonPath = "../../chatgpt-app-submission.json"
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read %s: %v", jsonPath, err)
	}
	var doc struct {
		Tools map[string]struct {
			Annotations struct {
				ReadOnlyHint    *bool `json:"readOnlyHint"`
				OpenWorldHint   *bool `json:"openWorldHint"`
				DestructiveHint *bool `json:"destructiveHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", jsonPath, err)
	}

	runtime := allRuntimeTools(&Server{})
	if len(doc.Tools) != len(runtime) {
		t.Fatalf("tool count mismatch: JSON has %d, runtime has %d", len(doc.Tools), len(runtime))
	}

	deref := func(b *bool) bool { return b != nil && *b }
	for name, jt := range doc.Tools {
		rt, ok := runtime[name]
		if !ok {
			t.Errorf("JSON tool %q has no runtime tool", name)
			continue
		}
		a := rt.Annotations
		if a.Title == "" {
			t.Errorf("%s: runtime tool missing title", name)
		}
		if jt.Annotations.ReadOnlyHint == nil || deref(a.ReadOnlyHint) != *jt.Annotations.ReadOnlyHint {
			t.Errorf("%s: readOnlyHint runtime=%v JSON=%v", name, a.ReadOnlyHint, jt.Annotations.ReadOnlyHint)
		}
		if jt.Annotations.DestructiveHint == nil || deref(a.DestructiveHint) != *jt.Annotations.DestructiveHint {
			t.Errorf("%s: destructiveHint runtime=%v JSON=%v", name, a.DestructiveHint, jt.Annotations.DestructiveHint)
		}
		if jt.Annotations.OpenWorldHint != nil && deref(a.OpenWorldHint) != *jt.Annotations.OpenWorldHint {
			t.Errorf("%s: openWorldHint runtime=%v JSON=%v", name, a.OpenWorldHint, jt.Annotations.OpenWorldHint)
		}
	}
	for name := range runtime {
		if _, ok := doc.Tools[name]; !ok {
			t.Errorf("runtime tool %q missing from submission JSON", name)
		}
	}
}

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
		{"list_dialogs", first(s.toolListDialogs()), true, false, true},
		{"get_unread_messages", first(s.toolGetUnreadMessages()), true, false, true},
		{"get_messages", first(s.toolGetMessages()), true, false, true},
		{"prepare_pin_message", first(s.toolPreparePinMessage()), false, false, false},
		{"list_telegram_identities", first(s.toolListIdentities()), true, false, false},
		{"get_user_audit_log", first(s.toolGetUserAuditLog()), true, false, false},
		{"get_my_audit_log", first(s.toolGetMyAuditLog()), true, false, false},
		{"disconnect_telegram_account", first(s.toolDisconnectAccount()), false, true, false},
		{"delete_telegram_account", first(s.toolDeleteAccount()), false, true, false},
		{"revoke_telegram_session", first(s.toolRevokeSession()), false, true, false},
		{"set_telegram_access", first(s.toolSetAccess()), false, true, false},
		{"set_account_send", first(s.toolSetAccountSend()), false, true, false},
		{"send_message", first(s.toolSendMessage()), false, true, true},
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
