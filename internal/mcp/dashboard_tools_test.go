package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/dashboard"
	"github.com/mctlhq/mctl-telegram/internal/mcpui"
)

func callDash(t *testing.T, h func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error), id *auth.Identity, name string, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	res, err := h(auth.With(context.Background(), id), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: args}})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func dashObject(t *testing.T, res *mcplib.CallToolResult) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", contentText(res))
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(contentText(res)), &out); err != nil {
		t.Fatalf("decode %s: %v", contentText(res), err)
	}
	return out
}

func TestPrepareDashboardAction_BindsMarkReadAndDoesNotCallTelegram(t *testing.T) {
	s, fake, id := markReadServer(t, true)
	s.Confirms = NewConfirmStore()
	_, prep := s.toolPrepareDashboardAction()
	res := callDash(t, prep, id, "prepare_dashboard_action", map[string]any{
		"action": "mark_read", "peer": "user:7120", "max_id": float64(41),
	})
	out := dashObject(t, res)
	if fake.calls != 0 {
		t.Fatal("prepare called Telegram")
	}
	if out["will_apply"] != true {
		t.Fatalf("will_apply = %v (%v)", out["will_apply"], out["dry_reason"])
	}
	conf, _ := out["confirmation_id"].(string)
	if !strings.HasPrefix(conf, "c") || conf == "" {
		t.Fatalf("confirmation_id = %q", conf)
	}
	marked := callMarkRead(t, s, id, map[string]any{"peer": "user:7120", "max_id": float64(41), "confirmation_id": conf})
	if marked.IsError || fake.calls != 1 {
		t.Fatalf("mark_read isError=%v calls=%d %s", marked.IsError, fake.calls, contentText(marked))
	}
	again := callMarkRead(t, s, id, map[string]any{"peer": "user:7120", "max_id": float64(41), "confirmation_id": conf})
	if !again.IsError || fake.calls != 1 {
		t.Fatalf("reuse isError=%v calls=%d %s", again.IsError, fake.calls, contentText(again))
	}
}

func TestPrepareDashboardAction_MismatchAndClosedGateDoNotMarkRead(t *testing.T) {
	s, fake, id := markReadServer(t, true)
	s.Confirms = NewConfirmStore()
	_, prep := s.toolPrepareDashboardAction()
	out := dashObject(t, callDash(t, prep, id, "prepare_dashboard_action", map[string]any{
		"action": "mark_read", "peer": "user:7120", "max_id": float64(41),
	}))
	bad := callMarkRead(t, s, id, map[string]any{"peer": "user:7120", "max_id": float64(42), "confirmation_id": out["confirmation_id"]})
	if !bad.IsError || fake.calls != 0 || !strings.Contains(contentText(bad), "different action") {
		t.Fatalf("mismatch isError=%v calls=%d %s", bad.IsError, fake.calls, contentText(bad))
	}
	// A mismatch consumes the id (ConfirmStore drops it either way), so the
	// foreign-user check needs a fresh one.
	fresh := dashObject(t, callDash(t, prep, id, "prepare_dashboard_action", map[string]any{
		"action": "mark_read", "peer": "user:7120", "max_id": float64(41),
	}))
	other := &auth.Identity{UserID: id.UserID + 1, Scopes: id.Scopes}
	foreign := callMarkRead(t, s, other, map[string]any{"peer": "user:7120", "max_id": float64(41), "confirmation_id": fresh["confirmation_id"]})
	if !foreign.IsError || fake.calls != 0 || !strings.Contains(contentText(foreign), "another identity") {
		t.Fatalf("foreign isError=%v calls=%d %s", foreign.IsError, fake.calls, contentText(foreign))
	}

	closed, closedFake, closedID := markReadServer(t, false)
	closed.Confirms = NewConfirmStore()
	_, closedPrep := closed.toolPrepareDashboardAction()
	closedOut := dashObject(t, callDash(t, closedPrep, closedID, "prepare_dashboard_action", map[string]any{
		"action": "mark_read", "peer": "user:7120", "max_id": float64(7),
	}))
	if closedOut["will_apply"] != false || closedFake.calls != 0 {
		t.Fatalf("closed prepare = %v calls=%d", closedOut, closedFake.calls)
	}
	refused := callMarkRead(t, closed, closedID, map[string]any{
		"peer": "user:7120", "max_id": float64(7), "confirmation_id": closedOut["confirmation_id"],
	})
	if !refused.IsError || closedFake.calls != 0 {
		t.Fatalf("closed mark_read isError=%v calls=%d %s", refused.IsError, closedFake.calls, contentText(refused))
	}
}

func TestPrepareDashboardAction_RejectsSendAndDelete(t *testing.T) {
	s, _, id := markReadServer(t, true)
	s.Confirms = NewConfirmStore()
	_, prep := s.toolPrepareDashboardAction()
	for _, action := range []string{"send_message", "delete_messages", "send_media"} {
		res := callDash(t, prep, id, "prepare_dashboard_action", map[string]any{"action": action, "peer": "user:7120"})
		if !res.IsError {
			t.Fatalf("%s was accepted", action)
		}
	}
}

func TestSaveDashboardTemplate_CustomRoundTripAndBuiltinLock(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedAccountWithSession(t, store, 424261, false)
	s := &Server{Store: store, Confirms: NewConfirmStore()}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:dialogs:read"}}
	_, save := s.toolSaveDashboardTemplate()
	_, get := s.toolGetDashboardTemplate()
	_, list := s.toolListDashboardTemplates()

	builtin := callDash(t, save, id, "save_dashboard_template", map[string]any{"template": map[string]any{"id": "unread_pulse"}})
	if !builtin.IsError || !strings.Contains(contentText(builtin), "cannot be overwritten") {
		t.Fatalf("builtin overwrite: %s", contentText(builtin))
	}
	bad := callDash(t, save, id, "save_dashboard_template", map[string]any{"template": map[string]any{
		"schema": dashboard.SchemaID, "id": "custom_pulse", "title": "Мой",
		"layout":      map[string]any{"columns": float64(12), "gap": float64(8)},
		"dataSources": []any{map[string]any{"id": "dialogs", "tool": "send_message"}},
		"tiles":       []any{map[string]any{"id": "k", "component": "kpi", "colSpan": float64(4), "props": map[string]any{"label": "N", "value": "1"}}},
	}})
	if !bad.IsError {
		t.Fatal("send_message data source was stored")
	}
	doc := map[string]any{
		"schema": dashboard.SchemaID, "id": "custom_pulse", "title": "Мой шаблон",
		"layout":      map[string]any{"columns": float64(12), "gap": float64(8)},
		"dataSources": []any{map[string]any{"id": "dialogs", "tool": "list_dialogs", "args": map[string]any{"limit": float64(10)}}},
		"tiles":       []any{map[string]any{"id": "k", "component": "kpi", "colSpan": float64(4), "props": map[string]any{"label": "N", "value": "@data:dialogs.stats.unread_dialogs"}}},
	}
	dry := dashObject(t, callDash(t, save, id, "save_dashboard_template", map[string]any{"template": doc, "dry_run": true}))
	if dry["valid"] != true || dry["saved"] != false {
		t.Fatalf("dry_run = %v", dry)
	}
	if _, err := store.GetDashboardTemplate(context.Background(), uid, "custom_pulse"); err == nil {
		t.Fatal("dry_run wrote a row")
	}
	saved := dashObject(t, callDash(t, save, id, "save_dashboard_template", map[string]any{"template": doc}))
	if saved["saved"] != true {
		t.Fatalf("saved = %v", saved)
	}
	got := dashObject(t, callDash(t, get, id, "get_dashboard_template", map[string]any{"id": "custom_pulse"}))
	tpl, _ := got["template"].(map[string]any)
	if got["builtin"] != false || tpl["id"] != "custom_pulse" {
		t.Fatalf("get = %v", got)
	}
	listed := dashObject(t, callDash(t, list, id, "list_dashboard_templates", map[string]any{}))
	rows, _ := listed["templates"].([]any)
	if len(rows) != len(dashboard.BuiltinIDs())+1 {
		t.Fatalf("list len = %d", len(rows))
	}
	_, del := s.toolDeleteDashboardTemplate()
	if res := callDash(t, del, id, "delete_dashboard_template", map[string]any{"id": "unread_pulse"}); !res.IsError {
		t.Fatal("deleted a builtin")
	}
	if res := callDash(t, del, id, "delete_dashboard_template", map[string]any{"id": "custom_pulse"}); res.IsError {
		t.Fatal(contentText(res))
	}
}

func TestDashboardFlag_ResourceAndToolsFollowAppsFlag(t *testing.T) {
	off := (&Server{}).newMCPServer()
	ctx := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: []string{"telegram:dialogs:read", "telegram:messages:read", "telegram:messages:send"}})
	tools := callRPC(t, ctx, off, "tools/list", map[string]any{})
	var offList struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(tools.Result, &offList); err != nil {
		t.Fatal(err)
	}
	for _, tool := range offList.Tools {
		switch tool.Name {
		case "list_dashboard_templates", "get_dashboard_template", "save_dashboard_template", "delete_dashboard_template", "prepare_dashboard_action":
			t.Fatalf("%s is registered with the flag off", tool.Name)
		}
	}

	on := (&Server{AppsEnabled: true}).newMCPServer()
	read := callRPC(t, ctx, on, "resources/read", map[string]any{"uri": mcpui.DashboardResourceURI})
	if read.Error != nil || !strings.Contains(string(read.Result), "tg-dashboard/v1") {
		t.Fatalf("dashboard resource: err=%v body missing document", read.Error)
	}
	listed := callRPC(t, ctx, on, "tools/list", map[string]any{})
	var payload struct {
		Tools []struct {
			Name string         `json:"name"`
			Meta map[string]any `json:"_meta"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(listed.Result, &payload); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"list_dashboard_templates": true, "get_dashboard_template": true,
		"save_dashboard_template": true, "delete_dashboard_template": true,
		"prepare_dashboard_action": true, "mark_read": true, "save_draft": true,
	}
	for _, tool := range payload.Tools {
		if !want[tool.Name] {
			continue
		}
		ui, _ := tool.Meta["ui"].(map[string]any)
		if ui["resourceUri"] != mcpui.DashboardResourceURI {
			t.Errorf("%s resourceUri = %v", tool.Name, ui["resourceUri"])
		}
		delete(want, tool.Name)
	}
	for name := range want {
		t.Errorf("missing dashboard tool %s", name)
	}
}
