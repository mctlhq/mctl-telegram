package mcp

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/mcpui"
)

func TestWorkspaceReadOnlyProfile(t *testing.T) {
	s := &Server{Store: newToolsTestStore(t), AppsEnabled: true, ToolFilter: config.TelegramWorkspaceReadOnly}
	server := s.newMCPServer()
	ctx := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: allToolScopes()})
	want := []string{"get_messages", "get_my_identity", "get_my_send_status", "get_unread_messages", "list_dialogs", "list_folders", "list_topics", "search_messages", "telegram_dashboard"}
	if len(server.ListTools()) != len(want) {
		t.Fatalf("registered %d tools, want %v", len(server.ListTools()), want)
	}
	list := callRPC(t, ctx, server, "tools/list", nil)
	var tools mcplib.ListToolsResult
	if err := json.Unmarshal(list.Result, &tools); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	var actual []string
	for _, tool := range tools.Tools {
		actual = append(actual, tool.Name)
		if tool.Name == "telegram_dashboard" {
			if tool.Meta == nil {
				t.Fatal("opener metadata is absent")
			}
			ui, ok := tool.Meta.AdditionalFields["ui"].(map[string]any)
			if !ok || ui["resourceUri"] != mcpui.WorkspaceResourceURI {
				t.Fatalf("opener UI metadata = %v", tool.Meta)
			}
		} else if tool.Meta != nil {
			t.Errorf("backing tool %s should not launch an app", tool.Name)
		}
	}
	slices.Sort(actual)
	if !slices.Equal(actual, want) {
		t.Fatalf("tools/list = %v, want %v", actual, want)
	}

	for name := range fullSurfaceServer(&Server{}).ListTools() {
		if slices.Contains(want, name) {
			continue
		}
		// The authenticated caller holds every scope, so even tools whose
		// mutations use a read scope have to be denied at registration.
		response := callRPC(t, ctx, server, "tools/call", map[string]any{"name": name, "arguments": map[string]any{}})
		if response.Error == nil {
			t.Errorf("%s resolved an excluded tool handler", name)
		}
	}

	for _, name := range []string{"get_messages", "get_unread_messages"} {
		response := callRPC(t, ctx, server, "tools/call", map[string]any{
			"name": name, "arguments": map[string]any{"peer": "user:8511", "fetch_media": true},
		})
		var result mcplib.CallToolResult
		if err := json.Unmarshal(response.Result, &result); err != nil || !result.IsError ||
			firstResultText(&result) != "media downloads are disabled on this endpoint" {
			t.Errorf("%s media download was not refused: %s", name, response.Result)
		}
	}
}

func TestWorkspaceSnapshotCallerBoundary(t *testing.T) {
	store := newToolsTestStore(t)
	ctx := context.Background()
	alice, err := store.EnsureUserByTelegramID(ctx, 8511, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	const bobID = 8512
	if _, err := store.EnsureUserByTelegramID(ctx, bobID, "bob", "Bob"); err != nil {
		t.Fatal(err)
	}
	server := (&Server{Store: store, AppsEnabled: true, ToolFilter: config.TelegramWorkspaceReadOnly}).newMCPServer()
	for _, tc := range []struct {
		name       string
		scopes     []string
		arguments  map[string]any
		wantDenied bool
	}{
		{name: "empty input", scopes: readOnlyScopes},
		{name: "missing dialogs scope", scopes: []string{"telegram:messages:read"}, wantDenied: true},
		{name: "foreign argument", scopes: readOnlyScopes, arguments: map[string]any{"telegram_id": bobID}, wantDenied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller := auth.With(ctx, &auth.Identity{UserID: alice, TelegramID: 8511, Scopes: tc.scopes})
			response := callRPC(t, caller, server, "tools/call", map[string]any{"name": "telegram_dashboard", "arguments": tc.arguments})
			if response.Error != nil && tc.wantDenied {
				return
			}
			var result struct {
				IsError    bool                 `json:"isError"`
				Content    []mcplib.TextContent `json:"content"`
				Structured workspaceSnapshot    `json:"structuredContent"`
			}
			if err := json.Unmarshal(response.Result, &result); err != nil {
				t.Fatalf("decode snapshot: %v, RPC error %+v", err, response.Error)
			}
			if tc.wantDenied {
				if !result.IsError {
					t.Fatal("expected refusal")
				}
				return
			}
			if result.IsError || result.Structured.Identity == nil || result.Structured.Identity.DisplayName != "Alice" ||
				result.Structured.Identity.TelegramID != 8511 || result.Structured.UpdatedAt.IsZero() || len(result.Content) == 0 {
				t.Fatalf("expected caller snapshot and text fallback, got %s", response.Result)
			}
		})
	}
}
