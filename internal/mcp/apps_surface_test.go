package mcp

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/mcpui"
)

// rpcEnvelope is the shape common to a JSON-RPC success or error response,
// enough for these in-process tests to route on. HandleMessage is called
// directly (no HTTP, no session) so these tests exercise exactly what
// newMCPServer wires -- the same surface the HTTP handler serves on top.
type rpcEnvelope struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// callRPC sends one JSON-RPC request through srv.HandleMessage in-process
// and decodes the envelope. ctx carries the identity (or none) the way
// auth.Middleware would have injected it.
func callRPC(t *testing.T, ctx context.Context, srv *mcpserver.MCPServer, method string, params any) rpcEnvelope {
	t.Helper()
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
	}
	if params != nil {
		req["params"] = params
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	resp := srv.HandleMessage(ctx, raw)
	respRaw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	var env rpcEnvelope
	if err := json.Unmarshal(respRaw, &env); err != nil {
		t.Fatalf("decode response %s: %v", respRaw, err)
	}
	return env
}

func initializeParams() map[string]any {
	return map[string]any{
		"protocolVersion": mcp.LATEST_LEGACY_PROTOCOL_VERSION,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "apps-test", "version": "1"},
	}
}

// TestAppsFlag_Off_SurfaceUnchanged is T1: with AppsEnabled false, initialize
// advertises no extensions and no resources capability, resources/list is
// unavailable, and no registered tool carries a non-nil Meta.
func TestAppsFlag_Off_SurfaceUnchanged(t *testing.T) {
	srv := (&Server{}).newMCPServer()
	// tools/list is scope-filtered (toolscopes.go); an identity holding every
	// scope sees the whole registered set, which is what this test inspects.
	ctx := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: allToolScopes()})

	initEnv := callRPC(t, ctx, srv, string(mcp.MethodInitialize), initializeParams())
	if initEnv.Error != nil {
		t.Fatalf("initialize failed: %+v", initEnv.Error)
	}
	var initResult mcp.InitializeResult
	if err := json.Unmarshal(initEnv.Result, &initResult); err != nil {
		t.Fatalf("decode initialize result: %v", err)
	}
	if initResult.Capabilities.Extensions != nil {
		t.Errorf("capabilities.extensions = %v, want absent", initResult.Capabilities.Extensions)
	}
	if initResult.Capabilities.Resources != nil {
		t.Errorf("capabilities.resources = %v, want absent", initResult.Capabilities.Resources)
	}

	resEnv := callRPC(t, ctx, srv, string(mcp.MethodResourcesList), map[string]any{})
	if resEnv.Error == nil {
		t.Error("resources/list succeeded with the flag off; resources must be unavailable")
	}

	toolsEnv := callRPC(t, ctx, srv, string(mcp.MethodToolsList), map[string]any{})
	if toolsEnv.Error != nil {
		t.Fatalf("tools/list failed: %+v", toolsEnv.Error)
	}
	var toolsResult mcp.ListToolsResult
	if err := json.Unmarshal(toolsEnv.Result, &toolsResult); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	if len(toolsResult.Tools) == 0 {
		t.Fatal("no tools registered")
	}
	for _, tool := range toolsResult.Tools {
		if tool.Meta != nil {
			t.Errorf("tool %s carries Meta with the flag off: %+v", tool.Name, tool.Meta)
		}
	}
}

// TestAppsFlag_On_SurfaceSpecShaped is T2: with AppsEnabled true, extensions
// advertises the MCP Apps extension with the right mimeType, resources/list
// carries the triage URI with that exact mimeType, resources/read returns
// one non-empty TextResourceContents whose _meta.ui.csp lists no domains, and
// the seven designated tools carry nested _meta.ui.resourceUri with the
// deprecated flat key appearing nowhere.
func TestAppsFlag_On_SurfaceSpecShaped(t *testing.T) {
	srv := (&Server{AppsEnabled: true}).newMCPServer()
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:dialogs:read", "telegram:messages:read", "telegram:messages:send"}}
	ctx := auth.With(context.Background(), id)

	initEnv := callRPC(t, ctx, srv, string(mcp.MethodInitialize), initializeParams())
	if initEnv.Error != nil {
		t.Fatalf("initialize failed: %+v", initEnv.Error)
	}
	var initResult mcp.InitializeResult
	if err := json.Unmarshal(initEnv.Result, &initResult); err != nil {
		t.Fatalf("decode initialize result: %v", err)
	}
	ext, ok := initResult.Capabilities.Extensions[mcpui.ExtensionID].(map[string]any)
	if !ok {
		t.Fatalf("capabilities.extensions[%q] missing or wrong shape: %v", mcpui.ExtensionID, initResult.Capabilities.Extensions)
	}
	mimeTypes, ok := ext["mimeTypes"].([]any)
	if !ok || len(mimeTypes) != 1 || mimeTypes[0] != mcpui.MIMEType {
		t.Errorf("extension mimeTypes = %v, want [%q]", ext["mimeTypes"], mcpui.MIMEType)
	}
	if initResult.Capabilities.Resources == nil {
		t.Error("capabilities.resources absent with the flag on")
	}

	resEnv := callRPC(t, ctx, srv, string(mcp.MethodResourcesList), map[string]any{})
	if resEnv.Error != nil {
		t.Fatalf("resources/list failed: %+v", resEnv.Error)
	}
	var resResult mcp.ListResourcesResult
	if err := json.Unmarshal(resEnv.Result, &resResult); err != nil {
		t.Fatalf("decode resources/list: %v", err)
	}
	var found *mcp.Resource
	for i := range resResult.Resources {
		if resResult.Resources[i].URI == mcpui.ResourceURI {
			found = &resResult.Resources[i]
		}
	}
	if found == nil {
		t.Fatalf("resources/list does not contain %q", mcpui.ResourceURI)
	}
	if found.MIMEType != mcpui.MIMEType {
		t.Errorf("resource mimeType = %q, want %q", found.MIMEType, mcpui.MIMEType)
	}

	readEnv := callRPC(t, ctx, srv, string(mcp.MethodResourcesRead), map[string]any{"uri": mcpui.ResourceURI})
	if readEnv.Error != nil {
		t.Fatalf("resources/read failed: %+v", readEnv.Error)
	}
	var readResult struct {
		Contents []struct {
			Text string         `json:"text"`
			Meta map[string]any `json:"_meta"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(readEnv.Result, &readResult); err != nil {
		t.Fatalf("decode resources/read: %v", err)
	}
	if len(readResult.Contents) != 1 {
		t.Fatalf("contents length = %d, want 1", len(readResult.Contents))
	}
	if readResult.Contents[0].Text == "" {
		t.Error("resources/read returned empty text")
	}
	ui, ok := readResult.Contents[0].Meta["ui"].(map[string]any)
	if !ok {
		t.Fatal("contents[0]._meta.ui missing")
	}
	csp, ok := ui["csp"].(map[string]any)
	if !ok {
		t.Fatal("contents[0]._meta.ui.csp missing")
	}
	for _, key := range []string{"connectDomains", "resourceDomains", "frameDomains", "baseUriDomains"} {
		list, ok := csp[key].([]any)
		if !ok || len(list) != 0 {
			t.Errorf("csp[%q] = %v, want empty list", key, csp[key])
		}
	}

	toolsEnv := callRPC(t, ctx, srv, string(mcp.MethodToolsList), map[string]any{})
	if toolsEnv.Error != nil {
		t.Fatalf("tools/list failed: %+v", toolsEnv.Error)
	}
	var toolsResult struct {
		Tools []struct {
			Name string         `json:"name"`
			Meta map[string]any `json:"_meta"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(toolsEnv.Result, &toolsResult); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	wantUI := map[string]bool{
		"list_dialogs": true, "get_unread_messages": true, "get_messages": true,
		"search_messages": true, "prepare_get_media": true, "prepare_send_message": true,
		"send_message": true,
	}
	seen := map[string]bool{}
	for _, tool := range toolsResult.Tools {
		raw, _ := json.Marshal(tool.Meta)
		if strings.Contains(string(raw), "ui/resourceUri") {
			t.Errorf("tool %s carries the deprecated flat ui/resourceUri key", tool.Name)
		}
		if !wantUI[tool.Name] {
			continue
		}
		seen[tool.Name] = true
		ui, ok := tool.Meta["ui"].(map[string]any)
		if !ok {
			t.Errorf("tool %s missing nested _meta.ui", tool.Name)
			continue
		}
		if ui["resourceUri"] != mcpui.ResourceURI {
			t.Errorf("tool %s _meta.ui.resourceUri = %v, want %q", tool.Name, ui["resourceUri"], mcpui.ResourceURI)
		}
	}
	for name := range wantUI {
		if !seen[name] {
			t.Errorf("tool %s not found in tools/list", name)
		}
	}
}

// TestAppResourceHandler_RequiresAuth is T3: the resource handler refuses
// when auth.From(ctx) is nil, even though the flag is on.
func TestAppResourceHandler_RequiresAuth(t *testing.T) {
	srv := &Server{}
	_, err := srv.handleReadAppResource(context.Background(), mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{URI: mcpui.ResourceURI},
	})
	if err == nil {
		t.Fatal("expected an error without an authenticated identity")
	}

	id := &auth.Identity{UserID: 1}
	ctx := auth.With(context.Background(), id)
	contents, err := srv.handleReadAppResource(ctx, mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{URI: mcpui.ResourceURI},
	})
	if err != nil {
		t.Fatalf("authenticated read failed: %v", err)
	}
	if len(contents) != 1 {
		t.Fatalf("contents length = %d, want 1", len(contents))
	}
}

func TestWorkspaceOnlyOnSharedServer(t *testing.T) {
	baselineServer := (&Server{AllowSend: true}).newMCPServer()
	shared := &Server{AllowSend: true, AppsEnabled: true, AppsWorkspaceOnly: true}
	srv := shared.newMCPServer()
	ctx := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: allToolScopes()})
	baseline := make(map[string]mcp.Tool)
	var existing mcp.ListToolsResult
	before := callRPC(t, ctx, baselineServer, "tools/list", nil)
	if err := json.Unmarshal(before.Result, &existing); err != nil || before.Error != nil {
		t.Fatalf("baseline tools/list failed: %v, %+v", err, before.Error)
	}
	for _, tool := range existing.Tools {
		baseline[tool.Name] = tool
	}
	if len(srv.ListTools()) != len(baselineServer.ListTools())+1 {
		t.Fatal("Workspace mode must add exactly one tool before OAuth filtering")
	}
	list := callRPC(t, ctx, srv, "tools/list", nil)
	var result mcp.ListToolsResult
	if err := json.Unmarshal(list.Result, &result); err != nil || list.Error != nil {
		t.Fatalf("tools/list failed: %v, %+v", err, list.Error)
	}
	var appTools []string
	for _, tool := range result.Tools {
		if tool.Meta == nil {
			t.Fatalf("%s lacks explicit UI visibility", tool.Name)
		}
		meta := tool.Meta.AdditionalFields
		ui, ok := meta["ui"].(map[string]any)
		if !ok {
			t.Fatalf("%s has no UI metadata", tool.Name)
		}
		visibility := ui["visibility"]
		if reflect.DeepEqual(visibility, []any{"model", "app"}) {
			appTools = append(appTools, tool.Name)
			if tool.Annotations.ReadOnlyHint == nil || !*tool.Annotations.ReadOnlyHint {
				t.Errorf("%s is visible to the App but lacks a read-only annotation", tool.Name)
			}
			if meta["openai/widgetAccessible"] != true {
				t.Errorf("%s has inconsistent ChatGPT visibility", tool.Name)
			}
		} else if !reflect.DeepEqual(visibility, []any{"model"}) || meta["openai/widgetAccessible"] != false {
			t.Errorf("%s is not model-only: %v", tool.Name, meta)
		}
		if tool.Name == "telegram_dashboard" {
			if ui["resourceUri"] != mcpui.WorkspaceResourceURI {
				t.Errorf("Workspace binding = %v", ui["resourceUri"])
			}
			continue
		}
		if _, ok := ui["resourceUri"]; ok {
			t.Errorf("%s carries an unexpected App binding", tool.Name)
		}
		original, ok := baseline[tool.Name]
		if !ok {
			t.Errorf("unexpected tool %s in shared surface", tool.Name)
		}
		// Compare wire descriptors, ignoring only the metadata this mode adds.
		tool.Meta = nil
		want, _ := json.Marshal(original)
		got, _ := json.Marshal(tool)
		if string(got) != string(want) {
			t.Errorf("%s changed its existing descriptor beyond UI metadata", tool.Name)
		}
		delete(baseline, tool.Name)
	}
	if len(baseline) != 0 {
		t.Errorf("shared mode omitted %d existing tools", len(baseline))
	}
	slices.Sort(appTools)
	if want := []string{"get_messages", "list_dialogs", "search_messages", "telegram_dashboard"}; !slices.Equal(appTools, want) {
		t.Errorf("app tools = %v, want %v", appTools, want)
	}
	resources := srv.ListResources()
	if len(resources) != 1 || resources[mcpui.WorkspaceResourceURI] == nil {
		t.Fatalf("shared mode must publish only the Workspace resource")
	}
	for _, uri := range []string{mcpui.ResourceURI, mcpui.DashboardResourceURI} {
		var request mcp.ReadResourceRequest
		request.Params.URI = uri
		if _, err := shared.handleReadAppResource(ctx, request); err == nil {
			t.Errorf("legacy resource %s was served by the Workspace handler", uri)
		}
	}
	resource := callRPC(t, ctx, srv, "resources/read", map[string]any{"uri": mcpui.WorkspaceResourceURI})
	var content struct {
		Contents []mcp.TextResourceContents
	}
	if err := json.Unmarshal(resource.Result, &content); err != nil || resource.Error != nil ||
		len(content.Contents) != 1 || content.Contents[0].MIMEType != mcpui.MIMEType {
		t.Fatalf("Workspace resource missing or invalid: decode=%v, rpc=%+v", err, resource.Error)
	}
	readOnly := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: []string{"telegram:dialogs:read", "telegram:messages:read"}})
	send := callRPC(t, readOnly, srv, "tools/call", map[string]any{"name": "send_message"})
	if send.Error == nil {
		t.Fatal("read-only OAuth grant reached a writable handler")
	}
}
