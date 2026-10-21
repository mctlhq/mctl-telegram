package mcp

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

func listedTools(t *testing.T, ctx context.Context, srv *mcpserver.MCPServer) map[string]mcplib.Tool {
	t.Helper()
	env := callRPC(t, ctx, srv, string(mcplib.MethodToolsList), map[string]any{})
	if env.Error != nil {
		t.Fatalf("tools/list failed: %+v", env.Error)
	}
	var res mcplib.ListToolsResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	out := map[string]mcplib.Tool{}
	for _, tool := range res.Tools {
		out[tool.Name] = tool
	}
	return out
}

func profileNames(p toolprofile.Profile) []string {
	out := make([]string, 0, len(p.Tools))
	for n := range p.Tools {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// TestCoreReadonly_ToolsAreRegistered: a profile entry naming a tool that
// does not exist would be shown to nobody and would read as a promise. Every
// listed tool must be registered and must be one toolScopes classifies.
func TestCoreReadonly_ToolsAreRegistered(t *testing.T) {
	p, ok := toolprofile.Lookup(toolprofile.CoreReadonly)
	if !ok {
		t.Fatal("core-readonly is not defined")
	}
	for _, name := range profileNames(p) {
		if _, ok := toolScopes[name]; !ok {
			t.Errorf("profile tool %s is not in toolScopes", name)
		}
	}
	got := listedToolNames(t, auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: allToolScopes()}), fullSurfaceServer(&Server{}))
	for _, name := range profileNames(p) {
		if !slices.Contains(got, name) {
			t.Errorf("profile tool %s is not registered", name)
		}
	}
}

// TestCoreReadonly_RuleArgumentsExist: every argument a rule names is a
// property of the tool's registered schema. checkProfileArgs and
// applyProfileSchema only act on the key they are given, so a typo in
// Forbidden ("fetch_medai") would leave the real argument open, silently.
func TestCoreReadonly_RuleArgumentsExist(t *testing.T) {
	p, _ := toolprofile.Lookup(toolprofile.CoreReadonly)
	env := callRPC(t, auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: allToolScopes()}), fullSurfaceServer(&Server{}), string(mcplib.MethodToolsList), map[string]any{})
	var res mcplib.ListToolsResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	schemas := map[string]map[string]any{}
	for _, tool := range res.Tools {
		schemas[tool.Name] = tool.InputSchema.Properties
	}
	for name, rule := range p.Tools {
		props, ok := schemas[name]
		if !ok {
			t.Fatalf("profile tool %s is not registered", name)
		}
		args := append(slices.Clone(rule.Required), rule.Forbidden...)
		if rule.LimitDefault > 0 || rule.LimitMax > 0 {
			args = append(args, "limit")
		}
		for _, a := range args {
			if _, ok := props[a]; !ok {
				t.Errorf("%s: rule names argument %q, which is not in the tool's schema", name, a)
			}
		}
	}
}

// TestToolsList_ProfileNarrowsTheScopeSurface: with every scope, a
// core-readonly credential is shown exactly the profile's tools. With fewer
// scopes it is shown the intersection, never a profile tool its scopes hide:
// the profile only removes.
func TestToolsList_ProfileNarrowsTheScopeSurface(t *testing.T) {
	p, _ := toolprofile.Lookup(toolprofile.CoreReadonly)
	srv := fullSurfaceServer(&Server{})

	full := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: allToolScopes(), Profile: toolprofile.CoreReadonly})
	if got, want := listedToolNames(t, full, srv), profileNames(p); !equalStrings(got, want) {
		t.Fatalf("all scopes + core-readonly listed\n  %v\nwant\n  %v", got, want)
	}

	// Dialogs only: no message reads, whatever the profile lists.
	dialogsOnly := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: []string{"telegram:dialogs:read"}, Profile: toolprofile.CoreReadonly})
	got := listedToolNames(t, dialogsOnly, srv)
	want := []string{"get_my_audit_log", "get_my_identity", "get_my_send_status", "list_dialogs"}
	if !equalStrings(got, want) {
		t.Fatalf("dialogs-only + core-readonly listed %v, want %v", got, want)
	}

	// No profile: unchanged, the whole scope surface.
	none := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: allToolScopes()})
	if n := len(listedToolNames(t, none, srv)); n <= len(p.Tools) {
		t.Fatalf("a credential without a profile was shown %d tools, want the full surface", n)
	}
}

// TestToolsList_UnknownProfileSeesNothing: a profile name this build does not
// know is not "no profile". It must fail closed to an empty surface.
func TestToolsList_UnknownProfileSeesNothing(t *testing.T) {
	ctx := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: allToolScopes(), Profile: "core-future"})
	if got := listedToolNames(t, ctx, fullSurfaceServer(&Server{})); len(got) != 0 {
		t.Fatalf("unknown profile listed %v, want nothing", got)
	}
}

// TestToolsList_ProfileSchemaShowsTheRules: a profiled caller is told the
// rules in the schema it receives, and the registered tool is left intact
// for everyone else.
func TestToolsList_ProfileSchemaShowsTheRules(t *testing.T) {
	srv := fullSurfaceServer(&Server{})
	profiled := listedTools(t, auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: allToolScopes(), Profile: toolprofile.CoreReadonly}), srv)
	plain := listedTools(t, auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: allToolScopes()}), srv)

	for _, name := range []string{"search_messages", "get_unread_messages"} {
		if !slices.Contains(profiled[name].InputSchema.Required, "peer") {
			t.Errorf("%s: peer is not required under core-readonly: %v", name, profiled[name].InputSchema.Required)
		}
		if slices.Contains(plain[name].InputSchema.Required, "peer") {
			t.Errorf("%s: peer became required for a caller without a profile", name)
		}
	}
	for _, name := range []string{"get_messages", "get_unread_messages"} {
		if _, ok := profiled[name].InputSchema.Properties["fetch_media"]; ok {
			t.Errorf("%s: fetch_media is still offered under core-readonly", name)
		}
		if _, ok := plain[name].InputSchema.Properties["fetch_media"]; !ok {
			t.Errorf("%s: fetch_media disappeared for a caller without a profile", name)
		}
	}
	for _, name := range []string{"get_messages", "get_unread_messages", "search_messages"} {
		d := profiled[name].Description
		if !strings.HasPrefix(d, `Restricted by this connection's tool profile "core-readonly"`) || !strings.Contains(d, "max 50") {
			t.Errorf("%s: description does not lead with the profile rules: %.160q", name, d)
		}
		if strings.HasPrefix(plain[name].Description, "Restricted") {
			t.Errorf("%s: unprofiled description carries the profile note", name)
		}
	}
	for _, name := range []string{"get_messages", "get_unread_messages", "search_messages"} {
		limit, _ := profiled[name].InputSchema.Properties["limit"].(map[string]any)
		if limit["maximum"] != float64(50) || limit["default"] != float64(20) {
			t.Errorf("%s: limit schema = %v, want maximum 50 and default 20", name, limit)
		}
		own, _ := plain[name].InputSchema.Properties["limit"].(map[string]any)
		noun, _, _ := strings.Cut(own["description"].(string), " (")
		if d, _ := limit["description"].(string); d != noun+" (default 20, max 50)." {
			t.Errorf("%s: limit description = %q, want the tool's own noun %q with the profile bound", name, d, noun)
		}
		if _, set := own["maximum"]; set {
			t.Errorf("%s: maximum leaked into the unprofiled schema", name)
		}
	}
	if profiled["list_dialogs"].Description != plain["list_dialogs"].Description {
		t.Error("list_dialogs has no rule but its description changed under the profile")
	}
}

// TestToolsCall_ProfileHiddenToolIsProfileDenied: a tool the scopes allow
// but the profile hides is refused before any handler and audited as
// profile_denied, not scope_denied. A tool the scopes hide stays
// scope_denied even under a profile.
func TestToolsCall_ProfileHiddenToolIsProfileDenied(t *testing.T) {
	store := newToolsTestStore(t)
	srv := fullSurfaceServer(&Server{Store: store, Confirms: NewConfirmStore(), AllowSend: true})

	cases := []struct {
		name   string
		scopes []string
		tool   string
		want   string
	}{
		{"scope allows, profile hides", allToolScopes(), "send_message", ReasonProfileDenied},
		{"scope allows, profile hides media", allToolScopes(), "get_media", ReasonProfileDenied},
		{"scope allows, profile hides delete", allToolScopes(), "delete_telegram_account", ReasonProfileDenied},
		{"scope hides first", readOnlyScopes, "send_message", ReasonScopeDenied},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uid := int64(4401 + i)
			logs := captureSlog(t)
			ctx := auth.With(context.Background(), &auth.Identity{UserID: uid, Scopes: tc.scopes, Profile: toolprofile.CoreReadonly})
			env := callRPC(t, ctx, srv, string(mcplib.MethodToolsCall), map[string]any{
				"name":      tc.tool,
				"arguments": map[string]any{"peer": "@x", "text": "hi"},
			})
			if env.Error == nil {
				t.Fatalf("tools/call %s succeeded under core-readonly: %s", tc.tool, env.Result)
			}
			if n := countAuditRows(t, store, uid); n != 1 {
				t.Fatalf("audit rows = %d, want 1", n)
			}
			if reason := latestAuditReason(t, store, uid); reason != tc.want {
				t.Fatalf("reason = %q, want %q", reason, tc.want)
			}
			// The jsonrpc error log line and the error metric share this
			// reason, so the two policies stay apart there too.
			if got := jsonrpcErrorReason(t, logs.String()); got != tc.want {
				t.Fatalf("jsonrpc error log reason = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestToolsCall_ProfileArgumentRefusalIsAudited: an argument that breaks the
// profile is refused on the real tools/call path, before the handler, and
// the row carries profile_denied.
func TestToolsCall_ProfileArgumentRefusalIsAudited(t *testing.T) {
	store := newToolsTestStore(t)
	srv := fullSurfaceServer(&Server{Store: store})
	cases := []struct {
		tool string
		args map[string]any
		msg  string
	}{
		{"get_messages", map[string]any{"peer": "@x", "fetch_media": true}, "fetch_media is not available"},
		{"get_messages", map[string]any{"peer": "@x", "limit": 51}, "exceeds the maximum of 50"},
		{"get_unread_messages", map[string]any{}, "peer is required"},
		{"search_messages", map[string]any{"query": "q"}, "peer is required"},
		{"search_messages", map[string]any{"query": "q", "peer": "@x", "limit": "100"}, "limit must be a number"},
	}
	for i, tc := range cases {
		t.Run(tc.tool+"/"+tc.msg, func(t *testing.T) {
			uid := int64(4411 + i)
			ctx := auth.With(context.Background(), &auth.Identity{UserID: uid, Scopes: allToolScopes(), Profile: toolprofile.CoreReadonly})
			env := callRPC(t, ctx, srv, string(mcplib.MethodToolsCall), map[string]any{"name": tc.tool, "arguments": tc.args})
			if env.Error != nil {
				t.Fatalf("unexpected JSON-RPC error: %+v", env.Error)
			}
			var res mcplib.CallToolResult
			if err := json.Unmarshal(env.Result, &res); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !res.IsError || !strings.Contains(contentText(&res), tc.msg) {
				t.Fatalf("result = %s, want an error containing %q", env.Result, tc.msg)
			}
			if reason := latestAuditReason(t, store, uid); reason != ReasonProfileDenied {
				t.Fatalf("reason = %q, want %q", reason, ReasonProfileDenied)
			}
		})
	}
}

// TestProfileArgGuard_PassesAndDefaults: a compliant call reaches the handler,
// a call without limit gets the profile default, an explicit
// fetch_media=false is accepted, and a caller without a profile passes
// through byte for byte.
func TestProfileArgGuard_PassesAndDefaults(t *testing.T) {
	var seen map[string]any
	next := func(_ context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		seen = req.GetArguments()
		return mcplib.NewToolResultText("ok"), nil
	}
	guard := (&Server{}).profileArgGuard(next)
	call := func(id *auth.Identity, tool string, args map[string]any) *mcplib.CallToolResult {
		t.Helper()
		seen = nil
		res, err := guard(withRecorder(auth.With(context.Background(), id), &callRecorder{}), mcplib.CallToolRequest{
			Params: mcplib.CallToolParams{Name: tool, Arguments: args},
		})
		if err != nil {
			t.Fatalf("Go error: %v", err)
		}
		return res
	}
	profiled := &auth.Identity{UserID: 1, Profile: toolprofile.CoreReadonly}

	noLimit := map[string]any{"peer": "@x"}
	if res := call(profiled, "get_messages", noLimit); res.IsError {
		t.Fatalf("compliant call refused: %s", contentText(res))
	}
	if seen["limit"] != float64(20) {
		t.Fatalf("limit = %v, want the profile default 20", seen["limit"])
	}
	if _, set := noLimit["limit"]; set {
		t.Fatal("guard wrote the default into the caller's argument map")
	}

	// A limit below 1 means "the handler's own default" to the handlers,
	// which is larger than the profile's; under the profile it is the
	// profile's default.
	for _, v := range []any{float64(0), float64(-1), float64(0.4)} {
		if res := call(profiled, "get_messages", map[string]any{"peer": "@x", "limit": v}); res.IsError {
			t.Fatalf("limit %v refused: %s", v, contentText(res))
		}
		if seen["limit"] != float64(20) {
			t.Fatalf("limit %v reached the handler as %v, want the profile default 20", v, seen["limit"])
		}
	}

	in := map[string]any{"peer": "@x", "limit": float64(50), "fetch_media": false}
	if res := call(profiled, "get_messages", in); res.IsError {
		t.Fatalf("limit=50 fetch_media=false refused: %s", contentText(res))
	}
	if seen["limit"] != float64(50) {
		t.Fatalf("limit = %v, want 50 kept", seen["limit"])
	}

	if res := call(profiled, "list_dialogs", map[string]any{"limit": float64(200)}); res.IsError {
		t.Fatalf("list_dialogs has no rule but was refused: %s", contentText(res))
	}

	plain := &auth.Identity{UserID: 1}
	raw := map[string]any{"peer": "@x", "limit": float64(200), "fetch_media": true}
	if res := call(plain, "get_messages", raw); res.IsError {
		t.Fatalf("caller without a profile refused: %s", contentText(res))
	}
	if seen["limit"] != float64(200) || seen["fetch_media"] != true {
		t.Fatalf("caller without a profile had its arguments changed: %v", seen)
	}

	if res := call(&auth.Identity{UserID: 1, Profile: "core-future"}, "list_dialogs", nil); !res.IsError || seen != nil {
		t.Fatal("unknown profile reached the handler")
	}
}

// jsonrpcErrorReason returns the reason of the single "mcp jsonrpc error"
// line in a captureSlog buffer.
func jsonrpcErrorReason(t *testing.T, logs string) string {
	t.Helper()
	var reasons []string
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		var rec struct{ Msg, Reason string }
		if json.Unmarshal([]byte(line), &rec) == nil && rec.Msg == "mcp jsonrpc error" {
			reasons = append(reasons, rec.Reason)
		}
	}
	if len(reasons) != 1 {
		t.Fatalf("want one mcp jsonrpc error line, got %d: %s", len(reasons), logs)
	}
	return reasons[0]
}
