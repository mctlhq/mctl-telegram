package mcp

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// allToolScopes returns every scope toolScopes mentions, for tests that need
// an identity able to see the whole registered surface.
func allToolScopes() []string {
	seen := map[string]bool{}
	var out []string
	for _, scopes := range toolScopes {
		for _, sc := range scopes {
			if !seen[sc] {
				seen[sc] = true
				out = append(out, sc)
			}
		}
	}
	sort.Strings(out)
	return out
}

// fullSurfaceServer is the registry with every optional tool on, the same
// surface DescriptorSurface snapshots.
func fullSurfaceServer(s *Server) *mcpserver.MCPServer {
	s.AppsEnabled = true
	return s.newMCPServer()
}

func listedToolNames(t *testing.T, ctx context.Context, srv *mcpserver.MCPServer) []string {
	t.Helper()
	env := callRPC(t, ctx, srv, string(mcplib.MethodToolsList), map[string]any{})
	if env.Error != nil {
		t.Fatalf("tools/list failed: %+v", env.Error)
	}
	var res mcplib.ListToolsResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatalf("decode tools/list: %v", err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

// TestToolScopes_CoverEveryRegisteredTool: a tool missing from toolScopes is
// hidden from everyone, so the omission must fail here rather than ship as a
// tool nobody can see. A stale entry fails too.
func TestToolScopes_CoverEveryRegisteredTool(t *testing.T) {
	registered := fullSurfaceServer(&Server{}).ListTools()
	for name := range registered {
		if _, ok := toolScopes[name]; !ok {
			t.Errorf("%s is registered but has no toolScopes entry; classify it in toolscopes.go", name)
		}
	}
	for name := range toolScopes {
		if _, ok := registered[name]; !ok {
			t.Errorf("toolScopes names %s, which is not registered", name)
		}
	}
}

// Credential shapes the server actually issues (internal/oauth ResolveScopes,
// internal/workertoken allowlists).
var (
	readOnlyScopes = []string{"telegram:dialogs:read", "telegram:messages:read"}
	clientScopes   = []string{
		"telegram:dialogs:read", "telegram:messages:read",
		"telegram:messages:send", "telegram:messages:pin", "account:manage",
	}
	lookupAdminScopes = []string{"admin:users:read"}
)

// The visible sets are spelled out rather than derived from toolScopes, so a
// wrong entry in the table fails here instead of agreeing with itself.
var (
	selfTools     = []string{"get_my_audit_log", "get_my_identity", "get_my_send_status"}
	readTools     = []string{"get_media", "get_messages", "get_unread_messages", "list_dialogs", "prepare_get_media", "search_messages"}
	writeTools    = []string{"delete_messages", "edit_message", "forward_messages", "pin_message", "prepare_pin_message", "prepare_send_message", "send_media", "send_message", "set_reaction"}
	accountTools  = []string{"delete_telegram_account", "disconnect_telegram_account", "get_my_notification_preferences", "revoke_local_bridge_device", "set_my_notification_preferences", "set_send_consent"}
	lookupTools   = []string{"get_user_audit_log", "list_telegram_identities"}
	adminWrites   = []string{"mint_worker_token", "provision_local_account", "revoke_telegram_session", "revoke_worker_token", "set_account_mode", "set_account_send", "set_telegram_access"}
	broadcastOnly = []string{"cancel_broadcast", "get_broadcast", "list_broadcasts", "prepare_broadcast"}
)

func union(sets ...[]string) []string {
	var out []string
	for _, s := range sets {
		out = append(out, s...)
	}
	sort.Strings(out)
	return out
}

func TestToolsList_FollowsCallerScopes(t *testing.T) {
	srv := fullSurfaceServer(&Server{})
	cases := []struct {
		name   string
		scopes []string
		want   []string
	}{
		{"read-only worker token", readOnlyScopes, union(selfTools, readTools)},
		{"client session", clientScopes, union(selfTools, readTools, writeTools, accountTools)},
		{"lookup admin", lookupAdminScopes, union(selfTools, lookupTools)},
		{"full admin", append(append([]string{}, clientScopes...), "admin:users"), union(selfTools, readTools, writeTools, accountTools, lookupTools, adminWrites)},
		{"broadcast operator", append(append([]string{}, clientScopes...), "admin:users", BroadcastScope), union(selfTools, readTools, writeTools, accountTools, lookupTools, adminWrites, broadcastOnly)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: c.scopes})
			got := listedToolNames(t, ctx, srv)
			if !equalStrings(got, c.want) {
				t.Fatalf("tools/list = %v\nwant        %v", got, c.want)
			}
		})
	}

	t.Run("anonymous", func(t *testing.T) {
		if got := listedToolNames(t, context.Background(), srv); len(got) != 0 {
			t.Fatalf("an anonymous caller was listed %v; every handler refuses it, so nothing may be advertised", got)
		}
	})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestToolsCall_HiddenToolIsRejected: a tool withheld from tools/list must be
// refused on a direct tools/call too, before its handler runs, and the
// refusal is audited as scope_denied for the calling user. Every hidden tool
// is exercised, not a sample: the send-shaped ones used to answer a
// read-only caller with a successful dry-run preview.
func TestToolsCall_HiddenToolIsRejected(t *testing.T) {
	store := newToolsTestStore(t)
	srv := fullSurfaceServer(&Server{Store: store, Confirms: NewConfirmStore(), AllowSend: true})

	const uid int64 = 4301
	ctx := auth.With(context.Background(), &auth.Identity{UserID: uid, Scopes: readOnlyScopes})
	hidden := union(writeTools, accountTools, lookupTools, adminWrites, broadcastOnly)
	for _, name := range hidden {
		t.Run(name, func(t *testing.T) {
			before := countAuditRows(t, store, uid)
			env := callRPC(t, ctx, srv, string(mcplib.MethodToolsCall), map[string]any{
				"name":      name,
				"arguments": map[string]any{"peer": "@x", "text": "hi", "message_id": 1, "message_ids": []int{1}, "enabled": true},
			})
			if env.Error == nil {
				t.Fatalf("tools/call %s succeeded for a read-only identity: %s", name, env.Result)
			}
			if env.Error.Code != mcplib.INVALID_PARAMS {
				t.Errorf("code = %d, want %d", env.Error.Code, mcplib.INVALID_PARAMS)
			}
			if n := countAuditRows(t, store, uid) - before; n != 1 {
				t.Fatalf("audit rows written = %d, want 1", n)
			}
			tool, status, _ := latestAudit(t, store, uid)
			if tool != name || status != "error" {
				t.Fatalf("audit = (%q, %q), want (%q, error)", tool, status, name)
			}
			if reason := latestAuditReason(t, store, uid); reason != ReasonScopeDenied {
				t.Fatalf("reason = %q, want %q", reason, ReasonScopeDenied)
			}
		})
	}
}

// TestToolsCall_ReadOnlyCannotGrantItselfSend: the concrete escalation the
// boundary exists to stop. A read-only credential calling set_send_consent
// directly is refused and the account's send flag is unchanged.
func TestToolsCall_ReadOnlyCannotGrantItselfSend(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedAccountWithSession(t, store, 424301, false)
	srv := fullSurfaceServer(&Server{Store: store, AllowSend: true})

	ctx := auth.With(context.Background(), &auth.Identity{UserID: uid, Scopes: readOnlyScopes})
	env := callRPC(t, ctx, srv, string(mcplib.MethodToolsCall), map[string]any{
		"name":      "set_send_consent",
		"arguments": map[string]any{"enabled": true},
	})
	if env.Error == nil {
		t.Fatalf("set_send_consent succeeded for a read-only identity: %s", env.Result)
	}
	enabled, err := store.IsSendEnabled(context.Background(), uid)
	if err != nil {
		t.Fatalf("IsSendEnabled: %v", err)
	}
	if enabled {
		t.Fatal("a read-only identity turned send_enabled on for its account")
	}
}

// TestToolsCall_ReadOnlyCannotEndItsSession: a read-only credential, and a
// device credential (send and pin, never account:manage), may neither
// disconnect nor delete the account they were issued against. Both the
// filter and the handler refuse; the session row survives and the refusal is
// audited as scope_denied. Until 2026-10-20 both tools were open to any
// authenticated credential (mctlhq/.github#35).
func TestToolsCall_ReadOnlyCannotEndItsSession(t *testing.T) {
	deviceScopes := []string{"telegram:dialogs:read", "telegram:messages:read", "telegram:messages:send", "telegram:messages:pin"}
	for _, cred := range []struct {
		name   string
		scopes []string
	}{{"read-only", readOnlyScopes}, {"device", deviceScopes}} {
		for i, name := range []string{"disconnect_telegram_account", "delete_telegram_account"} {
			t.Run(cred.name+"/"+name, func(t *testing.T) {
				store := newToolsTestStore(t)
				uid := seedAccountWithSession(t, store, int64(424310+i), false)
				srv := &Server{Store: store, Pool: telegram.NewClientPool(0, "", 0, store)}
				ctx := auth.With(context.Background(), &auth.Identity{UserID: uid, Scopes: cred.scopes})

				env := callRPC(t, ctx, fullSurfaceServer(srv), string(mcplib.MethodToolsCall), map[string]any{
					"name": name, "arguments": map[string]any{},
				})
				if env.Error == nil {
					t.Fatalf("tools/call %s succeeded for a %s credential: %s", name, cred.name, env.Result)
				}
				if reason := latestAuditReason(t, store, uid); reason != ReasonScopeDenied {
					t.Fatalf("reason = %q, want %q", reason, ReasonScopeDenied)
				}

				// The handler refuses on its own too, should the filter ever
				// be bypassed.
				handler := srv.toolDisconnectAccount
				if name == "delete_telegram_account" {
					handler = srv.toolDeleteAccount
				}
				_, h := handler()
				res, err := h(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name}})
				if err != nil {
					t.Fatalf("unexpected Go error: %v", err)
				}
				if !res.IsError || !strings.Contains(contentText(res), "account:manage") {
					t.Fatalf("handler did not refuse a %s credential: %s", cred.name, contentText(res))
				}

				if n := activeAccountCount(t, store, uid); n != 1 {
					t.Fatalf("active sessions = %d after a refused %s, want 1", n, name)
				}
				if n := totalAccountCount(t, store, uid); n != 1 {
					t.Fatalf("account rows = %d after a refused %s, want 1", n, name)
				}
			})
		}
	}
}

// TestToolsCall_AnonymousIsRejectedWithoutAudit: there is no user to record
// a refusal against, so an anonymous call is rejected and writes nothing.
func TestToolsCall_AnonymousIsRejectedWithoutAudit(t *testing.T) {
	store := newToolsTestStore(t)
	srv := fullSurfaceServer(&Server{Store: store})
	before := totalAuditRows(t, store)
	env := callRPC(t, context.Background(), srv, string(mcplib.MethodToolsCall), map[string]any{
		"name":      "list_dialogs",
		"arguments": map[string]any{},
	})
	if env.Error == nil {
		t.Fatal("expected an anonymous tools/call to be rejected")
	}
	if after := totalAuditRows(t, store); after != before {
		t.Fatalf("audit rows changed from %d to %d for an anonymous call", before, after)
	}
}

// TestToolsCall_ScopeDeniedRowSurvivesCancelledContext: the hook is the only
// writer of a scope_denied row, so it must write detached, the way Rule 4's
// flush does. A request whose context is already cancelled -- a client that
// disconnected right after sending -- still leaves the row.
func TestToolsCall_ScopeDeniedRowSurvivesCancelledContext(t *testing.T) {
	store := newToolsTestStore(t)
	srv := fullSurfaceServer(&Server{Store: store})

	const uid int64 = 4302
	ctx, cancel := context.WithCancel(auth.With(context.Background(), &auth.Identity{UserID: uid, Scopes: readOnlyScopes}))
	cancel()
	env := callRPC(t, ctx, srv, string(mcplib.MethodToolsCall), map[string]any{
		"name":      "set_send_consent",
		"arguments": map[string]any{"enabled": true},
	})
	if env.Error == nil {
		t.Fatalf("set_send_consent succeeded for a read-only identity: %s", env.Result)
	}
	if n := countAuditRows(t, store, uid); n != 1 {
		t.Fatalf("audit rows = %d, want 1: a cancelled request context dropped the refusal row", n)
	}
	if reason := latestAuditReason(t, store, uid); reason != ReasonScopeDenied {
		t.Fatalf("reason = %q, want %q", reason, ReasonScopeDenied)
	}
}

// TestToolsCall_ClientTierCannotReachAdminSurface is the call-level half of
// the client/admin boundary. TestToolsList_FollowsCallerScopes proves a
// client-tier identity is not LISTED the admin tools, and
// TestToolsCall_HiddenToolIsRejected proves a read-only identity cannot CALL
// them; this pins the same refusal for the full client scope set, the
// identity an ordinary signed-in user actually holds, including that the
// refusal is audited and that a refused set_telegram_access changes nothing.
func TestToolsCall_ClientTierCannotReachAdminSurface(t *testing.T) {
	store := newToolsTestStore(t)
	srv := fullSurfaceServer(&Server{Store: store, Confirms: NewConfirmStore(), AllowSend: true})

	const uid int64 = 4302
	ctx := auth.With(context.Background(), &auth.Identity{UserID: uid, Scopes: clientScopes})
	for _, name := range union(lookupTools, adminWrites, broadcastOnly) {
		t.Run(name, func(t *testing.T) {
			before := countAuditRows(t, store, uid)
			env := callRPC(t, ctx, srv, string(mcplib.MethodToolsCall), map[string]any{
				"name":      name,
				"arguments": map[string]any{"telegram_id": 424399, "tier": "client", "enabled": true},
			})
			if env.Error == nil {
				t.Fatalf("tools/call %s succeeded for a client-tier identity: %s", name, env.Result)
			}
			if n := countAuditRows(t, store, uid) - before; n != 1 {
				t.Fatalf("audit rows written = %d, want 1", n)
			}
			if reason := latestAuditReason(t, store, uid); reason != ReasonScopeDenied {
				t.Fatalf("reason = %q, want %q", reason, ReasonScopeDenied)
			}
		})
	}

	// A refused set_telegram_access must leave the target's tier untouched.
	const targetTG int64 = 424399
	if _, err := store.EnsureUserByTelegramID(context.Background(), targetTG, "target", "Target User"); err != nil {
		t.Fatalf("EnsureUserByTelegramID: %v", err)
	}
	tier, err := store.GetAccessTier(context.Background(), targetTG)
	if err != nil {
		t.Fatalf("GetAccessTier: %v", err)
	}
	if tier != "" {
		t.Fatalf("a client-tier identity changed another user's access tier to %q", tier)
	}
}
