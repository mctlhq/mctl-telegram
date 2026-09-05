package mcp

import (
	"context"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/workertoken"
)

// callAdminTool invokes one tool handler under an identity carrying exactly
// scopes, and reports whether the call was refused by the scope gate. It
// distinguishes a SCOPE refusal from any other error result on purpose: the
// read-only tools are expected to get past the gate and then fail on a
// missing row or empty store, and treating that as "allowed" would make the
// acceptance half of this test vacuous.
func callAdminTool(t *testing.T, name string, handler mcpserver.ToolHandlerFunc, scopes []string, args map[string]any) bool {
	t.Helper()
	ctx := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: scopes})
	result, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: name, Arguments: args,
	}})
	if err != nil {
		t.Fatalf("%s: unexpected Go error: %v", name, err)
	}
	if !result.IsError {
		return false
	}
	for _, c := range result.Content {
		if tc, ok := c.(mcplib.TextContent); ok && strings.Contains(tc.Text, "missing scope") {
			return true
		}
	}
	return false
}

// TestLookupAdminScope_ReadsOnly is the regression test for the defect the
// admin:users:read scope exists to fix. The lookup-admin tier
// (TG_LOGIN_LOOKUP_ADMINS) was originally granted the flat admin:users
// scope, which is the ONLY gate on every admin write tool -- so a tier
// documented as "lookup-only, must never need a working MTProto session"
// could flip access tiers, revoke sessions, and mint a send-capable worker
// token for any account. mint_worker_token is the sharpest case: it targets
// an arbitrary telegram_id and purpose "local-bridge" adds send and pin, so
// withholding telegram:* from that identity bought nothing.
//
// The assertion is on the gate's behaviour per tool, not on the scope
// string: a future tool added with the wrong gate fails here.
func TestLookupAdminScope_ReadsOnly(t *testing.T) {
	minter, err := workertoken.NewMinter([]byte(mintTestSecret), mintTestIssuer, "")
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}
	srv := &Server{Store: newToolsTestStore(t), WorkerTokenMinter: minter}
	const lookupScope = "admin:users:read"

	// Every admin WRITE tool must refuse admin:users:read outright.
	// Args are deliberately EMPTY. Every one of these tools checks the scope
	// before it validates arguments, so the gate is what the lookup-scope leg
	// exercises, while the admin:users leg stops at the argument error just
	// past the gate -- close enough to prove the gate let it through, without
	// executing a destructive body against a half-wired test Server.
	writes := []struct {
		name  string
		build func() (mcplib.Tool, mcpserver.ToolHandlerFunc)
		args  map[string]any
	}{
		{"set_telegram_access", srv.toolSetAccess, map[string]any{}},
		{"set_account_send", srv.toolSetAccountSend, map[string]any{}},
		{"set_account_mode", srv.toolSetAccountMode, map[string]any{}},
		{"provision_local_account", srv.toolProvisionLocalAccount, map[string]any{}},
		{"revoke_telegram_session", srv.toolRevokeSession, map[string]any{}},
		{"revoke_worker_token", srv.toolRevokeWorkerToken, map[string]any{}},
		{"mint_worker_token", srv.toolMintWorkerToken, map[string]any{}},
	}
	for _, w := range writes {
		_, handler := w.build()
		if !callAdminTool(t, w.name, handler, []string{lookupScope}, w.args) {
			t.Errorf("%s accepted %s: the lookup-admin tier must not reach any admin write tool", w.name, lookupScope)
		}
		// Sanity: the same call under the full admin scope is NOT refused by
		// the gate. Without this the test would still pass if the gate
		// rejected everything, proving nothing about admin:users:read.
		_, handler = w.build()
		if callAdminTool(t, w.name, handler, []string{"admin:users"}, w.args) {
			t.Errorf("%s refused admin:users at the scope gate; the write gate is broken, not narrowed", w.name)
		}
	}

	// The two read-only lookups must accept it — that is the tier's purpose.
	reads := []struct {
		name  string
		build func() (mcplib.Tool, mcpserver.ToolHandlerFunc)
		args  map[string]any
	}{
		{"list_telegram_identities", srv.toolListIdentities, map[string]any{}},
		{"get_user_audit_log", srv.toolGetUserAuditLog, map[string]any{"telegram_id": float64(42)}},
	}
	for _, r := range reads {
		_, handler := r.build()
		if callAdminTool(t, r.name, handler, []string{lookupScope}, r.args) {
			t.Errorf("%s refused %s: the lookup-admin tier exists to call exactly this tool", r.name, lookupScope)
		}
		// A scopeless identity must still be refused, so the acceptance
		// above is the scope doing work rather than the gate being gone.
		_, handler = r.build()
		if !callAdminTool(t, r.name, handler, []string{"telegram:messages:read"}, r.args) {
			t.Errorf("%s accepted an identity with neither admin scope", r.name)
		}
	}
}
