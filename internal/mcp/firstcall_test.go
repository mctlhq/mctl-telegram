package mcp

import (
	"context"
	"sync"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

type firstCallRecorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *firstCallRecorder) Called(_ context.Context, userID int64, clientID string) {
	r.mu.Lock()
	r.calls = append(r.calls, clientID)
	r.mu.Unlock()
}

func (r *firstCallRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// The connect funnel hears of a tools/list and of a tools/call that did not
// come back IsError, and of nothing else (issue #960).
func TestFirstCallHooks(t *testing.T) {
	store := newToolsTestStore(t)
	rec := &firstCallRecorder{}
	srv := (&Server{Store: store}).WithConnectFunnel(rec).newMCPServer()

	const adminUID int64 = 4205
	const targetTGID int64 = 4206
	_ = seedAccountWithSession(t, store, targetTGID, false)
	id := &auth.Identity{UserID: adminUID, ClientID: "claude.ai", Scopes: []string{"admin:users", "telegram:messages:read"}}
	ctx := auth.With(context.Background(), id)

	if res := callTool(t, ctx, srv, "search_messages", map[string]any{"query": ""}); !res.IsError {
		t.Fatalf("empty query: want an IsError result, got %+v", res)
	}
	if n := rec.count(); n != 0 {
		t.Fatalf("an IsError tools/call reached the funnel (%d calls)", n)
	}
	if env := callRPC(t, ctx, srv, string(mcplib.MethodToolsCall), map[string]any{"name": "no_such_tool", "arguments": map[string]any{}}); env.Error == nil {
		t.Fatal("unknown tool: want a JSON-RPC error")
	}
	if n := rec.count(); n != 0 {
		t.Fatalf("a JSON-RPC-level failure reached the funnel (%d calls)", n)
	}

	if res := callTool(t, ctx, srv, "get_user_audit_log", map[string]any{"telegram_id": float64(targetTGID)}); res.IsError {
		t.Fatalf("get_user_audit_log: want success, got %+v", res)
	}
	if n := rec.count(); n != 1 {
		t.Fatalf("successful tools/call: funnel calls = %d, want 1", n)
	}

	if env := callRPC(t, ctx, srv, string(mcplib.MethodToolsList), map[string]any{}); env.Error != nil {
		t.Fatalf("tools/list: %+v", env.Error)
	}
	if n := rec.count(); n != 2 {
		t.Fatalf("tools/list: funnel calls = %d, want 2", n)
	}
	if rec.calls[0] != "claude.ai" || rec.calls[1] != "claude.ai" {
		t.Fatalf("client ids = %v, want the identity's", rec.calls)
	}

	// No identity, nothing to correlate.
	if env := callRPC(t, context.Background(), srv, string(mcplib.MethodToolsList), map[string]any{}); env.Error != nil {
		t.Fatalf("anonymous tools/list: %+v", env.Error)
	}
	if n := rec.count(); n != 2 {
		t.Fatalf("anonymous tools/list reached the funnel (%d calls)", n)
	}
}

// Without a funnel the hooks are not installed at all.
func TestFirstCallHooksAbsentWithoutFunnel(t *testing.T) {
	srv := (&Server{Store: newToolsTestStore(t)}).newMCPServer()
	ctx := auth.With(context.Background(), &auth.Identity{UserID: 1, ClientID: "claude.ai"})
	if env := callRPC(t, ctx, srv, string(mcplib.MethodToolsList), map[string]any{}); env.Error != nil {
		t.Fatalf("tools/list: %+v", env.Error)
	}
}
