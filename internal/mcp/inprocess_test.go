package mcp

import (
	"context"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

func TestCallToolInProcess_RoutesThroughRegisteredHandler(t *testing.T) {
	s := New(newToolsTestStore(t), nil, false)
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:dialogs:read"}}
	res, err := s.CallToolInProcess(context.Background(), id, "get_my_identity", map[string]any{})
	if err != nil {
		t.Fatalf("CallToolInProcess: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
}

func TestCallToolInProcess_UnknownToolIsRefused(t *testing.T) {
	s := New(newToolsTestStore(t), nil, false)
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:dialogs:read"}}
	res, err := s.CallToolInProcess(context.Background(), id, "no_such_tool", nil)
	if err == nil && (res == nil || !res.IsError) {
		t.Fatalf("an unregistered tool must not succeed: res=%v", res)
	}
}

func TestCallToolInProcess_HonoursToolScopes(t *testing.T) {
	s := New(newToolsTestStore(t), nil, false)
	// No scopes: list_dialogs is filtered out before any handler runs, so the
	// call must fail without touching the (nil) pool.
	id := &auth.Identity{UserID: 1}
	res, err := s.CallToolInProcess(context.Background(), id, "list_dialogs", map[string]any{"limit": 1})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatalf("a tool outside the identity's scopes must be refused: res=%v", res)
	}
}

func TestCallToolInProcess_RequiresIdentity(t *testing.T) {
	if _, err := New(newToolsTestStore(t), nil, false).CallToolInProcess(context.Background(), nil, "list_dialogs", nil); err == nil {
		t.Fatal("expected an error without an identity")
	}
}
