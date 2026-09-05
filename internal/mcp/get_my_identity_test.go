package mcp

import (
	"context"
	"encoding/json"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
)

func callGetMyIdentity(t *testing.T, srv *Server, id *auth.Identity) *mcplib.CallToolResult {
	t.Helper()
	_, handler := srv.toolGetMyIdentity()
	ctx := context.Background()
	if id != nil {
		ctx = auth.With(ctx, id)
	}
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "get_my_identity",
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	return res
}

func TestGetMyIdentity_ReturnsCallerOnly(t *testing.T) {
	store := newToolsTestStore(t)
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, 888, "me", "My Name")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := store.EnsureUserByTelegramID(ctx, 999, "other", "Someone Else"); err != nil {
		t.Fatalf("ensure other: %v", err)
	}
	srv := &Server{Store: store}
	res := callGetMyIdentity(t, srv, &auth.Identity{UserID: uid, TelegramID: 888})
	if res.IsError {
		t.Fatalf("tool error: %s", contentText(res))
	}
	var out myIdentityResult
	if err := json.Unmarshal([]byte(contentText(res)), &out); err != nil {
		t.Fatalf("json: %v (%s)", err, contentText(res))
	}
	if out.TelegramID != 888 || out.Username != "me" || out.DisplayName != "My Name" {
		t.Fatalf("got %+v, want telegram_id=888 username=me display_name=My Name", out)
	}
}

func TestGetMyIdentity_RequiresAuth(t *testing.T) {
	res := callGetMyIdentity(t, &Server{}, nil)
	if !res.IsError {
		t.Fatal("unauthenticated call must fail")
	}
}

func TestGetMyIdentity_NoIdentityIsError(t *testing.T) {
	res := callGetMyIdentity(t, &Server{}, &auth.Identity{UserID: 1})
	if !res.IsError {
		t.Fatal("session without Telegram identity must fail")
	}
}
