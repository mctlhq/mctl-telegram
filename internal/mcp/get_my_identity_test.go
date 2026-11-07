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

func decodeIdentity(t *testing.T, res *mcplib.CallToolResult) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("unexpected tool error: %+v", res.Content)
	}
	text, ok := res.Content[0].(mcplib.TextContent)
	if !ok {
		t.Fatalf("content is %T, want TextContent", res.Content[0])
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// #749: the answer separates the sign-in identity from the connected
// session, and an unreadable session is omitted, never reported as false.
func TestGetMyIdentity_ReportsConnectedAccount(t *testing.T) {
	t.Run("connected", func(t *testing.T) {
		store := newToolsTestStore(t)
		uid := seedAccountWithSession(t, store, 4101, false)
		if _, err := store.DB.ExecContext(context.Background(),
			`UPDATE telegram_accounts SET username = 'alice', display_name = 'Alice' WHERE user_id = $1`, uid); err != nil {
			t.Fatalf("label account: %v", err)
		}
		out := decodeIdentity(t, callGetMyIdentity(t, &Server{Store: store}, &auth.Identity{UserID: uid, TelegramID: 4101}))
		if out["connected"] != true {
			t.Fatalf("connected = %v, want true", out["connected"])
		}
		acct, ok := out["connected_account"].(map[string]any)
		if !ok {
			t.Fatalf("connected_account missing: %v", out)
		}
		if acct["username"] != "alice" || acct["display_name"] != "Alice" {
			t.Fatalf("connected_account = %v", acct)
		}
		if _, ok := acct["connected_at"]; !ok {
			t.Fatalf("connected_at missing: %v", acct)
		}
	})
	t.Run("signed in, no session", func(t *testing.T) {
		store := newToolsTestStore(t)
		uid, err := store.EnsureUserByTelegramID(context.Background(), 4102, "bob", "Bob")
		if err != nil {
			t.Fatalf("ensure: %v", err)
		}
		out := decodeIdentity(t, callGetMyIdentity(t, &Server{Store: store}, &auth.Identity{UserID: uid, TelegramID: 4102}))
		if out["connected"] != false {
			t.Fatalf("connected = %v, want false", out["connected"])
		}
		if _, ok := out["connected_account"]; ok {
			t.Fatalf("connected_account present without a session: %v", out)
		}
	})
	t.Run("unreadable session is omitted", func(t *testing.T) {
		store := newToolsTestStore(t)
		uid := seedAccountWithSession(t, store, 4103, false)
		if _, err := store.DB.ExecContext(context.Background(), `DROP TABLE telegram_accounts`); err != nil {
			t.Fatalf("drop: %v", err)
		}
		out := decodeIdentity(t, callGetMyIdentity(t, &Server{Store: store}, &auth.Identity{UserID: uid, TelegramID: 4103}))
		if _, ok := out["connected"]; ok {
			t.Fatalf("connected reported after a failed read: %v", out)
		}
		if _, ok := out["connected_account"]; ok {
			t.Fatalf("connected_account reported after a failed read: %v", out)
		}
		if out["telegram_id"] != float64(4103) {
			t.Fatalf("sign-in identity lost: %v", out)
		}
	})
}
