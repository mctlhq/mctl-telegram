package mcp

import (
	"context"
	"encoding/json"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// TestToolGetMyNotificationPreferences_RequiresAccountManage mirrors
// TestToolSetSendConsent_RequiresAccountManage: a credential without
// account:manage (what a device/worker credential actually carries) must be
// refused, never see another account's -- or even its own -- preferences.
func TestToolGetMyNotificationPreferences_RequiresAccountManage(t *testing.T) {
	store := newToolsTestStore(t)
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, 700000401, "owner", "Owner")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	srv := &Server{Store: store}
	_, handler := srv.toolGetMyNotificationPreferences()

	authCtx := auth.With(context.Background(), &auth.Identity{
		UserID: uid, Scopes: []string{"telegram:dialogs:read"},
	})
	res, err := handler(authCtx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "get_my_notification_preferences",
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !res.IsError {
		t.Fatal("a credential without account:manage was allowed to read notification preferences")
	}
}

// TestToolGetMyNotificationPreferences_ReturnsDefaults asserts the owner
// path returns the three resolved categories with their Go-computed
// defaults when nothing has been explicitly decided.
func TestToolGetMyNotificationPreferences_ReturnsDefaults(t *testing.T) {
	store := newToolsTestStore(t)
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, 700000402, "owner", "Owner")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	srv := &Server{Store: store}
	_, handler := srv.toolGetMyNotificationPreferences()

	authCtx := auth.With(context.Background(), &auth.Identity{
		UserID: uid, Scopes: []string{"account:manage"},
	})
	res, err := handler(authCtx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "get_my_notification_preferences",
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if res.IsError {
		t.Fatalf("call was refused: %+v", res.Content)
	}
	var out notificationPrefsResult
	decodeToolJSON(t, res, &out)
	if len(out.Categories) != 3 {
		t.Fatalf("got %d categories, want 3", len(out.Categories))
	}
	for _, p := range out.Categories {
		if p.Explicit {
			t.Errorf("%s: Explicit = true, want false", p.Category)
		}
	}
}

// TestToolSetMyNotificationPreferences_PartialUpdateAndValidation is the
// tool-layer half of T10/T11: a partial change writes only the named
// category, and an unknown category/state is refused with nothing written.
func TestToolSetMyNotificationPreferences_PartialUpdateAndValidation(t *testing.T) {
	store := newToolsTestStore(t)
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, 700000403, "owner", "Owner")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	srv := &Server{Store: store}
	_, handler := srv.toolSetMyNotificationPreferences()
	authCtx := auth.With(context.Background(), &auth.Identity{
		UserID: uid, Scopes: []string{"account:manage"},
	})

	res, err := handler(authCtx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "set_my_notification_preferences",
		Arguments: map[string]any{"preferences": map[string]any{"product_updates": "unsubscribed"}},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if res.IsError {
		t.Fatalf("valid partial update was refused: %+v", res.Content)
	}
	var out notificationPrefsResult
	decodeToolJSON(t, res, &out)
	for _, p := range out.Categories {
		switch p.Category {
		case string(db.CategoryProductUpdates):
			if !p.Explicit || p.State != db.PrefUnsubscribed {
				t.Errorf("product_updates = %+v, want explicit unsubscribed", p)
			}
			if p.Source != "mcp_tool" {
				t.Errorf("source = %q, want mcp_tool", p.Source)
			}
		default:
			if p.Explicit {
				t.Errorf("%s became explicit after a product_updates-only change", p.Category)
			}
		}
	}

	// Unknown category: refused, nothing written.
	res, err = handler(authCtx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "set_my_notification_preferences",
		Arguments: map[string]any{"preferences": map[string]any{"bogus": "subscribed"}},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !res.IsError {
		t.Fatal("an unknown category was accepted")
	}
}

// decodeToolJSON extracts the JSON text content from a successful
// CallToolResult and unmarshals it into out.
func decodeToolJSON(t *testing.T, res *mcplib.CallToolResult, out any) {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("result has no content")
	}
	tc, ok := mcplib.AsTextContent(res.Content[0])
	if !ok {
		t.Fatalf("result content is not text: %+v", res.Content[0])
	}
	if err := json.Unmarshal([]byte(tc.Text), out); err != nil {
		t.Fatalf("decode result JSON: %v\ntext: %s", err, tc.Text)
	}
}
