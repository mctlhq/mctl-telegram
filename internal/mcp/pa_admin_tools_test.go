package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// TestSetPAPrincipalDisabled_AdminOnly: only admin:users may disable or
// re-enable a principal's PA; the read tool also takes admin:users:read.
// A refused call writes nothing; an accepted one is audited to the admin,
// and the store reads it back (#1318, T11).
func TestSetPAPrincipalDisabled_AdminOnly(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	const aliceTG, danaTG int64 = 500100101, 500100303
	adminUID, err := store.EnsureUserByTelegramID(ctx, danaTG, "dana", "Dana")
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{Store: store}
	_, set := srv.toolSetPAPrincipalDisabled()
	_, get := srv.toolGetPAPrincipalStatus()
	call := func(h func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error), scopes []string, args map[string]any) *mcplib.CallToolResult {
		t.Helper()
		id := &auth.Identity{UserID: adminUID, TelegramID: danaTG, Scopes: scopes}
		res, err := h(auth.With(ctx, id), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Arguments: args}})
		if err != nil {
			t.Fatalf("Go error: %v", err)
		}
		return res
	}
	disabled := func() bool {
		t.Helper()
		d, err := store.PAPrincipalDisabledState(ctx, aliceTG)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	on := map[string]any{"telegram_id": float64(aliceTG), "disabled": true, "reason": "abuse report"}

	for name, scopes := range map[string][]string{
		"no scope":         nil,
		"read scope":       {"admin:users:read"},
		"client scopes":    {"telegram:messages:read", "telegram:messages:send", "account:manage"},
		"broadcast scope":  {"admin:broadcast"},
		"lookalike scope":  {"admin:users:write"},
		"admin users read": {"admin:users:read", "telegram:messages:read"},
	} {
		if res := call(set, scopes, on); !res.IsError {
			t.Fatalf("%s: disable accepted", name)
		}
	}
	if disabled() {
		t.Fatal("a refused call disabled the principal")
	}

	for name, args := range map[string]map[string]any{
		"no reason":       {"telegram_id": float64(aliceTG), "disabled": true},
		"long reason":     {"telegram_id": float64(aliceTG), "disabled": true, "reason": strings.Repeat("x", 201)},
		"two lines":       {"telegram_id": float64(aliceTG), "disabled": true, "reason": "a\nb"},
		"no disabled":     {"telegram_id": float64(aliceTG), "reason": "x"},
		"disabled string": {"telegram_id": float64(aliceTG), "disabled": "true", "reason": "x"},
		"no id":           {"disabled": true, "reason": "x"},
	} {
		if res := call(set, []string{"admin:users"}, args); !res.IsError {
			t.Fatalf("%s: accepted", name)
		}
	}
	if disabled() {
		t.Fatal("an invalid call disabled the principal")
	}

	res := call(set, []string{"admin:users"}, on)
	if res.IsError {
		t.Fatalf("admin disable refused: %s", contentText(res))
	}
	var out paPrincipalDisableResult
	if err := json.Unmarshal([]byte(contentText(res)), &out); err != nil || out.TelegramID != aliceTG || !out.Disabled {
		t.Fatalf("result %s (%v)", contentText(res), err)
	}
	if !disabled() {
		t.Fatal("admin disable not stored")
	}
	if tool, status, _ := latestAudit(t, store, adminUID); tool != "set_pa_principal_disabled" || status != "ok" {
		t.Fatalf("audit %q %q", tool, status)
	}

	for _, scopes := range [][]string{{"admin:users"}, {"admin:users:read"}} {
		res := call(get, scopes, map[string]any{"telegram_id": float64(aliceTG)})
		var st paPrincipalDisableResult
		if res.IsError || json.Unmarshal([]byte(contentText(res)), &st) != nil || !st.Disabled || st.TelegramID != aliceTG {
			t.Fatalf("status with %v: %s", scopes, contentText(res))
		}
	}
	if res := call(get, []string{"telegram:messages:read"}, map[string]any{"telegram_id": float64(aliceTG)}); !res.IsError {
		t.Fatal("status readable without an admin scope")
	}

	if res := call(set, []string{"admin:users:read"}, map[string]any{"telegram_id": float64(aliceTG), "disabled": false}); !res.IsError || !disabled() {
		t.Fatal("re-enable accepted with the read scope")
	}
	if res := call(set, []string{"admin:users"}, map[string]any{"telegram_id": float64(aliceTG), "disabled": false}); res.IsError || disabled() {
		t.Fatalf("admin re-enable: %s", contentText(res))
	}
}
