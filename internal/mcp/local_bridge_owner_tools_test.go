package mcp

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// ownerToolFixture returns a store with one local account and one registered
// device belonging to it, plus the owner's user id.
func ownerToolFixture(t *testing.T, tgID int64) (*db.Store, int64, string) {
	t.Helper()
	ctx := context.Background()
	store := newToolsTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, tgID, "owner", "Owner")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := store.ProvisionLocalAccount(ctx, uid, tgID, "Owner", "owner"); err != nil {
		t.Fatalf("provision local account: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	deviceID, err := store.RegisterDevice(ctx, uid, "laptop", "idem-owner", pub)
	if err != nil {
		t.Fatalf("register device: %v", err)
	}
	return store, uid, deviceID
}

// The account:manage gate is the whole reason the owner consent tool is safe
// to expose: a device credential authenticates AS its owner, so a tool open
// to any authenticated identity would let a stolen device credential re-grant
// itself the send consent its owner had just revoked. Device and worker
// credentials can never hold account:manage, so the scope is the boundary.
func TestToolSetSendConsent_RequiresAccountManage(t *testing.T) {
	store, uid, _ := ownerToolFixture(t, 700000301)
	srv := &Server{Store: store}
	_, handler := srv.toolSetSendConsent()

	// The scope set a device credential actually carries.
	ctx := auth.With(context.Background(), &auth.Identity{
		UserID: uid, Scopes: []string{"telegram:dialogs:read", "telegram:messages:read"},
	})
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "set_send_consent", Arguments: map[string]any{"enabled": true},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !res.IsError {
		t.Fatal("a credential without account:manage was allowed to grant send consent")
	}
	enabled, err := store.IsSendEnabled(context.Background(), uid)
	if err != nil {
		t.Fatalf("IsSendEnabled: %v", err)
	}
	if enabled {
		t.Fatal("send_enabled was flipped by a call that should have been refused")
	}
}

// The owner's own session does hold account:manage, and the tool toggles the
// account flag in both directions.
func TestToolSetSendConsent_GrantAndRevoke(t *testing.T) {
	store, uid, _ := ownerToolFixture(t, 700000302)
	srv := &Server{Store: store}
	_, handler := srv.toolSetSendConsent()
	ctx := auth.With(context.Background(), &auth.Identity{
		UserID: uid, Scopes: []string{"account:manage"},
	})

	for _, want := range []bool{true, false} {
		res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
			Name: "set_send_consent", Arguments: map[string]any{"enabled": want},
		}})
		if err != nil {
			t.Fatalf("unexpected Go error: %v", err)
		}
		if res.IsError {
			t.Fatalf("enabled=%v was refused: %+v", want, res.Content)
		}
		got, err := store.IsSendEnabled(context.Background(), uid)
		if err != nil {
			t.Fatalf("IsSendEnabled: %v", err)
		}
		if got != want {
			t.Fatalf("send_enabled = %v, want %v", got, want)
		}
	}
}

func TestToolRevokeLocalBridgeDevice_RequiresAccountManage(t *testing.T) {
	store, uid, deviceID := ownerToolFixture(t, 700000303)
	srv := &Server{Store: store}
	_, handler := srv.toolRevokeLocalBridgeDevice()
	ctx := auth.With(context.Background(), &auth.Identity{
		UserID: uid, Scopes: []string{"telegram:messages:read"},
	})
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "revoke_local_bridge_device", Arguments: map[string]any{"device_id": deviceID},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !res.IsError {
		t.Fatal("a credential without account:manage was allowed to revoke a device")
	}
	dev, err := store.GetDevice(context.Background(), deviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if dev.RevokedAt != nil {
		t.Fatal("the device was revoked by a call that should have been refused")
	}
}

// A device belonging to somebody else must be refused, and refused the same
// way a nonexistent one is -- otherwise the tool tells a caller which device
// ids exist on other accounts.
func TestToolRevokeLocalBridgeDevice_OwnershipIsEnforcedWithoutAnOracle(t *testing.T) {
	store, _, victimDevice := ownerToolFixture(t, 700000304)
	ctx := context.Background()
	attacker, err := store.EnsureUserByTelegramID(ctx, 700000305, "attacker", "Attacker")
	if err != nil {
		t.Fatalf("ensure attacker: %v", err)
	}
	srv := &Server{Store: store}
	_, handler := srv.toolRevokeLocalBridgeDevice()
	actx := auth.With(ctx, &auth.Identity{UserID: attacker, Scopes: []string{"account:manage"}})

	call := func(id string) *mcplib.CallToolResult {
		res, err := handler(actx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
			Name: "revoke_local_bridge_device", Arguments: map[string]any{"device_id": id},
		}})
		if err != nil {
			t.Fatalf("unexpected Go error: %v", err)
		}
		return res
	}
	someoneElses := call(victimDevice)
	nonexistent := call("dev_no_such_device")
	if !someoneElses.IsError || !nonexistent.IsError {
		t.Fatal("expected both calls to be refused")
	}
	if a, b := renderToolText(t, someoneElses), renderToolText(t, nonexistent); a != b {
		t.Fatalf("messages differ, revealing whether the id exists: someone-else=%q nonexistent=%q", a, b)
	}

	dev, err := store.GetDevice(ctx, victimDevice)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if dev.RevokedAt != nil {
		t.Fatal("another user's device was revoked")
	}
}

// The owner can revoke their own device, and the lineage denylisting runs in
// the same call.
func TestToolRevokeLocalBridgeDevice_OwnerSucceeds(t *testing.T) {
	store, uid, deviceID := ownerToolFixture(t, 700000306)
	srv := &Server{Store: store}
	_, handler := srv.toolRevokeLocalBridgeDevice()
	ctx := auth.With(context.Background(), &auth.Identity{
		UserID: uid, TelegramID: 700000306, Scopes: []string{"account:manage"},
	})
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "revoke_local_bridge_device", Arguments: map[string]any{"device_id": deviceID},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if res.IsError {
		t.Fatalf("owner's own revoke was refused: %+v", res.Content)
	}
	dev, err := store.GetDevice(context.Background(), deviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if dev.RevokedAt == nil {
		t.Fatal("device row is not revoked after a successful revoke call")
	}

	// Re-running it must repair rather than report success over a partial
	// state: an already-revoked device is still accepted.
	res2, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "revoke_local_bridge_device", Arguments: map[string]any{"device_id": deviceID},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error on re-revoke: %v", err)
	}
	if res2.IsError {
		t.Fatalf("re-revoking an already-revoked device was refused: %+v", res2.Content)
	}
}

// renderToolText flattens a tool result's text content for comparison.
func renderToolText(t *testing.T, res *mcplib.CallToolResult) string {
	t.Helper()
	b, err := json.Marshal(res.Content)
	if err != nil {
		t.Fatalf("marshal tool content: %v", err)
	}
	return string(b)
}
