package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
)

// T6: revoke_worker_token rejects a caller without admin:users.
func TestToolRevokeWorkerToken_RequiresAdminScope(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t)}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolRevokeWorkerToken()
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "revoke_worker_token",
		Arguments: map[string]any{"jti": "some-jti"},
	}}
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected scope rejection for identity without admin:users")
	}
}

// T6: rejects a call with both jti and telegram_id set.
func TestToolRevokeWorkerToken_RejectsBothFields(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t)}
	id := &auth.Identity{UserID: 1, Scopes: []string{"admin:users"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolRevokeWorkerToken()
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "revoke_worker_token",
		Arguments: map[string]any{"jti": "some-jti", "telegram_id": float64(42)},
	}}
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected rejection when both jti and telegram_id are set")
	}
}

// T6: rejects a call with neither field set.
func TestToolRevokeWorkerToken_RejectsNeitherField(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t)}
	id := &auth.Identity{UserID: 1, Scopes: []string{"admin:users"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolRevokeWorkerToken()
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "revoke_worker_token",
		Arguments: map[string]any{},
	}}
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected rejection when neither jti nor telegram_id is set")
	}
}

// T6: succeeds with exactly jti set.
func TestToolRevokeWorkerToken_SucceedsWithJti(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	srv := &Server{Store: store}
	id := &auth.Identity{UserID: 1, Scopes: []string{"admin:users"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolRevokeWorkerToken()
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "revoke_worker_token",
		Arguments: map[string]any{"jti": "leaked-jti", "reason": "leaked in a support ticket"},
	}}
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got tool error: %s", contentText(result))
	}
	var out map[string]any
	if jsonErr := json.Unmarshal([]byte(contentText(result)), &out); jsonErr != nil {
		t.Fatalf("result is not JSON: %v", jsonErr)
	}
	if out["revoked"] != true {
		t.Errorf("unexpected response: %v", out)
	}
	revoked, err := store.IsWorkerTokenRevoked(ctx, "leaked-jti", 0, time.Now())
	if err != nil || !revoked {
		t.Errorf("jti not recorded as revoked: revoked=%v err=%v", revoked, err)
	}
}

// T6: succeeds with exactly telegram_id set.
func TestToolRevokeWorkerToken_SucceedsWithTelegramID(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	srv := &Server{Store: store}
	id := &auth.Identity{UserID: 1, Scopes: []string{"admin:users"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolRevokeWorkerToken()
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "revoke_worker_token",
		Arguments: map[string]any{"telegram_id": float64(555)},
	}}
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got tool error: %s", contentText(result))
	}
	// A token "issued" before the revocation call is covered by it; one
	// issued at time.Now() (after) legitimately is not — see
	// IsWorkerTokenRevoked's "at or before" semantics.
	revoked, err := store.IsWorkerTokenRevoked(ctx, "any-jti", 555, time.Now().Add(-time.Hour))
	if err != nil || !revoked {
		t.Errorf("telegram_id 555 not recorded as blanket-revoked: revoked=%v err=%v", revoked, err)
	}
}

// TE1: revoking by telegram_id evicts a live Local Bridge daemon connection
// for that account. Validated by mutation: removing the Hub.Unregister call
// in toolRevokeWorkerToken makes hub.Call keep succeeding (or block/time out
// on the still-open channel) instead of returning ErrNoDaemonConnected.
func TestToolRevokeWorkerToken_EvictsLiveDaemonConnection(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 42, "daemon-user", "Daemon User")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	hub := bridge.NewHub()
	hub.Register(uid)
	if !hub.HasDaemon(uid) {
		t.Fatal("daemon should be registered before revocation")
	}

	srv := &Server{Store: store, Hub: hub}
	id := &auth.Identity{UserID: 1, Scopes: []string{"admin:users"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolRevokeWorkerToken()
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "revoke_worker_token",
		Arguments: map[string]any{"telegram_id": float64(42)},
	}}
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got tool error: %s", contentText(result))
	}
	var out map[string]any
	if jsonErr := json.Unmarshal([]byte(contentText(result)), &out); jsonErr != nil {
		t.Fatalf("result is not JSON: %v", jsonErr)
	}
	if out["hub_evicted"] != true {
		t.Errorf("expected hub_evicted=true, got: %v", out)
	}

	if hub.HasDaemon(uid) {
		t.Fatal("daemon connection should have been evicted by revocation")
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if _, err := hub.Call(callCtx, uid, bridge.Envelope{ID: "x", Type: bridge.TypeCall}); err != bridge.ErrNoDaemonConnected {
		t.Fatalf("expected ErrNoDaemonConnected after eviction, got: %v", err)
	}
}

// Revoking an account with no connected daemon is a no-op, not an error.
func TestToolRevokeWorkerToken_NoDaemonConnectedIsNoop(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	if _, err := store.EnsureUserByTelegramID(ctx, 43, "no-daemon-user", "No Daemon"); err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	srv := &Server{Store: store, Hub: bridge.NewHub()}
	id := &auth.Identity{UserID: 1, Scopes: []string{"admin:users"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolRevokeWorkerToken()
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "revoke_worker_token",
		Arguments: map[string]any{"telegram_id": float64(43)},
	}}
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success even with no connected daemon, got tool error: %s", contentText(result))
	}
	var out map[string]any
	if jsonErr := json.Unmarshal([]byte(contentText(result)), &out); jsonErr != nil {
		t.Fatalf("result is not JSON: %v", jsonErr)
	}
	if out["hub_evicted"] != false {
		t.Errorf("expected hub_evicted=false with no daemon connected, got: %v", out)
	}
}
