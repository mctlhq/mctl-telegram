package mcp

import (
	"context"
	"encoding/json"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// callSend invokes the send_message handler with the given args and identity.
func callSend(t *testing.T, srv *Server, id *auth.Identity, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	_, handler := srv.toolSendMessage()
	ctx := auth.With(context.Background(), id)
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "send_message",
		Arguments: args,
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	return res
}

// parseSendResult decodes a successful send_message tool result.
func parseSendResult(t *testing.T, res *mcplib.CallToolResult) map[string]any {
	t.Helper()
	if res.IsError {
		t.Fatalf("expected success result, got tool error: %s", contentText(res))
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(contentText(res)), &out); err != nil {
		t.Fatalf("result is not JSON: %v (%s)", err, contentText(res))
	}
	return out
}

// When the send gate is closed (ALLOW_SEND=false is the production default),
// the tool must return a dry-run preview, NOT an error. Regression guard for
// the "draft reply" workflow promised on /security and the landing page.
func TestToolSendMessage_GateBlockedReturnsDraftPreview(t *testing.T) {
	srv := &Server{AllowSend: false, Store: newToolsTestStore(t)}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}

	out := parseSendResult(t, callSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi"}))
	if out["sent"] != false {
		t.Errorf("sent = %v, want false", out["sent"])
	}
	if out["mode"] != "draft" {
		t.Errorf("mode = %v, want draft", out["mode"])
	}
	if out["dry_reason"] == nil || out["dry_reason"] == "" {
		t.Errorf("expected a dry_reason explaining the block, got %v", out["dry_reason"])
	}
}

// A legacy/mobile client passing the removed mode="draft" argument must not
// blow up and must not send for real — the gate, not the argument, decides.
func TestToolSendMessage_IgnoresClientDraftMode(t *testing.T) {
	srv := &Server{AllowSend: false, Store: newToolsTestStore(t)}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}

	out := parseSendResult(t, callSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi", "mode": "draft"}))
	if out["sent"] != false {
		t.Errorf("sent = %v, want false (must not real-send)", out["sent"])
	}
}

// seedLocalAccount inserts a non-revoked local-bridge account with send_enabled.
func seedLocalAccount(t *testing.T, store *db.Store, tgID int64) int64 {
	t.Helper()
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, tgID, "seed", "Seed User")
	if err != nil {
		t.Fatalf("EnsureUserByTelegramID: %v", err)
	}
	if _, err := store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, send_enabled, mode) VALUES($1, $2, $3, 'local')`,
		uid, []byte("blob"), true,
	); err != nil {
		t.Fatalf("seed local account: %v", err)
	}
	return uid
}

// When the gate passes for a local-bridge account, the server must inject
// mode="send" into the args it forwards to the daemon — otherwise the daemon
// (realSend := args.Mode == "send") silently treats it as a dry-run and the
// message never leaves the user's machine. Regression guard for the bridge
// send-propagation contract.
func TestToolSendMessage_LocalBridgeInjectsSendMode(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedLocalAccount(t, store, 909)

	hub := bridge.NewHub()
	send := hub.Register(uid, "")

	gotMode := make(chan string, 1)
	go func() {
		env := <-send
		var args map[string]any
		_ = json.Unmarshal(env.Args, &args)
		gotMode <- toStr(args["mode"])
		hub.Deliver(uid, bridge.EncodeResponse(env.ID, json.RawMessage(`{"sent":true,"mode":"send"}`)))
	}()

	srv := &Server{Store: store, Hub: hub, AllowSend: true}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	res := callSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi"})
	if res.IsError {
		t.Fatalf("bridge send returned tool error: %s", contentText(res))
	}
	if m := <-gotMode; m != "send" {
		t.Fatalf("daemon received mode=%q, want \"send\" (would silently no-op otherwise)", m)
	}
}

func toStr(v any) string {
	s, _ := v.(string)
	return s
}
