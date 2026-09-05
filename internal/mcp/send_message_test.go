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

// TestToolSendMessage_HintOnlyForSendDisabled covers all four dry-run causes
// and asserts SendResult.Hint is a presentation-only add-on: empty for three
// of them, and equal to the expected nudge only when the per-account
// send_enabled flag is the reason. This is a regression guard for the hint
// logic staying scoped to exactly the one cause it was written for.
func TestToolSendMessage_HintOnlyForSendDisabled(t *testing.T) {
	const wantHint = "Your account has never opted into real sends. Enable them with set_send_consent or from /telegram/connect/manage, or call get_my_send_status to confirm this is the reason."

	cases := []struct {
		name     string
		build    func(t *testing.T) (*Server, *auth.Identity)
		wantHint string
	}{
		{
			name: "reviewer/demo account",
			build: func(t *testing.T) (*Server, *auth.Identity) {
				store := newToolsTestStore(t)
				uid := seedAccountWithSession(t, store, guardReviewerTGID, true)
				srv := &Server{Store: store, AllowSend: true, DemoReviewerTGID: guardReviewerTGID}
				id := &auth.Identity{UserID: uid, TelegramID: guardReviewerTGID, Scopes: []string{"telegram:messages:send"}}
				return srv, id
			},
			wantHint: "",
		},
		{
			name: "ALLOW_SEND=false",
			build: func(t *testing.T) (*Server, *auth.Identity) {
				srv := &Server{Store: newToolsTestStore(t), AllowSend: false}
				id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
				return srv, id
			},
			wantHint: "",
		},
		{
			name: "missing telegram:messages:send scope",
			build: func(t *testing.T) (*Server, *auth.Identity) {
				srv := &Server{Store: newToolsTestStore(t), AllowSend: true}
				id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:read"}}
				return srv, id
			},
			wantHint: "",
		},
		{
			name: "send_enabled=false",
			build: func(t *testing.T) (*Server, *auth.Identity) {
				store := newToolsTestStore(t)
				uid := seedAccountWithSession(t, store, 424242, false)
				srv := &Server{Store: store, AllowSend: true}
				id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}
				return srv, id
			},
			wantHint: wantHint,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, id := tc.build(t)
			out := parseSendResult(t, callSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi"}))
			if out["sent"] != false {
				t.Fatalf("sent = %v, want false (dry-run)", out["sent"])
			}
			gotHint := toStr(out["hint"])
			if gotHint != tc.wantHint {
				t.Fatalf("hint = %q, want %q", gotHint, tc.wantHint)
			}
		})
	}
}

// TestToolSendMessage_RealSendHasNoHint is the T3 regression guard: when the
// gate is fully open and a message is actually delivered, Hint must stay
// empty and Sent must be true. The only real-send path this test suite can
// exercise without a live MTProto connection is the local-bridge path (see
// TestToolSendMessage_LocalBridgeInjectsSendMode); it shares that setup.
func TestToolSendMessage_RealSendHasNoHint(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedLocalAccount(t, store, 910)

	hub := bridge.NewHub()
	send := hub.Register(uid, "")

	go func() {
		env := <-send
		hub.Deliver(uid, bridge.EncodeResponse(env.ID, json.RawMessage(`{"sent":true,"mode":"send"}`)))
	}()

	srv := &Server{Store: store, Hub: hub, AllowSend: true}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	out := parseSendResult(t, callSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi"}))
	if out["sent"] != true {
		t.Fatalf("sent = %v, want true", out["sent"])
	}
	if hint := out["hint"]; hint != nil && hint != "" {
		t.Fatalf("hint = %v, want empty on a real send", hint)
	}
}

// TestToolSendMessage_DraftAuditUnaffectedByHint is the T4 regression guard:
// the hint logic runs strictly after s.audit records the draft attempt, so
// adding it must not change what gets audited (tool_name, call site, or
// status) for the send_enabled=false dry-run path.
func TestToolSendMessage_DraftAuditUnaffectedByHint(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedAccountWithSession(t, store, 424243, false)
	srv := &Server{Store: store, AllowSend: true}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}

	out := parseSendResult(t, callSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi"}))
	if out["sent"] != false {
		t.Fatalf("sent = %v, want false", out["sent"])
	}

	tool, status, errMsg := latestAudit(t, store, uid)
	if tool != "send_message:draft" {
		t.Fatalf("audit tool_name = %q, want send_message:draft", tool)
	}
	if status != "ok" {
		t.Fatalf("audit status = %q, errMsg = %q, want ok", status, errMsg)
	}
}
