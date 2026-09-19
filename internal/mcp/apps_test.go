package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// callPrepareSend invokes the prepare_send_message handler directly.
func callPrepareSend(t *testing.T, srv *Server, id *auth.Identity, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	_, handler := srv.toolPrepareSendMessage()
	ctx := context.Background()
	if id != nil {
		ctx = auth.With(ctx, id)
	}
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "prepare_send_message",
		Arguments: args,
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	return res
}

func parsePrepareSendResult(t *testing.T, res *mcplib.CallToolResult) map[string]any {
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

// TestToolPrepareSendMessage_MakesNoTelegramCall guards that prepare_send_message
// never borrows a client. Store is real (in-memory) but srv.Pool is left nil;
// any attempt to reach Telegram would panic on a nil pool, so a passing test
// with a nil Pool is itself the evidence of no Telegram call.
func TestToolPrepareSendMessage_MakesNoTelegramCall(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t), Confirms: NewConfirmStore(), AllowSend: true}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	out := parsePrepareSendResult(t, callPrepareSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi"}))
	if out["confirmation_id"] == nil || out["confirmation_id"] == "" {
		t.Fatal("expected a confirmation_id")
	}
}

// TestToolPrepareSendMessage_ConfirmationBoundToPayload is T6's binding half:
// the issued confirmation_id must be consumable only against the exact
// (peer, text) HashSendPayload was computed from.
func TestToolPrepareSendMessage_ConfirmationBoundToPayload(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t), Confirms: NewConfirmStore(), AllowSend: true}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	out := parsePrepareSendResult(t, callPrepareSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi"}))
	confID := toStr(out["confirmation_id"])

	if _, err := srv.Confirms.Consume(confID, id.UserID, HashSendPayload("@x", "different text")); err == nil {
		t.Fatal("confirmation consumed against a different text; must be rejected")
	}
	// Issue a fresh one and consume it correctly, proving the id was valid.
	out2 := parsePrepareSendResult(t, callPrepareSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi"}))
	confID2 := toStr(out2["confirmation_id"])
	if _, err := srv.Confirms.Consume(confID2, id.UserID, HashSendPayload("@x", "hi")); err != nil {
		t.Fatalf("matching (peer, text) should consume cleanly: %v", err)
	}
}

// TestToolPrepareSendMessage_VerdictPerGateConjunct is T6: for each of the
// four send-gate conjuncts, prepare_send_message reports will_really_send
// false with the matching dry_reason, and (per
// TestToolPrepareSendMessage_MakesNoTelegramCall above) makes no Telegram
// call regardless.
func TestToolPrepareSendMessage_VerdictPerGateConjunct(t *testing.T) {
	cases := []struct {
		name          string
		build         func(t *testing.T) (*Server, *auth.Identity)
		wantReasonSub string
	}{
		{
			name: "demo reviewer identity",
			build: func(t *testing.T) (*Server, *auth.Identity) {
				store := newToolsTestStore(t)
				uid := seedAccountWithSession(t, store, guardReviewerTGID, true)
				srv := &Server{Store: store, Confirms: NewConfirmStore(), AllowSend: true, DemoReviewerTGID: guardReviewerTGID}
				id := &auth.Identity{UserID: uid, TelegramID: guardReviewerTGID, Scopes: []string{"telegram:messages:send"}}
				return srv, id
			},
			wantReasonSub: "reviewer/demo",
		},
		{
			name: "ALLOW_SEND=false",
			build: func(t *testing.T) (*Server, *auth.Identity) {
				srv := &Server{Store: newToolsTestStore(t), Confirms: NewConfirmStore(), AllowSend: false}
				id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
				return srv, id
			},
			wantReasonSub: "ALLOW_SEND",
		},
		{
			name: "missing telegram:messages:send scope",
			build: func(t *testing.T) (*Server, *auth.Identity) {
				srv := &Server{Store: newToolsTestStore(t), Confirms: NewConfirmStore(), AllowSend: true}
				id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:read"}}
				return srv, id
			},
			wantReasonSub: "scope",
		},
		{
			name: "send_enabled=false",
			build: func(t *testing.T) (*Server, *auth.Identity) {
				store := newToolsTestStore(t)
				uid := seedAccountWithSession(t, store, 424244, false)
				srv := &Server{Store: store, Confirms: NewConfirmStore(), AllowSend: true}
				id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}
				return srv, id
			},
			wantReasonSub: "send_enabled",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, id := tc.build(t)
			out := parsePrepareSendResult(t, callPrepareSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi"}))
			if out["will_really_send"] != false {
				t.Fatalf("will_really_send = %v, want false", out["will_really_send"])
			}
			reason := toStr(out["dry_reason"])
			if !strings.Contains(reason, tc.wantReasonSub) {
				t.Fatalf("dry_reason = %q, want it to contain %q", reason, tc.wantReasonSub)
			}
			if out["text_sha256"] == nil || out["text_sha256"] == "" {
				t.Fatal("expected text_sha256")
			}
			if out["confirmation_id"] == nil || out["confirmation_id"] == "" {
				t.Fatal("expected confirmation_id even on a dry-run verdict")
			}
		})
	}
}

// TestToolPrepareSendMessage_RequiresAuth mirrors toolPreparePinMessage's own
// auth check: no identity, no confirmation.
func TestToolPrepareSendMessage_RequiresAuth(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t), Confirms: NewConfirmStore(), AllowSend: true}
	res := callPrepareSend(t, srv, nil, map[string]any{"peer": "@x", "text": "hi"})
	if !res.IsError {
		t.Fatal("expected an error without an authenticated identity")
	}
}

// ---- send_message confirmation binding (T7) ----

func issueSendConfirmation(t *testing.T, srv *Server, userID int64, peer, text string) string {
	t.Helper()
	c, err := srv.Confirms.Issue(userID, "send", HashSendPayload(peer, text))
	if err != nil {
		t.Fatalf("issue confirmation: %v", err)
	}
	return c.ID
}

// TestToolSendMessage_ConfirmationMatchingPayloadConsumesCleanly is T7's
// first case: a matching (peer, text) consumes without a confirmation-shaped
// refusal. The send gate is left closed (AllowSend=false) so the assertion
// is purely about the confirmation check, not about delivery.
func TestToolSendMessage_ConfirmationMatchingPayloadConsumesCleanly(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t), Confirms: NewConfirmStore(), AllowSend: false}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	confID := issueSendConfirmation(t, srv, id.UserID, "@x", "hi")

	out := parseSendResult(t, callSend(t, srv, id, map[string]any{
		"peer": "@x", "text": "hi", "confirmation_id": confID,
	}))
	if out["sent"] != false {
		t.Fatalf("sent = %v, want false (gate closed)", out["sent"])
	}
	// A confirmation-shaped refusal would have come back as res.IsError with
	// one of the three confirmation_id error strings; parseSendResult already
	// asserts !res.IsError, so reaching here proves the confirmation consumed.
}

// TestToolSendMessage_ConfirmationMismatchedTextRefused is T7's second case.
func TestToolSendMessage_ConfirmationMismatchedTextRefused(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t), Confirms: NewConfirmStore(), AllowSend: false}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	confID := issueSendConfirmation(t, srv, id.UserID, "@x", "original text")

	res := callSend(t, srv, id, map[string]any{
		"peer": "@x", "text": "swapped text", "confirmation_id": confID,
	})
	if !res.IsError {
		t.Fatal("expected a refusal for a text swapped after prepare")
	}
	if !strings.Contains(contentText(res), "different (peer, text)") {
		t.Fatalf("refusal = %q, want it to name the mismatch", contentText(res))
	}
}

// TestToolSendMessage_ConfirmationReuseRefused is T7's third case: a second
// use of the same id (even with the original, matching payload) is refused
// because Consume is single-shot.
func TestToolSendMessage_ConfirmationReuseRefused(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t), Confirms: NewConfirmStore(), AllowSend: false}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	confID := issueSendConfirmation(t, srv, id.UserID, "@x", "hi")

	first := callSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi", "confirmation_id": confID})
	if first.IsError {
		t.Fatalf("first use should succeed: %s", contentText(first))
	}
	second := callSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi", "confirmation_id": confID})
	if !second.IsError {
		t.Fatal("expected a refusal on reuse of the same confirmation_id")
	}
	if !strings.Contains(contentText(second), "not found, expired, or already used") {
		t.Fatalf("refusal = %q, want the not-found/expired/used wording", contentText(second))
	}
}

// TestToolSendMessage_ConfirmationWrongUserRefused is T7's fourth case: an
// id issued to a different UserID is refused with the wrong-identity wording,
// never with a hint that distinguishes it from "not found" beyond that.
func TestToolSendMessage_ConfirmationWrongUserRefused(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t), Confirms: NewConfirmStore(), AllowSend: false}
	owner := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	attacker := &auth.Identity{UserID: 2, Scopes: []string{"telegram:messages:send"}}
	confID := issueSendConfirmation(t, srv, owner.UserID, "@x", "hi")

	res := callSend(t, srv, attacker, map[string]any{"peer": "@x", "text": "hi", "confirmation_id": confID})
	if !res.IsError {
		t.Fatal("expected a refusal for a confirmation issued to another identity")
	}
	if !strings.Contains(contentText(res), "another identity") {
		t.Fatalf("refusal = %q, want the wrong-identity wording", contentText(res))
	}
}

// TestToolSendMessage_EmptyConfirmationIDUnchanged is part of T8/back-compat:
// omitting confirmation_id entirely takes exactly the pre-existing path (no
// Confirms.Consume call at all), asserted here by using a Store/Confirms pair
// that would fail loudly if Consume were invoked with a zero-value id.
func TestToolSendMessage_EmptyConfirmationIDUnchanged(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t), Confirms: NewConfirmStore(), AllowSend: false}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	out := parseSendResult(t, callSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi"}))
	if out["sent"] != false {
		t.Fatalf("sent = %v, want false", out["sent"])
	}
}

// ---- Adversarial: the App path cannot bypass the send gate (T9) ----

// TestToolSendMessage_AppPathWithValidConfirmationStillDryRunsWhenGateClosed
// is T9's headline assertion: a valid, freshly-consumed confirmation_id does
// not open the send gate. With send_enabled=false the call still returns
// sent=false with a dry_reason, records send_message:draft in the audit log,
// and (Pool is nil here) issues no MTProto call.
func TestToolSendMessage_AppPathWithValidConfirmationStillDryRunsWhenGateClosed(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedAccountWithSession(t, store, 424245, false) // send_enabled=false
	srv := &Server{Store: store, Confirms: NewConfirmStore(), AllowSend: true}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}
	confID := issueSendConfirmation(t, srv, uid, "@x", "hi")

	out := parseSendResult(t, callSend(t, srv, id, map[string]any{
		"peer": "@x", "text": "hi", "confirmation_id": confID,
	}))
	if out["sent"] != false {
		t.Fatalf("sent = %v, want false: an App-supplied confirmation must not open the gate", out["sent"])
	}
	if reason := toStr(out["dry_reason"]); !strings.Contains(reason, "send_enabled") {
		t.Fatalf("dry_reason = %q, want it to name send_enabled=false", reason)
	}
	tool, status, _ := latestAudit(t, store, uid)
	if tool != "send_message:draft" || status != "ok" {
		t.Fatalf("audit tool=%q status=%q, want send_message:draft/ok", tool, status)
	}
}

// TestToolSendMessage_AppPathDebitsSamePeerLimiter is T9's second half: when
// the gate is open, an App-originated send (one carrying a confirmation_id)
// debits the same per-(identity, peer) limiter a model-originated send does.
// Delivery goes through the Local Bridge path (as in
// TestToolSendMessage_LocalBridgeInjectsSendMode) since this suite has no
// live MTProto connection; the limiter check runs identically before that
// dispatch either way.
func TestToolSendMessage_AppPathDebitsSamePeerLimiter(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedLocalAccount(t, store, 912)
	hub := bridge.NewHub()
	send := hub.Register(uid, "")
	go func() {
		env := <-send
		hub.Deliver(uid, bridge.EncodeResponse(env.ID, json.RawMessage(`{"sent":true,"mode":"send"}`)))
	}()

	limiter := audit.NewRateLimiter(1000)
	srv := &Server{Store: store, Hub: hub, Confirms: NewConfirmStore(), AllowSend: true, Limiter: limiter}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}
	peerRedacted := telegram.RedactPeer("@x")

	// Pre-exhaust the peer budget to 1 remaining token so this one send is the
	// last one the limiter allows.
	if !limiter.AllowPeerN(id, peerRedacted, audit.PeerSendCap-1, audit.PeerSendCap, audit.PeerWindow) {
		t.Fatal("failed to prime the limiter")
	}

	confID := issueSendConfirmation(t, srv, uid, "@x", "hi")
	res := callSend(t, srv, id, map[string]any{"peer": "@x", "text": "hi", "confirmation_id": confID})
	if res.IsError {
		t.Fatalf("expected the send to go through: %s", contentText(res))
	}

	if limiter.AllowPeer(id, peerRedacted, audit.PeerSendCap, audit.PeerWindow) {
		t.Fatal("the App-path send did not debit the per-peer limiter: budget was not exhausted")
	}
}

// ---- MCP_TOOL_FILTER interaction (T10) ----

// TestAppsFlag_ReadOnlyFilterDropsSendToolsKeepsUIResource is T10: with
// MCP_TOOL_FILTER=read-only and AppsEnabled=true, prepare_send_message and
// send_message are absent from the registered set, while the App resource
// and the read tools' _meta.ui remain present.
func TestAppsFlag_ReadOnlyFilterDropsSendToolsKeepsUIResource(t *testing.T) {
	srv := &Server{AppsEnabled: true, ToolFilter: "read-only"}
	mcpSrv := srv.newMCPServer()

	tools := mcpSrv.ListTools()
	for _, name := range []string{"prepare_send_message", "send_message"} {
		if _, ok := tools[name]; ok {
			t.Errorf("%s registered under MCP_TOOL_FILTER=read-only; write tools must be dropped", name)
		}
	}
	for _, name := range []string{"list_dialogs", "get_unread_messages", "get_messages", "search_messages", "prepare_get_media"} {
		st, ok := tools[name]
		if !ok {
			t.Fatalf("%s missing from the read-only tool set", name)
		}
		if st.Tool.Meta == nil {
			t.Errorf("%s carries no _meta under AppsEnabled=true even though it is still registered", name)
		}
	}
	resources := mcpSrv.ListResources()
	if len(resources) == 0 {
		t.Error("the App resource is absent under MCP_TOOL_FILTER=read-only; the resource is not a tool and must not be affected by the tool filter")
	}
}
