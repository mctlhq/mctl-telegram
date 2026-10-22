package mcp

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

// reviewerTestTGID is the reviewer/demo identity of these tests. In the reply
// fake, user:7001 is Alice and user:7002 is Bob; only Alice's chat is on the
// allowlist.
const reviewerTestTGID int64 = 990001

const alicePeer = "user:7001"

// reviewerServer is a server whose gate is fully open for the reviewer:
// ALLOW_SEND, every scope, send_enabled on a hosted account. Only the
// reviewer rules stand between the reviewer and Telegram.
func reviewerServer(t *testing.T, writePeers ...string) (*Server, *replyFake, *auth.Identity) {
	t.Helper()
	store := newToolsTestStore(t)
	uid := seedHostedAccount(t, store, reviewerTestTGID, true)
	s := (&Server{Store: store, AllowSend: true, Confirms: NewConfirmStore(), Replies: NewReplyStore()}).
		WithDemoReviewer(reviewerTestTGID, writePeers)
	f := newReplyFake()
	f.install(s)
	id := &auth.Identity{UserID: uid, TelegramID: reviewerTestTGID, Scopes: allToolScopes()}
	return s, f, id
}

func callHandler(t *testing.T, h mcpserver.ToolHandlerFunc, name string, id *auth.Identity, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	return callReplyTool(t, h, name, id, args)
}

// TestReviewerWriteRules_CoverEveryRegisteredTool is the decision table: every
// registered tool is classified for the reviewer, and the classes that let
// the reviewer through are spelled out here rather than read back from
// reviewerWriteRules. A new tool fails this test until someone decides what
// the reviewer may do with it; until then reviewerWriteGuard refuses it.
func TestReviewerWriteRules_CoverEveryRegisteredTool(t *testing.T) {
	registered := fullSurfaceServer(&Server{}).ListTools()
	for name, st := range registered {
		rule, ok := reviewerWriteRules[name]
		if !ok {
			t.Errorf("%s is registered but has no reviewerWriteRules entry; decide what the reviewer may do with it in reviewer.go", name)
			continue
		}
		ro := st.Tool.Annotations.ReadOnlyHint
		if rule == reviewerRead && (ro == nil || !*ro) {
			t.Errorf("%s is classified reviewerRead but is not annotated read-only", name)
		}
	}
	for name := range reviewerWriteRules {
		if _, ok := registered[name]; !ok {
			t.Errorf("reviewerWriteRules names %s, which is not registered", name)
		}
	}

	want := map[reviewerWriteRule][]string{
		reviewerAllowlistedPeer: {"send_message", "send_reply"},
		reviewerAccountGuard:    {"delete_telegram_account", "disconnect_telegram_account"},
		reviewerNoTelegramWrite: {"prepare_pin_message", "prepare_send_message", "set_my_notification_preferences", "set_send_consent"},
	}
	got := map[reviewerWriteRule][]string{}
	for name, rule := range reviewerWriteRules {
		got[rule] = append(got[rule], name)
	}
	for rule, names := range want {
		sort.Strings(got[rule])
		if strings.Join(got[rule], ",") != strings.Join(names, ",") {
			t.Errorf("rule %d covers %v, want %v", rule, got[rule], names)
		}
	}
	// Every Telegram write other than the two allowlisted ones is refused.
	for _, name := range []string{"send_media", "edit_message", "delete_messages", "forward_messages", "set_reaction", "pin_message"} {
		if rule, ok := reviewerWriteRules[name]; !ok || rule != reviewerRefused {
			t.Errorf("%s: rule %d, want reviewerRefused", name, rule)
		}
	}
}

// toolCallResult is the part of a tools/call result these tests read.
type toolCallResult struct {
	IsError bool `json:"isError"`
	Content []struct {
		Text string `json:"text"`
	} `json:"content"`
}

func callToolAs(t *testing.T, srv *mcpserver.MCPServer, id *auth.Identity, name string, args map[string]any) toolCallResult {
	t.Helper()
	env := callRPC(t, auth.With(context.Background(), id), srv, string(mcplib.MethodToolsCall), map[string]any{"name": name, "arguments": args})
	if env.Error != nil {
		t.Fatalf("tools/call %s: JSON-RPC error %+v", name, env.Error)
	}
	var res toolCallResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatalf("decode %s result: %v", name, err)
	}
	return res
}

func (r toolCallResult) text() string {
	if len(r.Content) == 0 {
		return ""
	}
	return r.Content[0].Text
}

// On the real tools/call path a refused tool never reaches its handler: the
// answer is the reviewer refusal, whatever the arguments, for every tool
// the table refuses, even with every scope and the gate wide open.
func TestReviewerWriteGuard_RefusesBeforeTheHandler(t *testing.T) {
	s, _, id := reviewerServer(t, alicePeer)
	srv := fullSurfaceServer(s)
	refused := 0
	for name := range srv.ListTools() {
		if reviewerWriteRules[name] != reviewerRefused {
			continue
		}
		refused++
		res := callToolAs(t, srv, id, name, map[string]any{"peer": alicePeer, "to_peer": alicePeer, "from_peer": alicePeer, "message_id": 1, "message_ids": []any{1}, "text": "hi"})
		if !res.IsError || res.text() != reviewerRefusalText(name) {
			t.Errorf("%s as the reviewer: isError=%v %q", name, res.IsError, res.text())
		}
	}
	if refused < 20 {
		t.Fatalf("only %d refused tools exercised", refused)
	}

	// The same calls by someone else are not the reviewer's business.
	other := &auth.Identity{UserID: id.UserID, TelegramID: 990002, Scopes: allToolScopes()}
	if res := callToolAs(t, srv, other, "edit_message", map[string]any{"peer": alicePeer, "message_id": 1, "text": "hi"}); res.text() == reviewerRefusalText("edit_message") {
		t.Fatalf("a non-reviewer got the reviewer refusal: %q", res.text())
	}

	// The account guards answer as they always have, end to end.
	for _, name := range []string{"disconnect_telegram_account", "delete_telegram_account"} {
		if res := callToolAs(t, srv, id, name, map[string]any{"confirm": true}); !res.IsError || res.text() != demoReviewerAccountMgmtRefusal {
			t.Errorf("%s as the reviewer: %q", name, res.text())
		}
	}

	// An allowlisted send passes the guard and meets the rest of the gate.
	s.AllowSend = false
	res := callToolAs(t, srv, id, "send_message", map[string]any{"peer": alicePeer, "text": "hi"})
	if res.IsError || !strings.Contains(res.text(), "ALLOW_SEND=false") {
		t.Fatalf("allowlisted send_message: isError=%v %s", res.IsError, res.text())
	}
}

// A reviewer refusal by the middleware is audited like any refusal: the
// guard writes no row itself and relies on running inside recordToolCall,
// which this pins.
func TestReviewerWriteGuard_RefusalIsAudited(t *testing.T) {
	s, _, id := reviewerServer(t, alicePeer)
	srv := fullSurfaceServer(s)
	if res := callToolAs(t, srv, id, "edit_message", map[string]any{"peer": alicePeer, "message_id": 1, "text": "hi"}); res.text() != reviewerRefusalText("edit_message") {
		t.Fatalf("edit_message as the reviewer: %q", res.text())
	}
	if n := countAuditRows(t, s.Store, id.UserID); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
	if reason := latestAuditReason(t, s.Store, id.UserID); reason != ReasonRefused {
		t.Fatalf("audit reason = %q, want %q", reason, ReasonRefused)
	}
}

// A tool that has no entry at all is refused to the reviewer: the table
// fails closed for a write tool added without a decision.
func TestReviewerWriteGuard_UnclassifiedToolIsRefused(t *testing.T) {
	s, _, id := reviewerServer(t, alicePeer)
	ran := false
	h := s.reviewerWriteGuard(func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		ran = true
		return mcplib.NewToolResultText("ok"), nil
	})
	res := callHandler(t, h, "brand_new_write", id, nil)
	if ran || !res.IsError || contentText(res) != reviewerRefusalText("brand_new_write") {
		t.Fatalf("unclassified tool: ran=%v %s", ran, contentText(res))
	}
	other := &auth.Identity{UserID: id.UserID, TelegramID: 990002}
	if res := callHandler(t, h, "brand_new_write", other, nil); !ran || res.IsError {
		t.Fatalf("a non-reviewer was refused an unclassified tool: %s", contentText(res))
	}
}

// Behind the middleware, each refused Telegram write is still refused by its
// own write gate when its handler is called directly, even aimed at the
// allowlisted peer, and the refusal is an error, never a preview.
func TestReviewerWriteGate_RefusedToolsAreErrorsInTheirHandlers(t *testing.T) {
	s, _, id := reviewerServer(t, alicePeer)
	cases := []struct {
		name string
		tool func() (mcplib.Tool, mcpserver.ToolHandlerFunc)
		args map[string]any
	}{
		{"send_media", s.toolSendMedia, map[string]any{"peer": alicePeer, "media_type": "photo", "file_base64": "aGk="}},
		{"edit_message", s.toolEditMessage, map[string]any{"peer": alicePeer, "message_id": float64(1), "text": "hi"}},
		{"delete_messages", s.toolDeleteMessages, map[string]any{"peer": alicePeer, "message_ids": []any{float64(1)}}},
		{"forward_messages", s.toolForwardMessages, map[string]any{"from_peer": alicePeer, "to_peer": alicePeer, "message_ids": []any{float64(1)}}},
		{"set_reaction", s.toolSetReaction, map[string]any{"peer": alicePeer, "message_id": float64(1), "emoji": "+1"}},
		{"pin_message", s.toolPinMessage, map[string]any{"peer": alicePeer, "message_id": float64(1), "confirmation_id": "cp_0000"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, h := c.tool()
			res := callHandler(t, h, c.name, id, c.args)
			if !res.IsError || !strings.Contains(contentText(res), reasonReviewerWriteRefused) {
				t.Fatalf("%s as the reviewer: isError=%v %s", c.name, res.IsError, contentText(res))
			}
			if got := classifyToolResultReason(res); got != ReasonRefused {
				t.Fatalf("reason = %q, want %q", got, ReasonRefused)
			}
		})
	}
}

// send_message really sends for the reviewer only to a listed peer, named in
// the canonical typed form. Anything else is an error, not a preview.
func TestReviewerSendMessage_OnlyToAllowlistedPeer(t *testing.T) {
	refusedPeers := []string{
		"user:7002",  // not listed
		"@alice",     // the listed chat, by name: not comparable with an id
		"7001",       // a bare id
		"chat:7001",  // the listed number as another kind of peer
		"user:-7001", // not a valid id
		"user:7001x", // malformed
	}
	for _, peer := range refusedPeers {
		s, _, id := reviewerServer(t, alicePeer)
		_, h := s.toolSendMessage()
		res := callHandler(t, h, "send_message", id, map[string]any{"peer": peer, "text": "hi"})
		if !res.IsError || contentText(res) != reviewerRefusalText("send_message") {
			t.Errorf("send_message to %q: isError=%v %s", peer, res.IsError, contentText(res))
		}
	}

	// An empty allowlist lets the reviewer write nowhere.
	s, _, id := reviewerServer(t)
	_, h := s.toolSendMessage()
	if res := callHandler(t, h, "send_message", id, map[string]any{"peer": alicePeer, "text": "hi"}); !res.IsError || contentText(res) != reviewerRefusalText("send_message") {
		t.Fatalf("send_message with an empty allowlist: %s", contentText(res))
	}

	// The listed peer clears the reviewer rule; the rest of the gate still
	// applies (ALLOW_SEND=false makes it a preview like anyone's), and the
	// equivalent spelling user:+7001 is the same peer.
	for _, peer := range []string{alicePeer, " user:+7001 "} {
		s, _, id = reviewerServer(t, alicePeer)
		s.AllowSend = false
		_, h = s.toolSendMessage()
		res := callHandler(t, h, "send_message", id, map[string]any{"peer": peer, "text": "hi"})
		if res.IsError || !strings.Contains(contentText(res), "ALLOW_SEND=false") {
			t.Fatalf("send_message to allowlisted %q: isError=%v %s", peer, res.IsError, contentText(res))
		}
	}

	// prepare_send_message reports the same verdict: open for the listed peer
	// with the gate open, closed with the reviewer reason for another.
	s, _, id = reviewerServer(t, alicePeer)
	for peer, want := range map[string]bool{alicePeer: true, "user:7002": false} {
		out := parsePrepareSendResult(t, callPrepareSend(t, s, id, map[string]any{"peer": peer, "text": "hi"}))
		if out["will_really_send"] != want {
			t.Errorf("prepare_send_message to %s: will_really_send=%v, want %v (%v)", peer, out["will_really_send"], want, out["dry_reason"])
		}
	}
}

// send_reply delivers for the reviewer only when the drafted recipient is
// listed. The recipient checked is the one the draft holds, and a refusal
// keeps the draft, like every other gate refusal.
func TestReviewerSendReply_OnlyToAllowlistedPeer(t *testing.T) {
	s, f, id := reviewerServer(t, alicePeer)
	id.Profile = toolprofile.CoreReply

	bob := draftOK(t, s, id, "@bob", "hi bob")
	if bob.SendGateOpen || bob.SendGateReason != reasonReviewerWriteRefused {
		t.Fatalf("draft to Bob: open=%v %q", bob.SendGateOpen, bob.SendGateReason)
	}
	res := sendReply(t, s, id, map[string]any{"confirmation_id": bob.ConfirmationID})
	if !res.IsError || !strings.Contains(contentText(res), "send_reply blocked: "+reasonReviewerWriteRefused) {
		t.Fatalf("send_reply to Bob: %s", contentText(res))
	}
	if len(f.delivered) != 0 {
		t.Fatalf("delivered %d messages to an unlisted peer", len(f.delivered))
	}
	if _, err := s.Replies.Peek(bob.ConfirmationID, id.UserID, id.Profile); err != nil {
		t.Fatalf("the refusal spent the draft: %v", err)
	}

	alice := draftOK(t, s, id, "@alice", "hi alice")
	if !alice.SendGateOpen {
		t.Fatalf("draft to Alice: gate closed: %q", alice.SendGateReason)
	}
	if res := sendReply(t, s, id, map[string]any{"confirmation_id": alice.ConfirmationID}); res.IsError {
		t.Fatalf("send_reply to Alice: %s", contentText(res))
	}
	if len(f.delivered) != 1 || f.delivered[0].target.Ref != alicePeer || f.delivered[0].text != "hi alice" {
		t.Fatalf("delivered %+v, want one message to Alice", f.delivered)
	}

	// An empty allowlist refuses even Alice.
	s2, f2, id2 := reviewerServer(t)
	id2.Profile = toolprofile.CoreReply
	d := draftOK(t, s2, id2, "@alice", "hi")
	if res := sendReply(t, s2, id2, map[string]any{"confirmation_id": d.ConfirmationID}); !res.IsError || len(f2.delivered) != 0 {
		t.Fatalf("send_reply with an empty allowlist: %s, delivered %d", contentText(res), len(f2.delivered))
	}
}
