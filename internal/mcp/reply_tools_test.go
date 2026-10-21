package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gotd/td/tg"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

// replyFake stands in for Telegram in the draft_reply / send_reply tests.
// Peers listed in dialogs exist; anything else has no history.
type replyFake struct {
	dialogs   map[string]*telegram.ReplyTarget
	delivered []delivered
}

type delivered struct {
	userID int64
	target *telegram.ReplyTarget
	text   string
}

func newReplyFake() *replyFake {
	return &replyFake{dialogs: map[string]*telegram.ReplyTarget{
		"@alice": {Peer: &tg.InputPeerUser{UserID: 7001, AccessHash: 11}, Ref: "user:7001", Title: "Alice"},
		"@bob":   {Peer: &tg.InputPeerUser{UserID: 7002, AccessHash: 22}, Ref: "user:7002", Title: "Bob"},
	}}
}

func (f *replyFake) install(s *Server) {
	s.replyResolve = func(_ context.Context, _ int64, peer string) (*telegram.ReplyTarget, error) {
		if t, ok := f.dialogs[peer]; ok {
			return t, nil
		}
		if peer == "@book_club_news" {
			return nil, telegram.ErrCannotPost
		}
		return nil, telegram.ErrNoExistingDialog
	}
	s.replyDeliver = func(_ context.Context, userID int64, target *telegram.ReplyTarget, text string) (*telegram.SendResult, error) {
		f.delivered = append(f.delivered, delivered{userID, target, text})
		return &telegram.SendResult{Sent: true, Mode: "send", PeerInput: target.Ref, Text: text, MessageID: 42}, nil
	}
}

// replyServer is a server with the gate fully open for the returned identity:
// ALLOW_SEND, the send scope, and send_enabled on a hosted account.
func replyServer(t *testing.T, tgID int64) (*Server, *replyFake, *auth.Identity) {
	t.Helper()
	store := newToolsTestStore(t)
	uid := seedHostedAccount(t, store, tgID, true)
	s := &Server{Store: store, AllowSend: true, Replies: NewReplyStore()}
	f := newReplyFake()
	f.install(s)
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:read", "telegram:dialogs:read", "telegram:messages:send"}, Profile: toolprofile.CoreReply}
	return s, f, id
}

func callReplyTool(t *testing.T, h func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error), name string, id *auth.Identity, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	res, err := h(auth.With(context.Background(), id), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: args}})
	if err != nil {
		t.Fatalf("%s: unexpected Go error: %v", name, err)
	}
	return res
}

func draft(t *testing.T, s *Server, id *auth.Identity, peer, text string) *mcplib.CallToolResult {
	t.Helper()
	_, h := s.toolDraftReply()
	return callReplyTool(t, h, "draft_reply", id, map[string]any{"peer": peer, "text": text})
}

func sendReply(t *testing.T, s *Server, id *auth.Identity, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	_, h := s.toolSendReply()
	return callReplyTool(t, h, "send_reply", id, args)
}

func draftOK(t *testing.T, s *Server, id *auth.Identity, peer, text string) draftReplyResult {
	t.Helper()
	res := draft(t, s, id, peer, text)
	if res.IsError {
		t.Fatalf("draft_reply refused: %s", contentText(res))
	}
	var out draftReplyResult
	if err := json.Unmarshal([]byte(contentText(res)), &out); err != nil {
		t.Fatalf("draft_reply result: %v (%s)", err, contentText(res))
	}
	return out
}

func TestDraftReply_ReturnsRecipientTextAndConfirmation(t *testing.T) {
	s, f, id := replyServer(t, 9301)
	out := draftOK(t, s, id, "@alice", "See you at 5")
	if out.Recipient != "user:7001" || out.RecipientTitle != "Alice" || out.Text != "See you at 5" {
		t.Fatalf("draft = %+v", out)
	}
	if !strings.HasPrefix(out.ConfirmationID, "cr_") {
		t.Fatalf("confirmation_id = %q", out.ConfirmationID)
	}
	if !out.SendGateOpen || out.SendGateReason != "" {
		t.Fatalf("gate open, but draft reports %v %q", out.SendGateOpen, out.SendGateReason)
	}
	if len(f.delivered) != 0 {
		t.Fatalf("draft_reply delivered %d messages", len(f.delivered))
	}
}

// A peer with no history, such as a bare @username never talked to, is
// refused and leaves no confirmation behind (owner decision 2026-10-21).
func TestDraftReply_RefusesPeerWithoutConversation(t *testing.T) {
	s, _, id := replyServer(t, 9302)
	res := draft(t, s, id, "@carol", "hello")
	if !res.IsError || !strings.Contains(contentText(res), "not an existing conversation") {
		t.Fatalf("draft to a stranger: %s", contentText(res))
	}
	if got := classifyToolResultReason(res); got != ReasonRefused {
		t.Fatalf("reason = %q, want %q", got, ReasonRefused)
	}
	if n := len(s.Replies.m); n != 0 {
		t.Fatalf("%d confirmations issued for a refused draft", n)
	}
}

// A conversation the account is in but may not post to, such as a broadcast
// channel it only subscribes to, is refused at draft time: otherwise the
// one-shot confirmation would be spent on a Telegram refusal at send time.
func TestDraftReply_RefusesConversationItCannotPostIn(t *testing.T) {
	s, f, id := replyServer(t, 9314)
	res := draft(t, s, id, "@book_club_news", "hello")
	if !res.IsError || !strings.Contains(contentText(res), "may not post") {
		t.Fatalf("draft to a read-only channel: %s", contentText(res))
	}
	if got := classifyToolResultReason(res); got != ReasonRefused {
		t.Fatalf("reason = %q, want %q", got, ReasonRefused)
	}
	if n := len(s.Replies.m); n != 0 || len(f.delivered) != 0 {
		t.Fatalf("refused draft left %d confirmations, %d deliveries", n, len(f.delivered))
	}
}

func TestDraftReply_RejectsBadText(t *testing.T) {
	s, _, id := replyServer(t, 9303)
	for name, text := range map[string]string{
		"blank":    "   ",
		"too long": strings.Repeat("я", maxReplyText+1),
		// 2049 emoji are 2049 runes but 4098 UTF-16 units, which is how
		// Telegram counts; a rune count would let this through to fail at
		// delivery, after the confirmation was spent.
		"too many emoji": strings.Repeat("😀", maxReplyText/2+1),
	} {
		if res := draft(t, s, id, "@alice", text); !res.IsError {
			t.Errorf("%s text accepted", name)
		} else if got := classifyToolResultReason(res); got != ReasonInvalidArgument {
			t.Errorf("%s text: reason %q, want %q", name, got, ReasonInvalidArgument)
		}
	}
	if res := draft(t, s, id, "@alice", strings.Repeat("я", maxReplyText)); res.IsError {
		t.Fatalf("text of exactly %d units refused: %s", maxReplyText, contentText(res))
	}
	if res := draft(t, s, id, "@alice", strings.Repeat("😀", maxReplyText/2)); res.IsError {
		t.Fatalf("%d emoji (%d units) refused: %s", maxReplyText/2, maxReplyText, contentText(res))
	}
}

// send_reply delivers what was drafted, to whom it was drafted. Any peer or
// text passed at send time is ignored: the tool has no such arguments.
func TestSendReply_DeliversExactlyTheDraft(t *testing.T) {
	s, f, id := replyServer(t, 9304)
	d := draftOK(t, s, id, "@alice", "See you at 5")
	res := sendReply(t, s, id, map[string]any{"confirmation_id": d.ConfirmationID, "peer": "@bob", "text": "changed"})
	if res.IsError {
		t.Fatalf("send_reply: %s", contentText(res))
	}
	if len(f.delivered) != 1 {
		t.Fatalf("delivered %d messages, want 1", len(f.delivered))
	}
	got := f.delivered[0]
	if got.target.Ref != "user:7001" || got.text != "See you at 5" || got.userID != id.UserID {
		t.Fatalf("delivered %+v to %s", got, got.target.Ref)
	}
	if p, ok := got.target.Peer.(*tg.InputPeerUser); !ok || p.AccessHash != 11 {
		t.Fatalf("delivered to %#v, want the InputPeer resolved at draft time", got.target.Peer)
	}
}

// send_reply has no dry run, so its result carries no preview fields.
func TestSendReply_ResultHasNoPreviewFields(t *testing.T) {
	s, _, id := replyServer(t, 9312)
	d := draftOK(t, s, id, "@alice", "hi")
	res := sendReply(t, s, id, map[string]any{"confirmation_id": d.ConfirmationID})
	var out map[string]any
	if err := json.Unmarshal([]byte(contentText(res)), &out); err != nil {
		t.Fatalf("result: %v (%s)", err, contentText(res))
	}
	if out["sent"] != true || out["recipient"] != "user:7001" || out["text"] != "hi" || out["message_id"] != float64(42) {
		t.Fatalf("result = %v", out)
	}
	for _, k := range []string{"mode", "dry_reason", "notice", "hint", "truncated"} {
		if _, ok := out[k]; ok {
			t.Errorf("send_reply result carries preview field %q", k)
		}
	}
	tool, _ := s.toolSendReply()
	raw, _ := json.Marshal(tool.OutputSchema)
	if strings.Contains(string(raw), "dry_reason") {
		t.Fatalf("send_reply output schema advertises dry_reason: %s", raw)
	}
}

// The per-peer rate limit can be waited out, so like the gate it must not
// spend the draft.
func TestSendReply_RateLimitKeepsTheDraft(t *testing.T) {
	s, f, id := replyServer(t, 9313)
	s.Limiter = audit.NewRateLimiter(1000)
	d := draftOK(t, s, id, "@alice", "hi")
	if !s.Limiter.AllowPeerN(id, telegram.RedactPeer("user:7001"), audit.PeerSendCap, audit.PeerSendCap, audit.PeerWindow) {
		t.Fatal("could not exhaust the per-peer bucket")
	}
	res := sendReply(t, s, id, map[string]any{"confirmation_id": d.ConfirmationID})
	if !res.IsError || classifyToolResultReason(res) != ReasonRateLimited {
		t.Fatalf("rate-limited send: %s", contentText(res))
	}
	if len(f.delivered) != 0 {
		t.Fatalf("delivered %d messages past the limit", len(f.delivered))
	}
	if _, err := s.Replies.Peek(d.ConfirmationID, id.UserID, id.Profile); err != nil {
		t.Fatalf("rate limit spent the draft: %v", err)
	}
}

func TestSendReply_IsSingleShot(t *testing.T) {
	s, f, id := replyServer(t, 9305)
	d := draftOK(t, s, id, "@alice", "once")
	if res := sendReply(t, s, id, map[string]any{"confirmation_id": d.ConfirmationID}); res.IsError {
		t.Fatalf("first send: %s", contentText(res))
	}
	res := sendReply(t, s, id, map[string]any{"confirmation_id": d.ConfirmationID})
	if !res.IsError || !strings.Contains(contentText(res), "call draft_reply again") {
		t.Fatalf("second send: %s", contentText(res))
	}
	if got := classifyToolResultReason(res); got != ReasonNotFound {
		t.Fatalf("reason = %q, want %q", got, ReasonNotFound)
	}
	if len(f.delivered) != 1 {
		t.Fatalf("delivered %d messages, want 1", len(f.delivered))
	}
}

// A confirmation belongs to the identity and the profile that drafted it.
// Another user, the same user under another profile, an expired draft and an
// unknown id all get the same answer and send nothing.
func TestSendReply_RefusesForeignOrStaleConfirmation(t *testing.T) {
	cases := map[string]func(s *Server, id *auth.Identity) *auth.Identity{
		"other user": func(s *Server, id *auth.Identity) *auth.Identity {
			other := *id
			other.UserID = seedHostedAccount(t, s.Store, 9399, true)
			return &other
		},
		"other profile": func(_ *Server, id *auth.Identity) *auth.Identity {
			other := *id
			other.Profile = "core-reply-v0"
			return &other
		},
		"expired": func(s *Server, id *auth.Identity) *auth.Identity {
			s.Replies.now = func() time.Time { return time.Now().Add(ConfirmationTTL + time.Second) }
			return id
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, f, id := replyServer(t, 9306)
			d := draftOK(t, s, id, "@alice", "hi")
			caller := mutate(s, id)
			res := sendReply(t, s, caller, map[string]any{"confirmation_id": d.ConfirmationID})
			if !res.IsError || contentText(res) != errReplyDraftNotFound.Error() {
				t.Fatalf("send_reply: %s", contentText(res))
			}
			if len(f.delivered) != 0 {
				t.Fatalf("delivered %d messages", len(f.delivered))
			}
			if name == "expired" {
				return
			}
			// Someone else's attempt must not spend the owner's draft.
			if res := sendReply(t, s, id, map[string]any{"confirmation_id": d.ConfirmationID}); res.IsError {
				t.Fatalf("owner after a foreign attempt: %s", contentText(res))
			}
		})
	}
	t.Run("unknown id", func(t *testing.T) {
		s, f, id := replyServer(t, 9307)
		res := sendReply(t, s, id, map[string]any{"confirmation_id": "cr_0000"})
		if !res.IsError || len(f.delivered) != 0 {
			t.Fatalf("unknown id: %s, delivered %d", contentText(res), len(f.delivered))
		}
	})
}

// A closed gate is an error that names the condition, never a preview, and it
// leaves the draft usable: turning sends on and retrying delivers it.
func TestSendReply_ClosedGateIsAnErrorAndKeepsTheDraft(t *testing.T) {
	s, f, id := replyServer(t, 9308)
	d := draftOK(t, s, id, "@alice", "hi")
	s.AllowSend = false
	res := sendReply(t, s, id, map[string]any{"confirmation_id": d.ConfirmationID})
	if !res.IsError || !strings.Contains(contentText(res), "send_reply blocked: server flag ALLOW_SEND=false") {
		t.Fatalf("closed gate: %s", contentText(res))
	}
	if strings.Contains(contentText(res), `"sent"`) {
		t.Fatalf("closed gate returned a preview: %s", contentText(res))
	}
	if got := classifyToolResultReason(res); got != ReasonRefused {
		t.Fatalf("reason = %q, want %q", got, ReasonRefused)
	}
	if len(f.delivered) != 0 {
		t.Fatalf("delivered %d messages through a closed gate", len(f.delivered))
	}
	s.AllowSend = true
	if res := sendReply(t, s, id, map[string]any{"confirmation_id": d.ConfirmationID}); res.IsError {
		t.Fatalf("after opening the gate: %s", contentText(res))
	}
	if len(f.delivered) != 1 {
		t.Fatalf("delivered %d messages, want 1", len(f.delivered))
	}
}

// The per-account flag is part of the gate, and the draft says so up front.
func TestDraftReply_ReportsClosedGate(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedHostedAccount(t, store, 9309, false)
	s := &Server{Store: store, AllowSend: true, Replies: NewReplyStore()}
	f := newReplyFake()
	f.install(s)
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}, Profile: toolprofile.CoreReply}
	d := draftOK(t, s, id, "@alice", "hi")
	if d.SendGateOpen || !strings.Contains(d.SendGateReason, "send_enabled=false") {
		t.Fatalf("draft gate = %v %q", d.SendGateOpen, d.SendGateReason)
	}
	res := sendReply(t, s, id, map[string]any{"confirmation_id": d.ConfirmationID})
	if !res.IsError || !strings.Contains(contentText(res), "send_reply blocked: ") || len(f.delivered) != 0 {
		t.Fatalf("send with send_enabled=false: %s, delivered %d", contentText(res), len(f.delivered))
	}
}

func TestReplyTools_RefuseLocalBridgeAccounts(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedLocalAccount(t, store, 9310)
	// The refusal must not depend on the bridge being wired up: a deployment
	// with the bridge disabled can still hold an account left in local mode,
	// and its MTProto session is not on this server.
	for name, hub := range map[string]*bridge.Hub{"bridge enabled": bridge.NewHub(), "bridge disabled": nil} {
		s := &Server{Store: store, Hub: hub, AllowSend: true, Replies: NewReplyStore()}
		f := newReplyFake()
		f.install(s)
		id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}, Profile: toolprofile.CoreReply}
		for _, res := range []*mcplib.CallToolResult{
			draft(t, s, id, "@alice", "hi"),
			sendReply(t, s, id, map[string]any{"confirmation_id": "cr_0000"}),
		} {
			if !res.IsError || classifyToolResultReason(res) != ReasonModeUnsupported {
				t.Fatalf("%s: local-bridge account: %s", name, contentText(res))
			}
		}
		if len(f.delivered) != 0 || len(s.Replies.m) != 0 {
			t.Fatalf("%s: a local-bridge account drafted or delivered", name)
		}
	}
}

func TestSendReply_DeliveryErrorIsReported(t *testing.T) {
	s, _, id := replyServer(t, 9311)
	d := draftOK(t, s, id, "@alice", "hi")
	s.replyDeliver = func(context.Context, int64, *telegram.ReplyTarget, string) (*telegram.SendResult, error) {
		return nil, errors.New("boom")
	}
	if res := sendReply(t, s, id, map[string]any{"confirmation_id": d.ConfirmationID}); !res.IsError {
		t.Fatalf("delivery error reported as success: %s", contentText(res))
	}
}

// The two tools exist only under a profile that lists them. An unprofiled
// caller holding every scope does not see them, so adding them changed
// nothing for existing connections; core-readonly does not see them either.
func TestReplyTools_AreProfileOnly(t *testing.T) {
	tools := []mcplib.Tool{first((&Server{}).toolDraftReply()), first((&Server{}).toolSendReply()), first((&Server{}).toolSendMessage())}
	scopes := []string{"telegram:messages:send", "telegram:messages:read", "telegram:dialogs:read"}
	visible := func(profile string) map[string]bool {
		id := &auth.Identity{UserID: 1, Scopes: scopes, Profile: profile}
		out := map[string]bool{}
		for _, tool := range scopeToolFilter(auth.With(context.Background(), id), tools) {
			out[tool.Name] = true
		}
		return out
	}
	if v := visible(""); v["draft_reply"] || v["send_reply"] || !v["send_message"] {
		t.Fatalf("unprofiled caller sees %v", v)
	}
	if v := visible(toolprofile.CoreReadonly); v["draft_reply"] || v["send_reply"] || v["send_message"] {
		t.Fatalf("core-readonly sees %v", v)
	}
	if v := visible(toolprofile.CoreReply); !v["draft_reply"] || !v["send_reply"] || v["send_message"] {
		t.Fatalf("core-reply sees %v", v)
	}
	// The send scope is still required under core-reply: a profile never
	// grants a scope.
	noSend := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:read"}, Profile: toolprofile.CoreReply}
	if toolAllowed(noSend, "draft_reply") || toolAllowed(noSend, "send_reply") {
		t.Fatal("core-reply without the send scope may use the reply tools")
	}
	unprofiled := &auth.Identity{UserID: 1, Scopes: scopes}
	if msg := profileDeniedMessage(unprofiled, "send_reply"); !strings.Contains(msg, "offered only to connections with a tool profile") {
		t.Fatalf("refusal for an unprofiled caller: %q", msg)
	}
}

// The store refuses on its own, not only behind send_reply's Peek: Consume
// is the single-shot step and must hold the binding by itself.
func TestReplyStore_ConsumeHoldsTheBinding(t *testing.T) {
	target := &telegram.ReplyTarget{Peer: &tg.InputPeerUser{UserID: 7001}, Ref: "user:7001"}
	for name, call := range map[string]func(st *ReplyStore, id string) error{
		"other user": func(st *ReplyStore, id string) error { _, err := st.Consume(id, 2, toolprofile.CoreReply); return err },
		"other profile": func(st *ReplyStore, id string) error {
			_, err := st.Consume(id, 1, toolprofile.CoreReadonly)
			return err
		},
		"no profile": func(st *ReplyStore, id string) error { _, err := st.Consume(id, 1, ""); return err },
		"peek other user": func(st *ReplyStore, id string) error {
			_, err := st.Peek(id, 2, toolprofile.CoreReply)
			return err
		},
		"peek other profile": func(st *ReplyStore, id string) error {
			_, err := st.Peek(id, 1, toolprofile.CoreReadonly)
			return err
		},
	} {
		st := NewReplyStore()
		d, err := st.Issue(1, toolprofile.CoreReply, target, "hi")
		if err != nil {
			t.Fatal(err)
		}
		if err := call(st, d.ID); !errors.Is(err, errReplyDraftNotFound) {
			t.Errorf("%s: Consume = %v, want not found", name, err)
		}
		// A mismatched call is a no-op for the owner's draft.
		if got, err := st.Consume(d.ID, 1, toolprofile.CoreReply); err != nil || got.Text != "hi" {
			t.Errorf("%s: owner after a mismatched Consume = %+v, %v", name, got, err)
		}
	}
	// An expired draft is dropped, not kept for a later probe.
	exp := NewReplyStore()
	d0, _ := exp.Issue(1, toolprofile.CoreReply, target, "hi")
	exp.now = func() time.Time { return time.Now().Add(ConfirmationTTL + time.Second) }
	if _, err := exp.Consume(d0.ID, 1, toolprofile.CoreReply); !errors.Is(err, errReplyDraftNotFound) || len(exp.m) != 0 {
		t.Fatalf("expired Consume = %v, %d entries left", err, len(exp.m))
	}
	st := NewReplyStore()
	d, _ := st.Issue(1, toolprofile.CoreReply, target, "hi")
	if got, err := st.Consume(d.ID, 1, toolprofile.CoreReply); err != nil || got.Text != "hi" {
		t.Fatalf("owner Consume = %+v, %v", got, err)
	}
}
