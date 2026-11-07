package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// TestToolDialogScope_CoversRegistry: every registered tool is classified as
// reading or writing dialogs or exempt from the hidden-chat scope. A new tool
// fails here until someone decides; until then the guard lets it through, so
// this test is the gate.
func TestToolDialogScope_CoversRegistry(t *testing.T) {
	for name := range fullSurfaceServer(&Server{}).ListTools() {
		if _, ok := toolDialogScope[name]; !ok {
			t.Errorf("%s is registered but has no toolDialogScope entry (internal/mcp/hidden.go)", name)
		}
	}
	for _, name := range []string{"list_dialogs", "get_messages", "get_unread_messages", "search_messages", "send_message", "send_reply", "forward_messages", "get_media"} {
		if toolDialogScope[name] != scopeDialogs {
			t.Errorf("%s must be scoped to visible chats", name)
		}
	}
}

type fakeHiddenStore struct {
	rows    []db.HiddenDialog
	err     error
	mode    string
	modeErr error
}

func (f *fakeHiddenStore) ListHiddenDialogs(context.Context, int64) ([]db.HiddenDialog, error) {
	return f.rows, f.err
}

func (f *fakeHiddenStore) GetAccountMode(context.Context, int64) (string, error) {
	if f.mode == "" {
		return "hosted", f.modeErr
	}
	return f.mode, f.modeErr
}

// runGuard runs one call through the guard with next recording whether it
// ran and with which hidden set.
func runGuard(t *testing.T, store hiddenStore, tool string, args map[string]any, out string) (res *mcplib.CallToolResult, ran bool, seen telegram.HiddenPeers) {
	t.Helper()
	next := func(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		ran, seen = true, telegram.HiddenPeersFrom(ctx)
		return mcplib.NewToolResultText(out), nil
	}
	id := &auth.Identity{UserID: 1}
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: tool, Arguments: args}}
	res, err := (&Server{}).runHiddenScoped(auth.With(context.Background(), id), store, id, tool, req, next)
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	return res, ran, seen
}

func TestHiddenGuard_RefusesNamedHiddenChat(t *testing.T) {
	store := &fakeHiddenStore{rows: []db.HiddenDialog{{Peer: "user:42"}, {Peer: "channel:9"}}}
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"get_messages", map[string]any{"peer": "user:42"}},
		{"get_messages", map[string]any{"peer": "42"}},
		{"get_messages", map[string]any{"peer": " channel:009 "}},
		{"send_message", map[string]any{"peer": "channel:9", "text": "hi"}},
		{"forward_messages", map[string]any{"from_peer": "user:5", "to_peer": "user:42"}},
		{"forward_messages", map[string]any{"from_peer": "channel:9", "to_peer": "user:5"}},
	} {
		res, ran, _ := runGuard(t, store, tc.tool, tc.args, `{}`)
		if ran || !res.IsError || !strings.Contains(firstResultText(res), " blocked: "+telegram.ErrPeerHidden.Error()) {
			t.Errorf("%s %v: ran=%v res=%q", tc.tool, tc.args, ran, firstResultText(res))
		}
	}
	// A visible chat runs, with the set on ctx for resolution (layer 2).
	res, ran, seen := runGuard(t, store, "get_messages", map[string]any{"peer": "@bob"}, `{"messages":[]}`)
	if !ran || res.IsError || !seen["user:42"] {
		t.Errorf("visible call: ran=%v err=%v set=%v", ran, res.IsError, seen)
	}
}

// A store error fails closed: the call does not run without the set.
func TestHiddenGuard_UnreadableSetFailsClosed(t *testing.T) {
	res, ran, _ := runGuard(t, &fakeHiddenStore{err: errors.New("db down")}, "list_dialogs", nil, `{}`)
	if ran || !res.IsError || !strings.Contains(firstResultText(res), "blocked: could not read") {
		t.Fatalf("ran=%v res=%q", ran, firstResultText(res))
	}
	store := &fakeHiddenStore{rows: []db.HiddenDialog{{Peer: "user:42"}}, modeErr: errors.New("db down")}
	if res, ran, _ := runGuard(t, store, "get_messages", map[string]any{"peer": "@bob"}, `{}`); ran || !res.IsError {
		t.Fatalf("unreadable account mode: ran=%v", ran)
	}
}

// A Local Bridge account resolves usernames on the daemon, out of the
// server's sight, so a username is refused while anything is hidden.
func TestHiddenGuard_LocalBridgeNeedsID(t *testing.T) {
	store := &fakeHiddenStore{rows: []db.HiddenDialog{{Peer: "user:42"}}, mode: "local"}
	res, ran, _ := runGuard(t, store, "get_messages", map[string]any{"peer": "@bob"}, `{}`)
	if ran || !res.IsError || !strings.Contains(firstResultText(res), "must name the chat by id") {
		t.Fatalf("ran=%v res=%q", ran, firstResultText(res))
	}
	if _, ran, _ := runGuard(t, store, "get_messages", map[string]any{"peer": "user:43"}, `{}`); !ran {
		t.Error("an id form was refused on a local account")
	}
	if _, ran, _ := runGuard(t, &fakeHiddenStore{mode: "local"}, "get_messages", map[string]any{"peer": "@bob"}, `{}`); !ran {
		t.Error("a username was refused on a local account that hides nothing")
	}
}

// Listings that bypass the telegram layer (Local Bridge) are filtered on the
// way out, in both the text and the structured content.
func TestHiddenGuard_FiltersResult(t *testing.T) {
	store := &fakeHiddenStore{rows: []db.HiddenDialog{{Peer: "chat:7"}, {Peer: "channel:8"}}}
	out := `{"dialogs":[{"id":"chat:7","title":"Hidden"},{"id":"user:1","title":"Alice"}],` +
		`"messages":[{"peer":"chat:7","text":"x"},{"peer":"user:1","text":"y"}],` +
		`"sponsored":[{"channel":"channel:8"}],"note":"kept"}`
	res, _, _ := runGuard(t, store, "list_dialogs", nil, out)
	text := firstResultText(res)
	if strings.Contains(text, "chat:7") || strings.Contains(text, "channel:8") || strings.Contains(text, "Hidden") {
		t.Errorf("hidden chat left in result: %s", text)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(text), &body); err != nil || body["note"] != "kept" || len(body["dialogs"].([]any)) != 1 {
		t.Errorf("result reshaped: %s (%v)", text, err)
	}
	sc, _ := res.StructuredContent.(map[string]any)
	if sc == nil || len(sc["messages"].([]any)) != 1 {
		t.Errorf("structured content not filtered: %v", res.StructuredContent)
	}

	// Nothing hidden: the result is untouched byte for byte.
	res, _, _ = runGuard(t, &fakeHiddenStore{}, "list_dialogs", nil, out)
	if firstResultText(res) != out {
		t.Error("a result was rewritten although nothing is hidden")
	}
}

func TestHiddenGuard_ExemptToolsSkipped(t *testing.T) {
	s := &Server{Store: newToolsTestStore(t)}
	ran := false
	next := func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		ran = true
		return mcplib.NewToolResultText("ok"), nil
	}
	// Exempt tools never read the set, so a dropped table cannot block them.
	if _, err := s.Store.DB.Exec(`DROP TABLE hidden_dialogs`); err != nil {
		t.Fatal(err)
	}
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: "get_my_identity"}}
	if _, err := s.hiddenScopeGuard(next)(auth.With(context.Background(), &auth.Identity{UserID: 1}), req); err != nil || !ran {
		t.Fatalf("exempt tool: ran=%v err=%v", ran, err)
	}
	ran = false
	req.Params.Name = "list_dialogs"
	res, _ := s.hiddenScopeGuard(next)(auth.With(context.Background(), &auth.Identity{UserID: 1}), req)
	if ran || !res.IsError {
		t.Fatal("a dialog tool ran with an unreadable set")
	}
}

// A reply drafted before the owner hid the chat is not delivered, and the
// draft is not spent: once shown again it goes out.
func TestSendReply_HiddenAfterDraftIsRefused(t *testing.T) {
	s, f, id := replyServer(t, 9351)
	out := draftOK(t, s, id, "@alice", "see you at 6")
	if err := s.Store.HideDialog(context.Background(), id.UserID, "user:7001", "Alice"); err != nil {
		t.Fatal(err)
	}
	_, h := s.toolSendReply()
	guarded := s.hiddenScopeGuard(h)
	res := callReplyTool(t, guarded, "send_reply", id, map[string]any{"confirmation_id": out.ConfirmationID})
	if !res.IsError || !strings.Contains(contentText(res), telegram.ErrPeerHidden.Error()) || len(f.delivered) != 0 {
		t.Fatalf("send to a hidden chat: %q, %d deliveries", contentText(res), len(f.delivered))
	}
	if _, err := s.Store.UnhideDialog(context.Background(), id.UserID, "user:7001"); err != nil {
		t.Fatal(err)
	}
	res = callReplyTool(t, guarded, "send_reply", id, map[string]any{"confirmation_id": out.ConfirmationID})
	if res.IsError || len(f.delivered) != 1 {
		t.Fatalf("send after show again: %q, %d deliveries", contentText(res), len(f.delivered))
	}
}
