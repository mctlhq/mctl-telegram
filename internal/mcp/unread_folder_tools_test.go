package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gotd/td/tg"
	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// issue #1155: get_unread_messages takes a chat folder.

func callUnread(t *testing.T, s *Server, id *auth.Identity, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	_, h := s.toolGetUnreadMessages()
	res, err := h(auth.With(context.Background(), id), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: "get_unread_messages", Arguments: args}})
	if err != nil {
		t.Fatalf("get_unread_messages: unexpected Go error: %v", err)
	}
	return res
}

type unreadFolderFake struct {
	calls    int
	folderID int
	limit    int
	scan     telegram.FolderScan
	err      error
}

func (f *unreadFolderFake) read(_ context.Context, _ int64, folderID, limit int) ([]telegram.Message, []*tg.Message, *telegram.Sponsored, telegram.FolderScan, error) {
	f.calls++
	f.folderID, f.limit = folderID, limit
	if f.err != nil {
		return nil, nil, nil, telegram.FolderScan{}, f.err
	}
	return []telegram.Message{{ID: 3, Peer: "user:8511", Text: "hi"}}, nil, &telegram.Sponsored{}, f.scan, nil
}

func unreadFolderServer(t *testing.T, tgID int64) (*Server, *unreadFolderFake, *auth.Identity) {
	t.Helper()
	store := newToolsTestStore(t)
	uid := seedAccountWithMode(t, store, tgID, "cloud")
	fake := &unreadFolderFake{scan: telegram.FolderScan{Scanned: 240, Complete: false}}
	s := &Server{Store: store, unreadFolder: fake.read}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:read"}}
	return s, fake, id
}

func TestGetUnread_FolderReadsTheFolderAndReportsTheScan(t *testing.T) {
	s, fake, id := unreadFolderServer(t, 452101)
	res := callUnread(t, s, id, map[string]any{"folder": float64(7), "limit": float64(20)})
	if res.IsError || fake.calls != 1 || fake.folderID != 7 || fake.limit != 20 {
		t.Fatalf("isError=%v fake=%+v %s", res.IsError, fake, contentText(res))
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out unreadMessagesResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.FolderScan == nil || out.FolderScan.Scanned != 240 || out.FolderScan.Complete || len(out.Messages) != 1 {
		t.Fatalf("result = %s", raw)
	}
}

func TestGetUnread_FolderRefusals(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		err  error
		want string
		read bool
	}{
		{"not an id", map[string]any{"folder": "Work"}, nil, "list_folders", false},
		{"fraction", map[string]any{"folder": float64(2.5)}, nil, "list_folders", false},
		{"with a peer", map[string]any{"folder": float64(7), "peer": "user:8511"}, nil, "not both", false},
		{"unknown folder", map[string]any{"folder": float64(9)}, fmt.Errorf("%w: 9", telegram.ErrFolderNotFound), "folder 9 not found; call list_folders", true},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, fake, id := unreadFolderServer(t, int64(452110+i))
			fake.err = c.err
			res := callUnread(t, s, id, c.args)
			if !res.IsError || !strings.Contains(contentText(res), c.want) {
				t.Fatalf("want an error naming %q, got %s", c.want, contentText(res))
			}
			if (fake.calls == 1) != c.read {
				t.Errorf("folder read calls = %d, want read=%v", fake.calls, c.read)
			}
		})
	}
}

// Local Bridge: a folder read travels under its own envelope name, so a
// daemon without folder support answers "unknown tool" instead of ignoring
// the argument and returning every chat's unread messages.
func TestGetUnread_FolderGoesToTheBridgeUnderItsOwnName(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		want string
	}{
		{"plain", map[string]any{"limit": float64(5)}, "get_unread_messages"},
		{"folder", map[string]any{"folder": float64(3)}, "get_unread_messages_in_folder"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := newToolsTestStore(t)
			uid := seedLocalAccount(t, store, int64(452120+i))
			hub := bridge.NewHub()
			send := hub.Register(uid, "")
			got := make(chan string, 1)
			go func() {
				env := <-send
				got <- env.Tool
				if env.Tool == "get_unread_messages_in_folder" {
					hub.Deliver(uid, bridge.EncodeError(env.ID, `unknown tool: "get_unread_messages_in_folder"`))
					return
				}
				hub.Deliver(uid, bridge.EncodeResponse(env.ID, json.RawMessage(`{"messages":[]}`)))
			}()
			s := &Server{Store: store, Hub: hub}
			id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:read"}}
			res := callUnread(t, s, id, c.args)
			if tool := <-got; tool != c.want {
				t.Fatalf("bridge tool = %q, want %q", tool, c.want)
			}
			if c.want == "get_unread_messages_in_folder" && (!res.IsError || !strings.Contains(contentText(res), "unknown tool")) {
				t.Errorf("old daemon answer not surfaced as an error: %s", contentText(res))
			}
		})
	}

	// A bad folder or a peer with a folder never reaches the daemon.
	store := newToolsTestStore(t)
	uid := seedLocalAccount(t, store, 452125)
	hub := bridge.NewHub()
	send := hub.Register(uid, "")
	s := &Server{Store: store, Hub: hub}
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:read"}}
	for _, args := range []map[string]any{{"folder": "Work"}, {"folder": float64(3), "peer": "user:8511"}} {
		if res := callUnread(t, s, id, args); !res.IsError {
			t.Errorf("%v accepted: %s", args, contentText(res))
		}
	}
	select {
	case env := <-send:
		t.Fatalf("a refused call still reached the daemon as %q", env.Tool)
	default:
	}
}
