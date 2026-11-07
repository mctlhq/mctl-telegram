package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
)

func TestFolderArg_RejectsAnythingButAnID(t *testing.T) {
	if _, in, err := folderArg(map[string]any{}); in || err != nil {
		t.Errorf("absent folder: in=%v err=%v, want no folder and no error", in, err)
	}
	if id, in, err := folderArg(map[string]any{"folder": float64(3)}); !in || id != 3 || err != nil {
		t.Errorf("folder 3: id=%d in=%v err=%v", id, in, err)
	}
	for _, bad := range []any{"Work", float64(0), float64(-2), float64(2.5), true} {
		if _, in, err := folderArg(map[string]any{"folder": bad}); err == nil || in {
			t.Errorf("folder %v accepted (in=%v); a bad value must not widen the listing", bad, in)
		}
	}
}

// TestListDialogs_FolderGoesToTheBridgeUnderItsOwnName pins the Local Bridge
// fail-closed path: a folder listing travels as list_dialogs_in_folder, so a
// daemon without folder support answers "unknown tool" instead of ignoring
// the argument and returning every dialog.
func TestListDialogs_FolderGoesToTheBridgeUnderItsOwnName(t *testing.T) {
	cases := []struct {
		name, tool string
		args       map[string]any
		want       string
	}{
		{"plain listing", "list_dialogs", map[string]any{"limit": float64(5)}, "list_dialogs"},
		{"folder listing", "list_dialogs", map[string]any{"folder": float64(3)}, "list_dialogs_in_folder"},
		{"folder list", "list_folders", map[string]any{}, "list_folders"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := newToolsTestStore(t)
			uid := seedLocalAccount(t, store, int64(4501+i))
			hub := bridge.NewHub()
			send := hub.Register(uid, "")
			got := make(chan string, 1)
			go func() {
				env := <-send
				got <- env.Tool
				if env.Tool == "list_dialogs_in_folder" {
					// What an old daemon answers.
					hub.Deliver(uid, bridge.EncodeError(env.ID, `unknown tool: "list_dialogs_in_folder"`))
					return
				}
				hub.Deliver(uid, bridge.EncodeResponse(env.ID, json.RawMessage(`{"dialogs":[],"folders":[]}`)))
			}()
			srv := (&Server{Store: store, Hub: hub}).newMCPServer()
			id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:dialogs:read"}}
			res := callTool(t, auth.With(context.Background(), id), srv, c.tool, c.args)
			if tool := <-got; tool != c.want {
				t.Fatalf("bridge tool = %q, want %q", tool, c.want)
			}
			if c.want == "list_dialogs_in_folder" {
				if !res.IsError || !strings.Contains(contentText(res), "unknown tool") {
					t.Errorf("old daemon answer not surfaced as an error: %s", contentText(res))
				}
			} else if res.IsError {
				t.Errorf("unexpected error: %s", contentText(res))
			}
		})
	}
}

func TestListDialogs_BadFolderIsRefusedBeforeAnyRead(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedLocalAccount(t, store, 4504)
	hub := bridge.NewHub()
	send := hub.Register(uid, "")
	srv := (&Server{Store: store, Hub: hub}).newMCPServer()
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:dialogs:read"}}
	res := callTool(t, auth.With(context.Background(), id), srv, "list_dialogs", map[string]any{"folder": "Work"})
	if !res.IsError || !strings.Contains(contentText(res), "list_folders") {
		t.Fatalf("bad folder not refused: %s", contentText(res))
	}
	select {
	case env := <-send:
		t.Fatalf("bad folder still reached the daemon as %q", env.Tool)
	default:
	}
}
