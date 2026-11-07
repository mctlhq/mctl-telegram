package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/bridge"
)

// A folder read without a folder must be refused before Telegram is
// reached, never run as an unscoped read of every chat (#1155). The nil pool
// proves no read was attempted: borrowing from it would panic.
func TestDispatch_UnreadInFolderNeedsAFolder(t *testing.T) {
	for _, args := range []string{`{}`, `{"folder":0}`, `{"folder":-3,"limit":5}`} {
		env := bridge.EncodeCall("1", "get_unread_messages_in_folder", json.RawMessage(args))
		got := dispatchCall(context.Background(), &localConfig{}, nil, 1, env)
		if got.Error == "" || !strings.Contains(got.Error, "folder is required") {
			t.Errorf("%s: want a folder-required refusal, got error=%q result=%s", args, got.Error, got.Result)
		}
	}
	env := bridge.EncodeCall("2", "get_unread_messages_in_folder", json.RawMessage(`{"folder":"Work"}`))
	if got := dispatchCall(context.Background(), &localConfig{}, nil, 1, env); !strings.Contains(got.Error, "bad args") {
		t.Errorf("non-numeric folder: got error=%q", got.Error)
	}
}
