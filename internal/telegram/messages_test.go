package telegram

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gotd/td/tg"
)

func TestLimitClamp(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{0, 50},
		{-1, 50},
		{1, 1},
		{50, 50},
		{200, 200},
		{201, 200},
		{500, 200},
	}
	for _, tc := range cases {
		got := clampLimit(tc.in)
		if got != tc.want {
			t.Errorf("clampLimit(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestHistoryCursor(t *testing.T) {
	t.Run("full page returns min raw ID", func(t *testing.T) {
		raw := &tg.MessagesMessages{
			Messages: []tg.MessageClass{
				&tg.Message{ID: 300, Message: "c"},
				&tg.Message{ID: 200, Message: "b"},
				&tg.Message{ID: 100, Message: "a"},
			},
		}
		if got := historyCursor(raw, 3); got != 100 {
			t.Errorf("historyCursor = %d, want 100", got)
		}
	})

	t.Run("short page means end of history", func(t *testing.T) {
		raw := &tg.MessagesMessages{
			Messages: []tg.MessageClass{
				&tg.Message{ID: 300, Message: "c"},
			},
		}
		if got := historyCursor(raw, 3); got != 0 {
			t.Errorf("historyCursor = %d, want 0", got)
		}
	})

	t.Run("service messages count toward page fullness and cursor", func(t *testing.T) {
		// A full raw page whose entries include service messages (joins/pins):
		// decodeMessages drops them, but the cursor must still be emitted and
		// must point below the lowest raw entry, or pagination would stop
		// early / re-fetch the service messages forever.
		raw := &tg.MessagesMessagesSlice{
			Messages: []tg.MessageClass{
				&tg.Message{ID: 300, Message: "c"},
				&tg.MessageService{ID: 200},
				&tg.Message{ID: 100, Message: "a"},
				&tg.MessageService{ID: 50},
			},
		}
		hint := &Dialog{ID: "user:1", Title: "Test"}
		msgs := decodeMessages(raw, hint, nil, nil, 4)
		if len(msgs) != 2 {
			t.Fatalf("expected 2 decoded messages, got %d", len(msgs))
		}
		if got := historyCursor(raw, 4); got != 50 {
			t.Errorf("historyCursor = %d, want 50 (min raw ID incl. service messages)", got)
		}
	})

	t.Run("empty response", func(t *testing.T) {
		if got := historyCursor(&tg.MessagesMessages{}, 3); got != 0 {
			t.Errorf("historyCursor = %d, want 0", got)
		}
	})
}

func TestGetUnreadMessages_PeerNotFoundError(t *testing.T) {
	// The error format when peerSpec is set but not in dialogs.
	peerSpec := "@testpeer"
	err := fmt.Errorf("peer %q not found in recent dialogs — use get_messages for this peer's full history", peerSpec)
	if !strings.Contains(err.Error(), "not found in recent dialogs") {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "get_messages") {
		t.Errorf("error should mention get_messages: %v", err)
	}
}

func TestGetUnreadMessages_ExplicitPeerNotFound_ActionHint(t *testing.T) {
	peerSpec := "@testpeer"
	err := fmt.Errorf("peer %q not found in recent dialogs — use get_messages for this peer's full history", peerSpec)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !strings.Contains(err.Error(), "get_messages") {
		t.Errorf("error %q should mention get_messages as the fallback tool", err.Error())
	}
}

func TestMatchUsername(t *testing.T) {
	cases := []struct {
		have, want string
		match      bool
	}{
		{"alice", "@alice", true},
		{"@alice", "alice", true},
		{"@Alice", "@alice", true},
		{"bob", "@alice", false},
		{"", "@alice", false},
	}
	for _, tc := range cases {
		got := matchUsername(tc.have, tc.want)
		if got != tc.match {
			t.Errorf("matchUsername(%q, %q) = %v, want %v", tc.have, tc.want, got, tc.match)
		}
	}
}
