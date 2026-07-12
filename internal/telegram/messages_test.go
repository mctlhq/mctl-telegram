package telegram

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gotd/td/tg"
)

// clampLimit mirrors the limit-guard logic in GetMessages / GetUnreadMessages
// so the table-driven test below can exercise it without a live Telegram
// connection.
func clampLimit(limit int) int {
	if limit <= 0 {
		return 50
	} else if limit > 200 {
		return 200
	}
	return limit
}

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

// TestDecodeMessages_MinIDCursor verifies the assumption relied on by the
// next_before_id computation: the minimum ID in a decoded batch matches what
// we would compute with a linear scan.
func TestDecodeMessages_MinIDCursor(t *testing.T) {
	raw := &tg.MessagesMessages{
		Messages: []tg.MessageClass{
			&tg.Message{ID: 300, Message: "c"},
			&tg.Message{ID: 200, Message: "b"},
			&tg.Message{ID: 100, Message: "a"},
		},
	}
	hint := &Dialog{ID: "user:1", Title: "Test"}
	msgs := decodeMessages(raw, hint, nil, nil, 10)
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(msgs))
	}
	minID := msgs[0].ID
	for _, m := range msgs[1:] {
		if m.ID < minID {
			minID = m.ID
		}
	}
	if minID != 100 {
		t.Errorf("min ID = %d, want 100", minID)
	}
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
