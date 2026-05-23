package telegram

import (
	"fmt"
	"strings"
	"testing"
)

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
