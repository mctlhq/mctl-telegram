package telegram

import "testing"

func TestPeerLimitKey_FoldsSpellingsOfOneTarget(t *testing.T) {
	same := [][]string{
		{"@Alice", "alice", " @alice ", "ALICE"},
		{"user:7001", "7001", "user:07001"},
		{"chat:7002"},
		{"channel:7003"},
	}
	for _, group := range same {
		want := PeerLimitKey(group[0])
		for _, spelling := range group[1:] {
			if got := PeerLimitKey(spelling); got != want {
				t.Errorf("PeerLimitKey(%q) = %q, want %q (same target as %q)", spelling, got, want, group[0])
			}
		}
	}
}

// RedactPeer maps every user:<id> to one tag and every handle of the same
// length to one tag. The limiter used to key on it, so these pairs shared
// one per-peer budget; they must not.
func TestPeerLimitKey_SeparatesTargetsRedactPeerCollapses(t *testing.T) {
	pairs := [][2]string{
		{"user:7001", "user:7002"},
		{"7001", "7002"},
		{"@alice", "@carol"},
		{"chat:7002", "chat:7003"},
		{"channel:7003", "channel:7004"},
		{"user:7002", "chat:7002"},
		{"chat:7002", "channel:7002"},
	}
	for _, p := range pairs {
		if PeerLimitKey(p[0]) == PeerLimitKey(p[1]) {
			t.Errorf("PeerLimitKey(%q) == PeerLimitKey(%q) = %q; distinct targets share a budget", p[0], p[1], PeerLimitKey(p[0]))
		}
	}
	if RedactPeer("@alice") != RedactPeer("@carol") || RedactPeer("user:7001") != RedactPeer("user:7002") {
		t.Fatal("fixture no longer exercises a RedactPeer collision")
	}
}

func TestPeerLimitKey_Empty(t *testing.T) {
	if got := PeerLimitKey("  "); got != "" {
		t.Errorf("PeerLimitKey(blank) = %q, want empty", got)
	}
}
