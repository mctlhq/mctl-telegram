package telegram

import (
	"strings"
	"testing"

	"github.com/gotd/td/tg"
)

func TestMessageBelongsToPeer(t *testing.T) {
	userMsg := &tg.Message{ID: 1, PeerID: &tg.PeerUser{UserID: 42}}
	chatMsg := &tg.Message{ID: 2, PeerID: &tg.PeerChat{ChatID: 7}}

	cases := []struct {
		name  string
		msg   *tg.Message
		input tg.InputPeerClass
		want  bool
	}{
		{"user match", userMsg, &tg.InputPeerUser{UserID: 42}, true},
		{"user mismatch", userMsg, &tg.InputPeerUser{UserID: 99}, false},
		{"chat match", chatMsg, &tg.InputPeerChat{ChatID: 7}, true},
		{"chat mismatch", chatMsg, &tg.InputPeerChat{ChatID: 8}, false},
		{"cross-kind mismatch", userMsg, &tg.InputPeerChat{ChatID: 42}, false},
		// channels.getMessages is already peer-scoped — always passes.
		{"channel always passes", userMsg, &tg.InputPeerChannel{ChannelID: 5}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := messageBelongsToPeer(c.msg, c.input); got != c.want {
				t.Errorf("messageBelongsToPeer = %v, want %v", got, c.want)
			}
		})
	}
}

func TestPeerNeedsAccessHash(t *testing.T) {
	if !peerNeedsAccessHash(&tg.InputPeerChannel{ChannelID: 1}) {
		t.Error("zero-hash channel should need a hash")
	}
	if peerNeedsAccessHash(&tg.InputPeerChannel{ChannelID: 1, AccessHash: 5}) {
		t.Error("hash-bearing channel should not need a hash")
	}
	if peerNeedsAccessHash(&tg.InputPeerChat{ChatID: 1}) {
		t.Error("basic groups never carry a hash")
	}
}

func TestSanitizeFileName(t *testing.T) {
	if got := sanitizeFileName("report.pdf"); got != "report.pdf" {
		t.Errorf("plain name mangled: %q", got)
	}
	if got := sanitizeFileName("evil\x00​name.pdf"); strings.ContainsAny(got, "\x00​") {
		t.Errorf("control/invisible chars survived: %q", got)
	}
	if got := sanitizeFileName("a\nb.txt"); strings.Contains(got, "\n") {
		t.Errorf("newline survived: %q", got)
	}
	if got := sanitizeFileName(strings.Repeat("x", 5000)); len([]rune(got)) > 300 {
		t.Errorf("oversized name not truncated: %d runes", len([]rune(got)))
	}
	if got := sanitizeFileName(""); got != "" {
		t.Errorf("empty name should stay empty, got %q", got)
	}
	if got := sanitizeFileName("​​"); got != "" {
		t.Errorf("all-invisible name should become empty, got %q", got)
	}
}
