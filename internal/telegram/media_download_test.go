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

func TestExtractMediaLocation_Photo(t *testing.T) {
	msg := &tg.Message{
		ID: 1,
		Media: &tg.MessageMediaPhoto{
			Photo: &tg.Photo{
				ID:            555,
				AccessHash:    777,
				FileReference: []byte("ref"),
				Sizes: []tg.PhotoSizeClass{
					&tg.PhotoSize{Type: "m", W: 100, H: 100},
				},
			},
		},
	}
	loc, err := ExtractMediaLocation(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loc == nil {
		t.Fatal("expected non-nil location for a photo message")
	}
	if loc.IsDocument {
		t.Error("photo location must not be marked as a document")
	}
	if loc.PhotoID != 555 || loc.AccessHash != 777 {
		t.Errorf("loc = %+v, want PhotoID=555 AccessHash=777", loc)
	}
}

func TestExtractMediaLocation_Document(t *testing.T) {
	msg := &tg.Message{
		ID: 2,
		Media: &tg.MessageMediaDocument{
			Document: &tg.Document{
				ID:            42,
				AccessHash:    99,
				FileReference: []byte("docref"),
				MimeType:      "application/pdf",
				Size:          1024,
			},
		},
	}
	loc, err := ExtractMediaLocation(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if loc == nil {
		t.Fatal("expected non-nil location for a document message")
	}
	if !loc.IsDocument {
		t.Error("document location must be marked IsDocument=true")
	}
	if loc.DocID != 42 || loc.AccessHash != 99 {
		t.Errorf("loc = %+v, want DocID=42 AccessHash=99", loc)
	}
}

func TestExtractMediaLocation_Poll(t *testing.T) {
	msg := &tg.Message{
		ID:    3,
		Media: &tg.MessageMediaPoll{},
	}
	loc, err := ExtractMediaLocation(msg)
	if err != nil {
		t.Fatalf("unexpected error for a poll message: %v", err)
	}
	if loc != nil {
		t.Errorf("expected nil location for a poll message, got %+v", loc)
	}
}

func TestExtractMediaLocation_Noforwards(t *testing.T) {
	msg := &tg.Message{
		ID:         4,
		Noforwards: true,
		Media: &tg.MessageMediaDocument{
			Document: &tg.Document{ID: 1, AccessHash: 1},
		},
	}
	loc, err := ExtractMediaLocation(msg)
	if err == nil {
		t.Fatal("expected an error for a Noforwards-flagged message")
	}
	if loc != nil {
		t.Errorf("expected nil location alongside the error, got %+v", loc)
	}
	if !strings.Contains(err.Error(), "protected content") {
		t.Errorf("expected a protected-content error, got %q", err.Error())
	}
}

func TestExtractMediaLocation_NilMessage(t *testing.T) {
	loc, err := ExtractMediaLocation(nil)
	if err != nil || loc != nil {
		t.Errorf("ExtractMediaLocation(nil) = (%v, %v), want (nil, nil)", loc, err)
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

// TestCappedBuffer_Write_UnderCap verifies the ordinary case: writes below
// cap succeed, and consumed tracks exactly the bytes written (no rejection,
// so no downloaderReadAheadBytes margin applies).
func TestCappedBuffer_Write_UnderCap(t *testing.T) {
	w := &cappedBuffer{cap: 100}
	n, err := w.Write(make([]byte, 40))
	if err != nil || n != 40 {
		t.Fatalf("Write(40) = (%d, %v), want (40, nil)", n, err)
	}
	n, err = w.Write(make([]byte, 40))
	if err != nil || n != 40 {
		t.Fatalf("Write(40) = (%d, %v), want (40, nil)", n, err)
	}
	if len(w.buf) != 80 {
		t.Errorf("len(buf) = %d, want 80", len(w.buf))
	}
	if w.consumed != 80 {
		t.Errorf("consumed = %d, want 80", w.consumed)
	}
}

// TestCappedBuffer_Write_OverCap locks in the fix for Codex's P2 ("Count
// discarded download chunks against the budget"): when a block is rejected
// for exceeding cap, that block was already fully fetched over the wire
// before Write was even called, and gotd's stream() pipeline (buffer-1
// channel between its fetch and write loops) may already have the NEXT
// block in flight too. consumed must charge the rejected block's own size
// on top of what's already buffered, plus the downloaderReadAheadBytes
// margin for that possible in-flight next block — not just len(buf).
func TestCappedBuffer_Write_OverCap(t *testing.T) {
	w := &cappedBuffer{cap: 50}
	n, err := w.Write(make([]byte, 40)) // fits: 0+40 <= 50
	if err != nil || n != 40 {
		t.Fatalf("Write(40) = (%d, %v), want (40, nil)", n, err)
	}
	n, err = w.Write(make([]byte, 30)) // rejected: 40+30 > 50
	if err == nil {
		t.Fatal("expected an error for a write that exceeds cap")
	}
	if n != 0 {
		t.Errorf("Write() n = %d, want 0 on rejection", n)
	}
	if len(w.buf) != 40 {
		t.Errorf("len(buf) = %d, want 40 (the rejected block must not be appended)", len(w.buf))
	}
	wantConsumed := int64(40+30) + downloaderReadAheadBytes
	if w.consumed != wantConsumed {
		t.Errorf("consumed = %d, want %d (buffered 40 + rejected 30 + %d read-ahead margin)", w.consumed, wantConsumed, downloaderReadAheadBytes)
	}
}
