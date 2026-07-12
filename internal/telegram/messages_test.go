package telegram

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gotd/td/tg"
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

func TestDecodeMediaInfo_Photo(t *testing.T) {
	media := &tg.MessageMediaPhoto{
		Photo: &tg.Photo{
			Sizes: []tg.PhotoSizeClass{
				&tg.PhotoSize{Type: "s", W: 100, H: 100},
				&tg.PhotoSize{Type: "m", W: 320, H: 320},
			},
		},
	}
	info := DecodeMediaInfo(media)
	if info == nil {
		t.Fatal("expected non-nil MediaInfo")
	}
	if info.MediaType != "photo" {
		t.Errorf("MediaType = %q, want %q", info.MediaType, "photo")
	}
	if info.Width != 320 || info.Height != 320 {
		t.Errorf("Width/Height = %d/%d, want 320/320", info.Width, info.Height)
	}
}

func TestDecodeMediaInfo_DocumentFile(t *testing.T) {
	media := &tg.MessageMediaDocument{
		Document: &tg.Document{
			MimeType: "application/pdf",
			Size:     1024,
			Attributes: []tg.DocumentAttributeClass{
				&tg.DocumentAttributeFilename{FileName: "report.pdf"},
			},
		},
	}
	info := DecodeMediaInfo(media)
	if info == nil {
		t.Fatal("expected non-nil MediaInfo")
	}
	if info.MediaType != "document" {
		t.Errorf("MediaType = %q, want %q", info.MediaType, "document")
	}
	if info.FileName != "report.pdf" {
		t.Errorf("FileName = %q, want %q", info.FileName, "report.pdf")
	}
	if info.MimeType != "application/pdf" {
		t.Errorf("MimeType = %q, want %q", info.MimeType, "application/pdf")
	}
	if info.Size != 1024 {
		t.Errorf("Size = %d, want 1024", info.Size)
	}
}

func TestDecodeMediaInfo_Voice(t *testing.T) {
	media := &tg.MessageMediaDocument{
		Document: &tg.Document{
			Attributes: []tg.DocumentAttributeClass{
				&tg.DocumentAttributeAudio{Voice: true, Duration: 15},
			},
		},
	}
	info := DecodeMediaInfo(media)
	if info == nil {
		t.Fatal("expected non-nil MediaInfo")
	}
	if info.MediaType != "voice" {
		t.Errorf("MediaType = %q, want %q", info.MediaType, "voice")
	}
	if info.Duration != 15 {
		t.Errorf("Duration = %d, want 15", info.Duration)
	}
}

func TestDecodeMediaInfo_Sticker(t *testing.T) {
	media := &tg.MessageMediaDocument{
		Document: &tg.Document{
			Attributes: []tg.DocumentAttributeClass{
				&tg.DocumentAttributeSticker{},
			},
		},
	}
	info := DecodeMediaInfo(media)
	if info == nil {
		t.Fatal("expected non-nil MediaInfo")
	}
	if info.MediaType != "sticker" {
		t.Errorf("MediaType = %q, want %q", info.MediaType, "sticker")
	}
}

func TestDecodeMediaInfo_Empty(t *testing.T) {
	if got := DecodeMediaInfo(nil); got != nil {
		t.Errorf("DecodeMediaInfo(nil) = %v, want nil", got)
	}
	if got := DecodeMediaInfo(&tg.MessageMediaEmpty{}); got != nil {
		t.Errorf("DecodeMediaInfo(&tg.MessageMediaEmpty{}) = %v, want nil", got)
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
