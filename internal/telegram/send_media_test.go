package telegram

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/gotd/td/tg"
)

// A dry-run (realSend=false) must never touch Telegram and must return a
// self-describing preview mirroring SendMessage's dry-run shape, plus the
// media-specific fields. data may be nil in this path — the caller (the MCP
// tool layer) must not have fetched file_url or decoded file_base64 before
// reaching here on a gate-denied call.
func TestSendMedia_DryRunShape(t *testing.T) {
	res, err := SendMedia(context.Background(), nil, "@bob", "photo", nil, "cat.jpg", "image/jpeg", "look at this cat", false, "ALLOW_SEND=false", nil, 0)
	if err != nil {
		t.Fatalf("dry-run must not error: %v", err)
	}
	if res.Sent {
		t.Error("dry-run result must have sent=false")
	}
	if res.Mode != "draft" {
		t.Errorf("mode = %q, want draft", res.Mode)
	}
	if res.Notice == "" {
		t.Error("dry-run result must carry a human-readable notice")
	}
	if res.DryReason != "ALLOW_SEND=false" {
		t.Errorf("dry_reason = %q, want the gate reason", res.DryReason)
	}
	if res.MessageID != 0 {
		t.Errorf("dry-run must not have a message_id, got %d", res.MessageID)
	}
	if res.MediaType != "photo" {
		t.Errorf("media_type = %q, want photo", res.MediaType)
	}
	if res.Caption != "look at this cat" {
		t.Errorf("caption = %q, want echoed back", res.Caption)
	}

	b, _ := json.Marshal(res)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["sent"]; !ok {
		t.Errorf("serialized result missing \"sent\" field: %s", b)
	}
}

// An invalid media_type must be rejected before any dry-run/real-send
// branching, for both the dry-run and (implicitly) real-send paths.
func TestSendMedia_InvalidMediaType(t *testing.T) {
	_, err := SendMedia(context.Background(), nil, "@bob", "sticker", nil, "", "", "", false, "draft", nil, 0)
	if err == nil {
		t.Fatal("expected an error for an unsupported media_type")
	}
}

func TestSendMedia_PeerRequired(t *testing.T) {
	_, err := SendMedia(context.Background(), nil, "", "photo", nil, "", "", "", false, "draft", nil, 0)
	if err == nil {
		t.Fatal("expected an error for an empty peer")
	}
}

// A real send with no bytes must fail loudly rather than upload an empty
// file — this shouldn't be reachable through the MCP tool layer (which
// resolves bytes before calling SendMedia on the real-send path), but
// SendMedia itself must not silently proceed if it ever is.
func TestSendMedia_RealSendRequiresBytes(t *testing.T) {
	_, err := SendMedia(context.Background(), nil, "@bob", "photo", nil, "", "", "", true, "", nil, 0)
	if err == nil {
		t.Fatal("expected an error when realSend=true with no data")
	}
}

// buildInputMedia's attribute shapes are the concrete mechanism that keeps
// send_media's media_type choices consistent with DecodeMediaInfo's read-side
// classification (internal/telegram/messages.go). These are pure-function
// tests — no gotd/td RPC transport needed.
func TestBuildInputMedia_Photo(t *testing.T) {
	media, err := buildInputMedia("photo", &tg.InputFile{ID: 1}, "photo.jpg", "image/jpeg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	photo, ok := media.(*tg.InputMediaUploadedPhoto)
	if !ok {
		t.Fatalf("got %T, want *tg.InputMediaUploadedPhoto", media)
	}
	if photo.File == nil {
		t.Error("File must be set")
	}
}

func TestBuildInputMedia_Video(t *testing.T) {
	media, err := buildInputMedia("video", &tg.InputFile{ID: 1}, "clip.mp4", "video/mp4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	doc, ok := media.(*tg.InputMediaUploadedDocument)
	if !ok {
		t.Fatalf("got %T, want *tg.InputMediaUploadedDocument", media)
	}
	if doc.MimeType != "video/mp4" {
		t.Errorf("MimeType = %q, want video/mp4", doc.MimeType)
	}
	var hasVideo, hasAnimated bool
	for _, a := range doc.Attributes {
		switch v := a.(type) {
		case *tg.DocumentAttributeVideo:
			hasVideo = true
			if !v.SupportsStreaming {
				t.Error("video attribute should set SupportsStreaming")
			}
		case *tg.DocumentAttributeAnimated:
			hasAnimated = true
		}
	}
	if !hasVideo {
		t.Error("video media must carry a DocumentAttributeVideo")
	}
	if hasAnimated {
		t.Error("plain video media must NOT carry DocumentAttributeAnimated (would be misread as animation)")
	}
}

// TestBuildInputMedia_Animation is the key regression guard for requirement
// #9: animation must never be relabeled as video. It must carry BOTH
// DocumentAttributeAnimated and DocumentAttributeVideo, with Animated
// appearing FIRST in the slice — DecodeMediaInfo (messages.go) classifies a
// document by whichever of these two attributes appears first (both only
// fill an empty MediaType slot), so the order here is load-bearing, not
// cosmetic.
func TestBuildInputMedia_Animation(t *testing.T) {
	media, err := buildInputMedia("animation", &tg.InputFile{ID: 1}, "clip.gif", "video/mp4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	doc, ok := media.(*tg.InputMediaUploadedDocument)
	if !ok {
		t.Fatalf("got %T, want *tg.InputMediaUploadedDocument", media)
	}
	if len(doc.Attributes) < 2 {
		t.Fatalf("expected at least 2 attributes (animated, video), got %d", len(doc.Attributes))
	}
	if _, ok := doc.Attributes[0].(*tg.DocumentAttributeAnimated); !ok {
		t.Fatalf("Attributes[0] = %T, want *tg.DocumentAttributeAnimated (order is load-bearing, see DecodeMediaInfo)", doc.Attributes[0])
	}
	var hasVideo bool
	for _, a := range doc.Attributes {
		if _, ok := a.(*tg.DocumentAttributeVideo); ok {
			hasVideo = true
		}
	}
	if !hasVideo {
		t.Error("animation media must also carry a DocumentAttributeVideo for gif-as-mp4 playback")
	}
}

func TestBuildInputMedia_Document(t *testing.T) {
	media, err := buildInputMedia("document", &tg.InputFile{ID: 1}, "report.pdf", "application/pdf")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	doc, ok := media.(*tg.InputMediaUploadedDocument)
	if !ok {
		t.Fatalf("got %T, want *tg.InputMediaUploadedDocument", media)
	}
	var gotName string
	for _, a := range doc.Attributes {
		if fn, ok := a.(*tg.DocumentAttributeFilename); ok {
			gotName = fn.FileName
		}
	}
	if gotName != "report.pdf" {
		t.Errorf("filename attribute = %q, want report.pdf", gotName)
	}
}

func TestBuildInputMedia_UnsupportedType(t *testing.T) {
	if _, err := buildInputMedia("sticker", &tg.InputFile{ID: 1}, "", ""); err == nil {
		t.Fatal("expected an error for an unsupported media_type")
	}
}
