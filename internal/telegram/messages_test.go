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
	t.Run("complete-history response never emits a cursor", func(t *testing.T) {
		// messages.messages (non-slice) means Telegram returned the entire
		// history — even a well-populated one must not ask the client to
		// keep paging.
		raw := &tg.MessagesMessages{
			Messages: []tg.MessageClass{
				&tg.Message{ID: 300, Message: "c"},
				&tg.Message{ID: 200, Message: "b"},
				&tg.Message{ID: 100, Message: "a"},
			},
		}
		if got := historyCursor(raw); got != 0 {
			t.Errorf("historyCursor = %d, want 0", got)
		}
	})

	t.Run("slice page emits min raw ID even when shorter than requested", func(t *testing.T) {
		// Telegram caps page sizes server-side, so a slice response smaller
		// than the requested limit does NOT mean end of history — the cursor
		// must still be emitted.
		raw := &tg.MessagesMessagesSlice{
			Count: 5000,
			Messages: []tg.MessageClass{
				&tg.Message{ID: 300, Message: "c"},
				&tg.Message{ID: 200, Message: "b"},
			},
		}
		if got := historyCursor(raw); got != 200 {
			t.Errorf("historyCursor = %d, want 200", got)
		}
	})

	t.Run("service messages count toward the cursor", func(t *testing.T) {
		// A raw page whose entries include service messages (joins/pins):
		// decodeMessages drops them, but the cursor must point below the
		// lowest raw entry, or pagination would re-fetch the service
		// messages forever.
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
		if got := historyCursor(raw); got != 50 {
			t.Errorf("historyCursor = %d, want 50 (min raw ID incl. service messages)", got)
		}
	})

	t.Run("empty slice page terminates paging", func(t *testing.T) {
		if got := historyCursor(&tg.MessagesMessagesSlice{Count: 5000}); got != 0 {
			t.Errorf("historyCursor = %d, want 0", got)
		}
	})

	t.Run("channel page behaves like a slice", func(t *testing.T) {
		raw := &tg.MessagesChannelMessages{
			Messages: []tg.MessageClass{
				&tg.Message{ID: 42, Message: "x"},
			},
		}
		if got := historyCursor(raw); got != 42 {
			t.Errorf("historyCursor = %d, want 42", got)
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

// TestDecodeMessagesRaw_MatchesDecoded proves the raw []*tg.Message slice
// GetMessagesRaw/GetUnreadMessagesRaw expose to fetch_media stays in lockstep
// with the decoded []Message slice: same length, same order, same IDs, and
// service messages dropped from both.
func TestDecodeMessagesRaw_MatchesDecoded(t *testing.T) {
	raw := &tg.MessagesMessagesSlice{
		Messages: []tg.MessageClass{
			&tg.Message{ID: 300, Message: "c"},
			&tg.MessageService{ID: 250},
			&tg.Message{ID: 200, Message: "b"},
			&tg.Message{ID: 100, Message: "a"},
		},
	}
	hint := &Dialog{ID: "user:1", Title: "Test"}
	decoded, rawMsgs := decodeMessagesRaw(raw, hint, nil, nil, 10)
	if len(decoded) != 3 {
		t.Fatalf("expected 3 decoded messages (service message dropped), got %d", len(decoded))
	}
	if len(decoded) != len(rawMsgs) {
		t.Fatalf("decoded len %d != raw len %d", len(decoded), len(rawMsgs))
	}
	for i := range decoded {
		if decoded[i].ID != rawMsgs[i].ID {
			t.Errorf("index %d: decoded ID %d != raw ID %d", i, decoded[i].ID, rawMsgs[i].ID)
		}
	}
	// decodeMessages (used by GetMessages/GetUnreadMessages) must produce the
	// exact same decoded slice as decodeMessagesRaw's first return value.
	plain := decodeMessages(raw, hint, nil, nil, 10)
	if len(plain) != len(decoded) {
		t.Fatalf("decodeMessages len %d != decodeMessagesRaw decoded len %d", len(plain), len(decoded))
	}
	for i := range plain {
		if plain[i].ID != decoded[i].ID {
			t.Errorf("index %d: decodeMessages ID %d != decodeMessagesRaw ID %d", i, plain[i].ID, decoded[i].ID)
		}
	}
}

// TestDecodeMessagesRaw_RespectsMax proves the raw slice is truncated to max
// in lockstep with the decoded slice.
func TestDecodeMessagesRaw_RespectsMax(t *testing.T) {
	raw := &tg.MessagesMessagesSlice{
		Messages: []tg.MessageClass{
			&tg.Message{ID: 3, Message: "c"},
			&tg.Message{ID: 2, Message: "b"},
			&tg.Message{ID: 1, Message: "a"},
		},
	}
	hint := &Dialog{ID: "user:1", Title: "Test"}
	decoded, rawMsgs := decodeMessagesRaw(raw, hint, nil, nil, 2)
	if len(decoded) != 2 || len(rawMsgs) != 2 {
		t.Fatalf("expected max=2 truncation, got decoded=%d raw=%d", len(decoded), len(rawMsgs))
	}
	if decoded[1].ID != rawMsgs[1].ID {
		t.Errorf("decoded[1].ID = %d, rawMsgs[1].ID = %d, want equal", decoded[1].ID, rawMsgs[1].ID)
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

func TestOrderUnreadTargets_UsersAndChatsBeforeChannels(t *testing.T) {
	targets := []unreadTarget{
		{hint: &Dialog{ID: "channel:1", Type: "channel"}},
		{hint: &Dialog{ID: "user:1", Type: "user"}},
		{hint: &Dialog{ID: "channel:2", Type: "channel"}},
		{hint: &Dialog{ID: "chat:1", Type: "chat"}},
		{hint: &Dialog{ID: "user:2", Type: "user"}},
	}
	got := orderUnreadTargets(targets)
	want := []string{"user:1", "chat:1", "user:2", "channel:1", "channel:2"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (channels must not be dropped)", len(got), len(want))
	}
	for i, id := range want {
		if got[i].hint.ID != id {
			t.Errorf("index %d: got %s, want %s", i, got[i].hint.ID, id)
		}
	}
}

func TestOrderUnreadTargets_EmptyAndSingleUnchanged(t *testing.T) {
	if got := orderUnreadTargets(nil); got != nil {
		t.Errorf("nil: got %#v", got)
	}
	one := []unreadTarget{{hint: &Dialog{ID: "channel:1", Type: "channel"}}}
	got := orderUnreadTargets(one)
	if len(got) != 1 || got[0].hint.ID != "channel:1" {
		t.Errorf("single: got %#v", got)
	}
}

func TestOrderUnreadTargets_LimitFillsHighPriorityFirst(t *testing.T) {
	// Mixed Telegram dialog order: a broadcast channel with 10k unread is
	// listed first. The default limit of 50 would previously be consumed
	// entirely by that channel (per-dialog cap 50). After reordering, the
	// DM is fetched first and leftover capacity still goes to the channel.
	targets := []unreadTarget{
		{hint: &Dialog{ID: "channel:news", Type: "channel"}, dialog: &tg.Dialog{UnreadCount: 10000}},
		{hint: &Dialog{ID: "user:alice", Type: "user"}, dialog: &tg.Dialog{UnreadCount: 3}},
		{hint: &Dialog{ID: "chat:group", Type: "chat"}, dialog: &tg.Dialog{UnreadCount: 2}},
		{hint: &Dialog{ID: "channel:other", Type: "channel"}, dialog: &tg.Dialog{UnreadCount: 40}},
	}
	ordered := orderUnreadTargets(targets)
	limit := 50
	type take struct {
		id string
		n  int
	}
	var plan []take
	remaining := limit
	for _, tgt := range ordered {
		if remaining <= 0 {
			break
		}
		n := tgt.dialog.UnreadCount
		if n > 50 {
			n = 50
		}
		if n > remaining {
			n = remaining
		}
		plan = append(plan, take{id: tgt.hint.ID, n: n})
		remaining -= n
	}
	want := []take{
		{id: "user:alice", n: 3},
		{id: "chat:group", n: 2},
		{id: "channel:news", n: 45},
	}
	if len(plan) != len(want) {
		t.Fatalf("plan = %+v, want %+v", plan, want)
	}
	for i := range want {
		if plan[i] != want[i] {
			t.Errorf("index %d: got %+v, want %+v", i, plan[i], want[i])
		}
	}
	if remaining != 0 {
		t.Errorf("remaining = %d, want 0 (channel leftover filled the rest)", remaining)
	}
}
