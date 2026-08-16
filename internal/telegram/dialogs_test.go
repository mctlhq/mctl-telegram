package telegram

import (
	"testing"
	"time"

	"github.com/gotd/td/tg"
)

func TestDialogEntries_LastMessageDateFromTopMessage(t *testing.T) {
	users := map[int64]*tg.User{
		1: {ID: 1, FirstName: "Alice"},
		2: {ID: 2, FirstName: "Bob"},
	}
	chats := map[int64]tg.ChatClass{
		10: &tg.Chat{ID: 10, Title: "Group"},
		20: &tg.Channel{ID: 20, Title: "News", Username: "news"},
	}
	// Same numeric TopMessage on a user and a chat must not collide: channel
	// message ids live in a per-channel space, and even user/chat ids can
	// overlap a channel id.
	dialogs := []tg.DialogClass{
		&tg.Dialog{Peer: &tg.PeerUser{UserID: 1}, TopMessage: 5, UnreadCount: 2},
		&tg.Dialog{Peer: &tg.PeerChat{ChatID: 10}, TopMessage: 5, UnreadCount: 0},
		&tg.Dialog{Peer: &tg.PeerChannel{ChannelID: 20}, TopMessage: 100, UnreadCount: 999},
		&tg.Dialog{Peer: &tg.PeerUser{UserID: 2}, TopMessage: 7, UnreadCount: 1},
	}
	aliceDate := int(time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC).Unix())
	groupDate := int(time.Date(2024, 6, 2, 8, 30, 0, 0, time.UTC).Unix())
	newsDate := int(time.Date(2024, 6, 3, 18, 0, 0, 0, time.UTC).Unix())
	messages := []tg.MessageClass{
		&tg.Message{ID: 5, Date: aliceDate, PeerID: &tg.PeerUser{UserID: 1}, Message: "hi"},
		&tg.Message{ID: 5, Date: groupDate, PeerID: &tg.PeerChat{ChatID: 10}, Message: "group"},
		&tg.Message{ID: 100, Date: newsDate, PeerID: &tg.PeerChannel{ChannelID: 20}, Message: "news"},
		// Bob's top message is missing: LastMessageDate must stay zero.
	}

	got := dialogEntries(dialogs, users, chats, messages, "")
	if len(got) != 4 {
		t.Fatalf("got %d dialogs, want 4", len(got))
	}

	want := map[string]time.Time{
		"user:1":     time.Unix(int64(aliceDate), 0).UTC(),
		"chat:10":    time.Unix(int64(groupDate), 0).UTC(),
		"channel:20": time.Unix(int64(newsDate), 0).UTC(),
		"user:2":     time.Time{},
	}
	for _, d := range got {
		ts, ok := want[d.ID]
		if !ok {
			t.Fatalf("unexpected dialog %q", d.ID)
		}
		if !d.LastMessageDate.Equal(ts) {
			t.Errorf("%s LastMessageDate = %v, want %v", d.ID, d.LastMessageDate, ts)
		}
	}
}

func TestDialogEntries_ServiceTopMessageDate(t *testing.T) {
	users := map[int64]*tg.User{1: {ID: 1, FirstName: "Alice"}}
	date := int(time.Date(2024, 7, 4, 9, 0, 0, 0, time.UTC).Unix())
	dialogs := []tg.DialogClass{
		&tg.Dialog{Peer: &tg.PeerUser{UserID: 1}, TopMessage: 42},
	}
	messages := []tg.MessageClass{
		&tg.MessageService{ID: 42, Date: date, PeerID: &tg.PeerUser{UserID: 1}},
	}
	got := dialogEntries(dialogs, users, nil, messages, "")
	if len(got) != 1 {
		t.Fatalf("got %d dialogs, want 1", len(got))
	}
	want := time.Unix(int64(date), 0).UTC()
	if !got[0].LastMessageDate.Equal(want) {
		t.Errorf("LastMessageDate = %v, want %v", got[0].LastMessageDate, want)
	}
}

func TestDialogEntries_DoesNotInventDates(t *testing.T) {
	users := map[int64]*tg.User{1: {ID: 1, FirstName: "Alice"}}
	dialogs := []tg.DialogClass{
		&tg.Dialog{Peer: &tg.PeerUser{UserID: 1}, TopMessage: 9},
	}
	t.Run("date zero", func(t *testing.T) {
		messages := []tg.MessageClass{
			&tg.Message{ID: 9, Date: 0, PeerID: &tg.PeerUser{UserID: 1}},
		}
		got := dialogEntries(dialogs, users, nil, messages, "")
		if len(got) != 1 {
			t.Fatalf("got %d dialogs, want 1", len(got))
		}
		if !got[0].LastMessageDate.IsZero() {
			t.Errorf("LastMessageDate = %v, want zero (do not invent epoch)", got[0].LastMessageDate)
		}
	})
	t.Run("top message id unmatched", func(t *testing.T) {
		messages := []tg.MessageClass{
			&tg.Message{ID: 8, Date: 1700000000, PeerID: &tg.PeerUser{UserID: 1}},
		}
		got := dialogEntries(dialogs, users, nil, messages, "")
		if len(got) != 1 {
			t.Fatalf("got %d dialogs, want 1", len(got))
		}
		if !got[0].LastMessageDate.IsZero() {
			t.Errorf("LastMessageDate = %v, want zero when TopMessage is missing", got[0].LastMessageDate)
		}
	})
	t.Run("empty messages", func(t *testing.T) {
		got := dialogEntries(dialogs, users, nil, nil, "")
		if len(got) != 1 {
			t.Fatalf("got %d dialogs, want 1", len(got))
		}
		if !got[0].LastMessageDate.IsZero() {
			t.Errorf("LastMessageDate = %v, want zero", got[0].LastMessageDate)
		}
	})
}

func TestDialogsTopMessages(t *testing.T) {
	msg := &tg.Message{ID: 1, Date: 1700000000, PeerID: &tg.PeerUser{UserID: 1}}
	full := &tg.MessagesDialogs{Messages: []tg.MessageClass{msg}}
	slice := &tg.MessagesDialogsSlice{Messages: []tg.MessageClass{msg}}
	if got := dialogsTopMessages(full); len(got) != 1 || got[0] != msg {
		t.Errorf("MessagesDialogs: got %#v", got)
	}
	if got := dialogsTopMessages(slice); len(got) != 1 || got[0] != msg {
		t.Errorf("MessagesDialogsSlice: got %#v", got)
	}
	if got := dialogsTopMessages(&tg.MessagesDialogsNotModified{}); got != nil {
		t.Errorf("MessagesDialogsNotModified: got %#v, want nil", got)
	}
}

func TestDialogEntries_QueryFilterKeepsDate(t *testing.T) {
	users := map[int64]*tg.User{
		1: {ID: 1, FirstName: "Alice"},
		2: {ID: 2, FirstName: "Bob"},
	}
	date := 1700000000
	dialogs := []tg.DialogClass{
		&tg.Dialog{Peer: &tg.PeerUser{UserID: 1}, TopMessage: 1},
		&tg.Dialog{Peer: &tg.PeerUser{UserID: 2}, TopMessage: 2},
	}
	messages := []tg.MessageClass{
		&tg.Message{ID: 1, Date: date, PeerID: &tg.PeerUser{UserID: 1}},
		&tg.Message{ID: 2, Date: date + 60, PeerID: &tg.PeerUser{UserID: 2}},
	}
	got := dialogEntries(dialogs, users, nil, messages, "ali")
	if len(got) != 1 || got[0].ID != "user:1" {
		t.Fatalf("got %#v, want only Alice", got)
	}
	want := time.Unix(int64(date), 0).UTC()
	if !got[0].LastMessageDate.Equal(want) {
		t.Errorf("LastMessageDate = %v, want %v", got[0].LastMessageDate, want)
	}
}
