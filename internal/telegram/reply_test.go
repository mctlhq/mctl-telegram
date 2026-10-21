package telegram

import (
	"errors"
	"testing"

	"github.com/gotd/td/tg"
)

func TestReplyTargetFromHistory(t *testing.T) {
	alice := &tg.InputPeerUser{UserID: 7001, AccessHash: 11}
	msg := []tg.MessageClass{&tg.Message{ID: 1}}
	users := []tg.UserClass{&tg.User{ID: 7001, FirstName: "Alice", LastName: "Doe"}}

	got, err := replyTargetFromHistory(alice, &tg.MessagesMessagesSlice{Messages: msg, Users: users})
	if err != nil {
		t.Fatal(err)
	}
	if got.Ref != "user:7001" || got.Title != "Alice Doe" || got.Peer != alice {
		t.Fatalf("target = %+v", got)
	}

	// No history is the documented "never talked to" signal.
	if _, err := replyTargetFromHistory(alice, &tg.MessagesMessages{Users: users}); !errors.Is(err, ErrNoExistingDialog) {
		t.Fatalf("empty history: %v", err)
	}
	// A response that carries no history at all could not be observed; it
	// is an error, and not the "no conversation" one.
	if _, err := replyTargetFromHistory(alice, &tg.MessagesMessagesNotModified{}); err == nil || errors.Is(err, ErrNoExistingDialog) {
		t.Fatalf("not-modified response: %v", err)
	}

	group := &tg.InputPeerChannel{ChannelID: 8001, AccessHash: 5}
	got, err = replyTargetFromHistory(group, &tg.MessagesChannelMessages{
		Messages: msg, Chats: []tg.ChatClass{&tg.Channel{ID: 8001, Title: "Book club"}},
	})
	if err != nil || got.Ref != "channel:8001" || got.Title != "Book club" {
		t.Fatalf("channel target = %+v, %v", got, err)
	}

	if _, err := replyTargetFromHistory(&tg.InputPeerSelf{}, &tg.MessagesMessages{Messages: msg}); err == nil {
		t.Fatal("InputPeerSelf accepted as a reply target")
	}
}
