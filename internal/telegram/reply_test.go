package telegram

import (
	"errors"
	"testing"

	"github.com/gotd/td/tg"
)

func TestReplyTargetFromPeerDialogs(t *testing.T) {
	alice := &tg.InputPeerUser{UserID: 7001, AccessHash: 11}
	aliceDialog := &tg.Dialog{Peer: &tg.PeerUser{UserID: 7001}, TopMessage: 5}
	users := []tg.UserClass{&tg.User{ID: 7001, FirstName: "Alice", LastName: "Doe"}}

	got, err := replyTargetFromPeerDialogs(alice, &tg.MessagesPeerDialogs{Dialogs: []tg.DialogClass{aliceDialog}, Users: users})
	if err != nil {
		t.Fatal(err)
	}
	if got.Ref != "user:7001" || got.Title != "Alice Doe" || got.Peer != alice {
		t.Fatalf("target = %+v", got)
	}

	club := &tg.InputPeerChannel{ChannelID: 8001, AccessHash: 5}
	clubDialog := &tg.Dialog{Peer: &tg.PeerChannel{ChannelID: 8001}, TopMessage: 9}
	got, err = replyTargetFromPeerDialogs(club, &tg.MessagesPeerDialogs{
		Dialogs: []tg.DialogClass{clubDialog},
		Chats:   []tg.ChatClass{&tg.Channel{ID: 8001, Title: "Book club"}},
	})
	if err != nil || got.Ref != "channel:8001" || got.Title != "Book club" {
		t.Fatalf("member channel = %+v, %v", got, err)
	}

	group := &tg.InputPeerChat{ChatID: 9001}
	groupDialog := &tg.Dialog{Peer: &tg.PeerChat{ChatID: 9001}, TopMessage: 3}
	if _, err := replyTargetFromPeerDialogs(group, &tg.MessagesPeerDialogs{
		Dialogs: []tg.DialogClass{groupDialog},
		Chats:   []tg.ChatClass{&tg.Chat{ID: 9001, Title: "Family"}},
	}); err != nil {
		t.Fatalf("member group: %v", err)
	}

	// Every case below is "not a conversation of this account".
	for name, tc := range map[string]struct {
		peer tg.InputPeerClass
		res  *tg.MessagesPeerDialogs
	}{
		"user never talked to": {alice, &tg.MessagesPeerDialogs{Users: users}},
		"user dialog without messages": {alice, &tg.MessagesPeerDialogs{
			Dialogs: []tg.DialogClass{&tg.Dialog{Peer: &tg.PeerUser{UserID: 7001}}}, Users: users}},
		"dialog for another peer": {alice, &tg.MessagesPeerDialogs{
			Dialogs: []tg.DialogClass{&tg.Dialog{Peer: &tg.PeerUser{UserID: 7002}, TopMessage: 1}}}},
		// A public channel resolves by @username and reads fine for a
		// non-member; readability is not participation.
		"public channel never joined": {club, &tg.MessagesPeerDialogs{
			Dialogs: []tg.DialogClass{clubDialog},
			Chats:   []tg.ChatClass{&tg.Channel{ID: 8001, Title: "Book club", Left: true}}}},
		"channel without its chat object": {club, &tg.MessagesPeerDialogs{Dialogs: []tg.DialogClass{clubDialog}}},
		"min channel": {club, &tg.MessagesPeerDialogs{
			Dialogs: []tg.DialogClass{clubDialog},
			Chats:   []tg.ChatClass{&tg.Channel{ID: 8001, Min: true}}}},
		"group left": {group, &tg.MessagesPeerDialogs{
			Dialogs: []tg.DialogClass{groupDialog},
			Chats:   []tg.ChatClass{&tg.Chat{ID: 9001, Left: true}}}},
		"group forbidden": {group, &tg.MessagesPeerDialogs{
			Dialogs: []tg.DialogClass{groupDialog},
			Chats:   []tg.ChatClass{&tg.ChatForbidden{ID: 9001}}}},
	} {
		if _, err := replyTargetFromPeerDialogs(tc.peer, tc.res); !errors.Is(err, ErrNoExistingDialog) {
			t.Errorf("%s: err = %v, want ErrNoExistingDialog", name, err)
		}
	}

	// No response is not an observed absence.
	if _, err := replyTargetFromPeerDialogs(alice, nil); err == nil || errors.Is(err, ErrNoExistingDialog) {
		t.Fatalf("nil response: %v", err)
	}
	if _, err := replyTargetFromPeerDialogs(&tg.InputPeerSelf{}, &tg.MessagesPeerDialogs{}); err == nil {
		t.Fatal("InputPeerSelf accepted as a reply target")
	}
}
