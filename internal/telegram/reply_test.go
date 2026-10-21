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

	// Posting rights: a member who may post is accepted.
	for name, ch := range map[string]tg.ChatClass{
		"own broadcast channel":     &tg.Channel{ID: 8001, Broadcast: true, Creator: true},
		"broadcast channel poster":  withAdmin(&tg.Channel{ID: 8001, Broadcast: true}, tg.ChatAdminRights{PostMessages: true}),
		"gigagroup admin":           withAdmin(&tg.Channel{ID: 8001, Megagroup: true, Gigagroup: true}, tg.ChatAdminRights{}),
		"admin in muted supergroup": withAdmin(withDefaultBan(&tg.Channel{ID: 8001, Megagroup: true}, tg.ChatBannedRights{SendMessages: true}), tg.ChatAdminRights{}),
		"supergroup member":         &tg.Channel{ID: 8001, Megagroup: true},
		// A per-member exception in a read-only supergroup overrides the
		// default ban for that member.
		"exception in muted supergroup": withOwnRights(withDefaultBan(&tg.Channel{ID: 8001, Megagroup: true}, tg.ChatBannedRights{SendMessages: true}), tg.ChatBannedRights{SendMedia: true}),
	} {
		if _, err := replyTargetFromPeerDialogs(club, &tg.MessagesPeerDialogs{Dialogs: []tg.DialogClass{clubDialog}, Chats: []tg.ChatClass{ch}}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	mutedGroup := &tg.Chat{ID: 9001}
	mutedGroup.SetDefaultBannedRights(tg.ChatBannedRights{SendPlain: true})
	adminInMutedGroup := &tg.Chat{ID: 9001}
	adminInMutedGroup.SetDefaultBannedRights(tg.ChatBannedRights{SendMessages: true})
	adminInMutedGroup.SetAdminRights(tg.ChatAdminRights{})
	if _, err := replyTargetFromPeerDialogs(group, &tg.MessagesPeerDialogs{Dialogs: []tg.DialogClass{groupDialog}, Chats: []tg.ChatClass{adminInMutedGroup}}); err != nil {
		t.Errorf("admin in muted group: %v", err)
	}

	// A deleted account keeps its dialog but cannot receive messages.
	if _, err := replyTargetFromPeerDialogs(alice, &tg.MessagesPeerDialogs{
		Dialogs: []tg.DialogClass{aliceDialog},
		Users:   []tg.UserClass{&tg.User{ID: 7001, Deleted: true}, &tg.User{ID: 7002}},
	}); !errors.Is(err, ErrPeerDeleted) {
		t.Errorf("deleted account: err = %v, want ErrPeerDeleted", err)
	}
	// Without its user object a user peer is still proven by the dialog.
	if _, err := replyTargetFromPeerDialogs(alice, &tg.MessagesPeerDialogs{Dialogs: []tg.DialogClass{aliceDialog}}); err != nil {
		t.Errorf("user object missing: %v", err)
	}
	// Another user in the response being deleted does not refuse this one.
	if _, err := replyTargetFromPeerDialogs(alice, &tg.MessagesPeerDialogs{
		Dialogs: []tg.DialogClass{aliceDialog},
		Users:   []tg.UserClass{&tg.User{ID: 7001}, &tg.User{ID: 7002, Deleted: true}},
	}); err != nil {
		t.Errorf("another user deleted: %v", err)
	}

	// A member who may not post is refused with its own error.
	ownBan := withOwnRights(&tg.Channel{ID: 8001, Megagroup: true}, tg.ChatBannedRights{SendMessages: true})
	viewBan := withOwnRights(&tg.Channel{ID: 8001, Megagroup: true}, tg.ChatBannedRights{ViewMessages: true})
	for name, tc := range map[string]struct {
		peer tg.InputPeerClass
		chat tg.ChatClass
		dlg  tg.DialogClass
	}{
		"broadcast channel subscriber": {club, &tg.Channel{ID: 8001, Broadcast: true}, clubDialog},
		"broadcast admin without post": {club, withAdmin(&tg.Channel{ID: 8001, Broadcast: true}, tg.ChatAdminRights{EditMessages: true}), clubDialog},
		"gigagroup member":             {club, &tg.Channel{ID: 8001, Megagroup: true, Gigagroup: true}, clubDialog},
		"supergroup bans sending":      {club, withDefaultBan(&tg.Channel{ID: 8001, Megagroup: true}, tg.ChatBannedRights{SendMessages: true}), clubDialog},
		"supergroup bans plain text":   {club, withDefaultBan(&tg.Channel{ID: 8001, Megagroup: true}, tg.ChatBannedRights{SendPlain: true}), clubDialog},
		"member restricted personally": {club, ownBan, clubDialog},
		"member banned from viewing":   {club, viewBan, clubDialog},
		"group bans plain text":        {group, mutedGroup, groupDialog},
	} {
		_, err := replyTargetFromPeerDialogs(tc.peer, &tg.MessagesPeerDialogs{Dialogs: []tg.DialogClass{tc.dlg}, Chats: []tg.ChatClass{tc.chat}})
		if !errors.Is(err, ErrCannotPost) {
			t.Errorf("%s: err = %v, want ErrCannotPost", name, err)
		}
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

func withAdmin(ch *tg.Channel, r tg.ChatAdminRights) *tg.Channel {
	ch.SetAdminRights(r)
	return ch
}

func withDefaultBan(ch *tg.Channel, r tg.ChatBannedRights) *tg.Channel {
	ch.SetDefaultBannedRights(r)
	return ch
}

func withOwnRights(ch *tg.Channel, r tg.ChatBannedRights) *tg.Channel {
	ch.SetBannedRights(r)
	return ch
}
