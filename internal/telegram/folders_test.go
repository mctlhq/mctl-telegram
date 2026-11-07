package telegram

import (
	"testing"
	"time"

	"github.com/gotd/td/tg"
)

// Fixture peers: Alice is a contact, Bob is not, Carol is a bot; 4401 is a
// basic group, 4402 a megagroup and 4403 a broadcast channel.
func folderFixture() (map[int64]*tg.User, map[int64]tg.ChatClass) {
	users := map[int64]*tg.User{
		4301: {ID: 4301, FirstName: "Alice", Contact: true},
		4302: {ID: 4302, FirstName: "Bob"},
		4303: {ID: 4303, FirstName: "Carol", Bot: true},
		4304: {ID: 4304, FirstName: "Dana", Self: true},
	}
	chats := map[int64]tg.ChatClass{
		4401: &tg.Chat{ID: 4401, Title: "Group"},
		4402: &tg.Channel{ID: 4402, Title: "Mega", Megagroup: true},
		4403: &tg.Channel{ID: 4403, Title: "News", Broadcast: true},
	}
	return users, chats
}

func dlg(p tg.PeerClass, unread int) *tg.Dialog {
	return &tg.Dialog{Peer: p, UnreadCount: unread}
}

func TestFolderSpec_RulesFollowTelegramClients(t *testing.T) {
	users, chats := folderFixture()
	now := time.Unix(1_800_000_000, 0)
	alice := &tg.PeerUser{UserID: 4301}
	bob := &tg.PeerUser{UserID: 4302}
	carol := &tg.PeerUser{UserID: 4303}
	self := &tg.PeerUser{UserID: 4304}
	group := &tg.PeerChat{ChatID: 4401}
	mega := &tg.PeerChannel{ChannelID: 4402}
	news := &tg.PeerChannel{ChannelID: 4403}

	groupsOnly, _ := specFromFilter(&tg.DialogFilter{ID: 2, Groups: true})
	contactsOnly, _ := specFromFilter(&tg.DialogFilter{ID: 3, Contacts: true})
	nonContacts, _ := specFromFilter(&tg.DialogFilter{ID: 4, NonContacts: true, Bots: true})
	channels, _ := specFromFilter(&tg.DialogFilter{ID: 5, Broadcasts: true, ExcludeRead: true})
	byHand, _ := specFromFilter(&tg.DialogFilter{
		ID: 6, Groups: true, ExcludeMuted: true, ExcludeArchived: true,
		IncludePeers: []tg.InputPeerClass{&tg.InputPeerUser{UserID: 4302}, &tg.InputPeerSelf{}},
		ExcludePeers: []tg.InputPeerClass{&tg.InputPeerChannel{ChannelID: 4402}},
	})
	shared, _ := specFromFilter(&tg.DialogFilterChatlist{ID: 7,
		IncludePeers: []tg.InputPeerClass{&tg.InputPeerChannel{ChannelID: 4403}}})

	muted := dlg(group, 3)
	muted.NotifySettings.SetMuteUntil(int(now.Unix()) + 3600)
	expiredMute := dlg(group, 3)
	expiredMute.NotifySettings.SetMuteUntil(int(now.Unix()) - 60)
	markedUnread := dlg(news, 0)
	markedUnread.UnreadMark = true

	cases := []struct {
		name     string
		spec     folderSpec
		d        *tg.Dialog
		archived bool
		want     bool
	}{
		{"groups rule takes a basic group", groupsOnly, dlg(group, 0), false, true},
		{"groups rule takes a megagroup", groupsOnly, dlg(mega, 0), false, true},
		{"groups rule skips a channel", groupsOnly, dlg(news, 0), false, false},
		{"groups rule skips a user", groupsOnly, dlg(alice, 0), false, false},
		{"contacts rule takes a contact", contactsOnly, dlg(alice, 0), false, true},
		{"contacts rule skips a non-contact", contactsOnly, dlg(bob, 0), false, false},
		{"contacts rule skips a bot", contactsOnly, dlg(carol, 0), false, false},
		{"non-contacts rule takes a stranger", nonContacts, dlg(bob, 0), false, true},
		{"bots rule takes a bot", nonContacts, dlg(carol, 0), false, true},
		{"non-contacts rule skips a contact", nonContacts, dlg(alice, 0), false, false},
		{"exclude read drops a read channel", channels, dlg(news, 0), false, false},
		{"exclude read keeps an unread channel", channels, dlg(news, 2), false, true},
		{"exclude read keeps a channel marked unread", channels, markedUnread, false, true},
		{"included by hand ignores the rules", byHand, dlg(bob, 0), false, true},
		{"self included by hand", byHand, dlg(self, 0), false, true},
		{"excluded by hand beats the rule", byHand, dlg(mega, 0), false, false},
		{"exclude muted drops a muted group", byHand, muted, false, false},
		{"an expired mute is not muted", byHand, expiredMute, false, true},
		{"exclude archived drops an archived group", byHand, dlg(group, 0), true, false},
		{"included by hand survives the archive", byHand, dlg(bob, 0), true, true},
		{"shared list takes its member", shared, dlg(news, 0), false, true},
		{"shared list has no rules", shared, dlg(group, 0), false, false},
		{"unknown user is not matched by a rule", nonContacts, dlg(&tg.PeerUser{UserID: 9}, 0), false, false},
	}
	for _, c := range cases {
		if got := c.spec.contains(c.d, users, chats, c.archived, now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestFoldersFromFilters_SkipsAllChatsAndDescribesRules(t *testing.T) {
	got := foldersFromFilters([]tg.DialogFilterClass{
		&tg.DialogFilterDefault{},
		&tg.DialogFilter{ID: 2, Title: tg.TextWithEntities{Text: "Work"}, Groups: true, ExcludeMuted: true,
			PinnedPeers:  []tg.InputPeerClass{&tg.InputPeerSelf{}},
			IncludePeers: []tg.InputPeerClass{&tg.InputPeerUser{UserID: 4302}},
			ExcludePeers: []tg.InputPeerClass{&tg.InputPeerChat{ChatID: 4401}}},
		&tg.DialogFilterChatlist{ID: 3, Title: tg.TextWithEntities{Text: "Shared"}},
	})
	if len(got) != 2 {
		t.Fatalf("want 2 folders (All chats skipped), got %d", len(got))
	}
	w := got[0]
	if w.ID != 2 || w.Title != "Work" || w.Kind != "folder" || w.IncludedPeers != 2 || w.ExcludedPeers != 1 {
		t.Errorf("work folder: %+v", w)
	}
	if len(w.IncludeRules) != 1 || w.IncludeRules[0] != "groups" || len(w.ExcludeRules) != 1 || w.ExcludeRules[0] != "muted" {
		t.Errorf("work rules: %+v / %+v", w.IncludeRules, w.ExcludeRules)
	}
	if got[1].Kind != "shared" || got[1].Title != "Shared" {
		t.Errorf("shared folder: %+v", got[1])
	}
}

func TestFolderMembersOf_ReportsWhatWasScanned(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	spec, _ := specFromFilter(&tg.DialogFilter{ID: 2, Groups: true})
	users := []tg.UserClass{&tg.User{ID: 4301, FirstName: "Alice", Contact: true}}
	chats := []tg.ChatClass{&tg.Chat{ID: 4401, Title: "Group"}}
	dialogs := []tg.DialogClass{
		&tg.Dialog{Peer: &tg.PeerUser{UserID: 4301}},
		&tg.Dialog{Peer: &tg.PeerChat{ChatID: 4401}},
	}

	full := &tg.MessagesDialogs{Dialogs: dialogs, Users: users, Chats: chats}
	got, scanned, complete := folderMembersOf(full, spec, false, now, "")
	if len(got) != 1 || got[0].Title != "Group" || got[0].Archived || scanned != 2 || !complete {
		t.Errorf("full list: got %+v scanned=%d complete=%v", got, scanned, complete)
	}

	partial := &tg.MessagesDialogsSlice{Count: 500, Dialogs: dialogs, Users: users, Chats: chats}
	_, scanned, complete = folderMembersOf(partial, spec, false, now, "")
	if scanned != 2 || complete {
		t.Errorf("slice of 500: scanned=%d complete=%v, want 2/false", scanned, complete)
	}

	whole := &tg.MessagesDialogsSlice{Count: 2, Dialogs: dialogs, Users: users, Chats: chats}
	if _, _, complete = folderMembersOf(whole, spec, false, now, ""); !complete {
		t.Error("slice holding every dialog reported incomplete")
	}

	got, _, _ = folderMembersOf(full, spec, true, now, "")
	if len(got) != 1 || !got[0].Archived {
		t.Errorf("archive page: member not marked archived: %+v", got)
	}

	got, scanned, complete = folderMembersOf(&tg.MessagesDialogsNotModified{Count: 9}, spec, false, now, "")
	if got != nil || scanned != 0 || complete {
		t.Errorf("not-modified: got %+v scanned=%d complete=%v, want nothing observed", got, scanned, complete)
	}
}
