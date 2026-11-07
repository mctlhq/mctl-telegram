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

func TestFolderPageOf_ReportsWhatWasScanned(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	spec, _ := specFromFilter(&tg.DialogFilter{ID: 2, Groups: true})
	users := []tg.UserClass{&tg.User{ID: 4301, FirstName: "Alice", Contact: true}}
	chats := []tg.ChatClass{&tg.Chat{ID: 4401, Title: "Group"}}
	dialogs := []tg.DialogClass{
		&tg.Dialog{Peer: &tg.PeerUser{UserID: 4301}},
		&tg.Dialog{Peer: &tg.PeerChat{ChatID: 4401}},
	}

	full := &tg.MessagesDialogs{Dialogs: dialogs, Users: users, Chats: chats}
	p := folderPageOf(full, spec, false, now, "")
	if len(p.members) != 1 || p.members[0].Title != "Group" || p.members[0].Archived || p.scanned != 2 || p.total != 2 {
		t.Errorf("full list: %+v", p)
	}
	if p := folderPageOf(&tg.MessagesDialogsSlice{Count: 500, Dialogs: dialogs, Users: users, Chats: chats}, spec, false, now, ""); p.total != 500 {
		t.Errorf("slice total = %d, want 500", p.total)
	}
	if p := folderPageOf(full, spec, true, now, ""); len(p.members) != 1 || !p.members[0].Archived {
		t.Errorf("archive page: member not marked archived: %+v", p.members)
	}
	if p := folderPageOf(&tg.MessagesDialogsNotModified{Count: 9}, spec, false, now, ""); p.total != -1 || p.scanned != 0 {
		t.Errorf("not-modified: %+v, want nothing observed", p)
	}
}

// fakeDialogPages serves count dialogs (basic groups 5000..) in pages,
// newest first, the way
// messages.getDialogs answers an offset request.
type fakeDialogPages struct {
	count    int
	requests []*tg.MessagesGetDialogsRequest
	notMod   bool
	noDates  bool
	// emptyAfter, when set, answers every request after the first with an
	// empty slice that still reports count.
	emptyAfter bool
}

func (f *fakeDialogPages) fetch(req *tg.MessagesGetDialogsRequest) (tg.MessagesDialogsClass, error) {
	f.requests = append(f.requests, req)
	if f.notMod {
		return &tg.MessagesDialogsNotModified{Count: f.count}, nil
	}
	start := 0
	if req.OffsetID != 0 {
		start = req.OffsetID // fixture: top message id == position+1
	}
	res := &tg.MessagesDialogsSlice{Count: f.count}
	if f.emptyAfter && len(f.requests) > 1 {
		return res, nil
	}
	for i := start; i < f.count && len(res.Dialogs) < req.Limit; i++ {
		id := int64(5000 + i)
		res.Dialogs = append(res.Dialogs, &tg.Dialog{Peer: &tg.PeerChat{ChatID: id}, TopMessage: i + 1})
		res.Chats = append(res.Chats, &tg.Chat{ID: id, Title: "Group"})
		if !f.noDates {
			res.Messages = append(res.Messages, &tg.Message{ID: i + 1, PeerID: &tg.PeerChat{ChatID: id}, Date: 1_700_000_000 - i})
		}
	}
	return res, nil
}

func TestScanFolderList_PagesToTheBoundAndSaysWhetherItEnded(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	spec, _ := specFromFilter(&tg.DialogFilter{ID: 2, Groups: true})
	cases := []struct {
		name         string
		pages        *fakeDialogPages
		wantScanned  int
		wantMembers  int
		wantComplete bool
		wantRequests int
	}{
		{"list ends on the second page", &fakeDialogPages{count: 150}, 150, 150, true, 2},
		{"list longer than the bound", &fakeDialogPages{count: 500}, 200, 200, false, 2},
		{"short list in one page", &fakeDialogPages{count: 30}, 30, 30, true, 1},
		{"nothing observable", &fakeDialogPages{count: 30, notMod: true}, 0, 0, false, 1},
		{"empty page short of the total", &fakeDialogPages{count: 500, emptyAfter: true}, 100, 100, false, 2},
		{"no offset for the next page", &fakeDialogPages{count: 150, noDates: true}, 100, 100, false, 1},
	}
	for _, c := range cases {
		got, scan, err := scanFolderList(c.pages.fetch, 0, folderScanMain, spec, false, now, "")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if scan.Scanned != c.wantScanned || len(got) != c.wantMembers || scan.Complete != c.wantComplete || len(c.pages.requests) != c.wantRequests {
			t.Errorf("%s: scanned=%d members=%d complete=%v requests=%d; want %d/%d/%v/%d", c.name,
				scan.Scanned, len(got), scan.Complete, len(c.pages.requests), c.wantScanned, c.wantMembers, c.wantComplete, c.wantRequests)
		}
	}
	p := &fakeDialogPages{count: 150}
	_, _, _ = scanFolderList(p.fetch, 1, folderScanMain, spec, true, now, "")
	second := p.requests[1]
	peer, ok := second.OffsetPeer.(*tg.InputPeerChat)
	if !ok || peer.ChatID != 5099 || second.OffsetID != 100 || second.OffsetDate != 1_700_000_000-99 || second.Limit != 100 {
		t.Errorf("second page request = %+v, want offset after dialog 5099", second)
	}
	if fid, ok := second.GetFolderID(); !ok || fid != 1 {
		t.Errorf("archive paging lost the folder id: %v %v", fid, ok)
	}
}

func TestFolderSpec_MentionsAndDefaultMutes(t *testing.T) {
	users, chats := folderFixture()
	now := time.Unix(1_800_000_000, 0)
	group := &tg.PeerChat{ChatID: 4401}
	news := &tg.PeerChannel{ChannelID: 4403}
	spec, _ := specFromFilter(&tg.DialogFilter{ID: 2, Groups: true, Broadcasts: true, ExcludeMuted: true, ExcludeRead: true})
	spec.defaultMuted = map[string]bool{"broadcasts": true}

	mutedMention := dlg(group, 1)
	mutedMention.NotifySettings.SetMuteUntil(int(now.Unix()) + 3600)
	mutedMention.UnreadMentionsCount = 1
	readMention := dlg(group, 0)
	readMention.UnreadMentionsCount = 1
	explicitUnmute := dlg(news, 2)
	explicitUnmute.NotifySettings.SetMuteUntil(0)

	cases := []struct {
		name     string
		d        *tg.Dialog
		archived bool
		want     bool
	}{
		{"muted chat with a mention stays in the main list", mutedMention, false, true},
		{"muted chat with a mention in the archive is dropped", mutedMention, true, false},
		{"read chat with an unread mention stays", readMention, false, true},
		{"channel muted by the default is dropped", dlg(news, 2), false, false},
		{"channel unmuted on its own beats the default", explicitUnmute, false, true},
		{"group follows its own default (unmuted)", dlg(group, 2), false, true},
	}
	for _, c := range cases {
		if got := spec.contains(c.d, users, chats, c.archived, now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
