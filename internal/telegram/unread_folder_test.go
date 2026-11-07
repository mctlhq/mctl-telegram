package telegram

import (
	"context"
	"errors"
	"testing"

	"github.com/gotd/td/tg"
)

// Dana is an archived private chat for the folder tests (issue #1155).
const bcDanaID = 8531

var bcDana = &tg.User{ID: bcDanaID, AccessHash: 4, FirstName: "Dana"}

func unreadPeers(msgs []Message) map[string]int {
	got := map[string]int{}
	for _, m := range msgs {
		got[m.Peer]++
	}
	return got
}

func historyHasUser(f *fakeMTProto, id int64) bool {
	for _, p := range f.history {
		if u, ok := p.(*tg.InputPeerUser); ok && u.UserID == id {
			return true
		}
	}
	return false
}

func TestGetUnreadInFolder_ReadsOnlyTheFolderMembers(t *testing.T) {
	f, api := newFake()
	f.filters = []tg.DialogFilterClass{
		&tg.DialogFilter{ID: 7, Title: tg.TextWithEntities{Text: "Work"}, IncludePeers: []tg.InputPeerClass{
			&tg.InputPeerUser{UserID: bcAliceID}, &tg.InputPeerUser{UserID: bcDanaID},
		}},
	}
	f.archive = &tg.MessagesDialogs{
		Dialogs: []tg.DialogClass{&tg.Dialog{Peer: &tg.PeerUser{UserID: bcDanaID}, UnreadCount: 1}},
		Users:   []tg.UserClass{bcDana},
	}
	msgs, _, _, scan, err := getUnreadMessagesInFolderWith(context.Background(), api, 7, 50, BroadcastContentAllowed, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := unreadPeers(msgs)
	if !historyHasUser(f, bcAliceID) || !historyHasUser(f, bcDanaID) || len(msgs) == 0 {
		t.Errorf("folder members missing from the unread: %v", got)
	}
	if historyHasChannel(f, bcTeamID) || historyHasChannel(f, bcNewsID) {
		t.Errorf("a chat outside the folder was read: %v", got)
	}
	if !scan.Complete || scan.Scanned != 4 {
		t.Errorf("scan = %+v, want 4 dialogs, complete", scan)
	}
}

func TestGetUnreadInFolder_KeepsTheUnscopedRules(t *testing.T) {
	// A folder of every group and channel: the broadcast switch still
	// applies, as it does to an unscoped call.
	f, api := newFake()
	f.filters = []tg.DialogFilterClass{&tg.DialogFilter{ID: 8, Groups: true, Broadcasts: true, ExcludeArchived: true}}
	msgs, _, _, _, err := getUnreadMessagesInFolderWith(context.Background(), api, 8, 50, BroadcastContentRefused, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if historyHasChannel(f, bcNewsID) {
		t.Error("a broadcast channel was read with broadcast content off")
	}
	if !historyHasChannel(f, bcTeamID) {
		t.Errorf("the megagroup in the folder was not read: %v", unreadPeers(msgs))
	}
	if f.called("getArchive") {
		t.Error("the archive was scanned for a folder that excludes archived chats")
	}
}

func TestGetUnreadInFolder_Refusals(t *testing.T) {
	f, api := newFake()
	if _, _, _, _, err := getUnreadMessagesInFolderWith(context.Background(), api, 9, 50, BroadcastContentAllowed, nil, 0); !errors.Is(err, ErrFolderNotFound) {
		t.Fatalf("unknown folder: %v", err)
	}
	if f.called("getDialogs") || f.called("getHistory") {
		t.Errorf("an unknown folder read chats: %v", f.calls)
	}
}
