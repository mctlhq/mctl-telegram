package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

// Synthetic ids for issue #851: Alice is a private chat, News a broadcast
// channel, Team a megagroup. Tests named *_SwitchOff* pin the refusal that
// BROADCAST_CONTENT_ENABLED=false restores; the rest pin channel content
// with its sponsored messages.
const (
	bcAliceID = 8511
	bcNewsID  = 8521
	bcTeamID  = 8522
)

var (
	bcAlice = &tg.User{ID: bcAliceID, AccessHash: 1, FirstName: "Alice"}
	bcNews  = &tg.Channel{ID: bcNewsID, AccessHash: 2, Title: "News", Broadcast: true, Photo: &tg.ChatPhotoEmpty{}}
	bcTeam  = &tg.Channel{ID: bcTeamID, AccessHash: 3, Title: "Team", Megagroup: true, Photo: &tg.ChatPhotoEmpty{}}
)

// fakeMTProto answers the requests the content tools send, recording each
// one, so a test can assert both the result and which calls never happened.
type fakeMTProto struct {
	dialogs   *tg.MessagesDialogs
	channels  map[int64]tg.ChatClass // channels.getChannels answers; missing id = absent from reply
	lookupErr error
	calls     []string
	history   []tg.InputPeerClass

	historyChats   []tg.ChatClass // chats attached to every history reply
	emptyHistory   bool           // history replies carry no messages
	historyErrOnce error          // returned by the first getHistory only

	sponsored    tg.MessagesSponsoredMessagesClass // nil = messages.sponsoredMessagesEmpty
	sponsoredErr error
	sponsoredFor []tg.InputPeerClass
	viewed       [][]byte
	viewErr      error
}

func (f *fakeMTProto) Invoke(_ context.Context, input bin.Encoder, output bin.Decoder) error {
	var res bin.Encoder
	switch req := input.(type) {
	case *tg.MessagesGetDialogsRequest:
		f.calls = append(f.calls, "getDialogs")
		res = f.dialogs
	case *tg.MessagesGetHistoryRequest:
		f.calls = append(f.calls, "getHistory")
		f.history = append(f.history, req.Peer)
		if err := f.historyErrOnce; err != nil {
			f.historyErrOnce = nil
			return err
		}
		out := &tg.MessagesMessages{Chats: f.historyChats}
		if !f.emptyHistory {
			n := req.Limit
			if n > 3 {
				n = 3
			}
			for i := 1; i <= n; i++ {
				out.Messages = append(out.Messages, &tg.Message{ID: i, Message: "hi", PeerID: peerOf(req.Peer)})
			}
		}
		res = out
	case *tg.MessagesGetSponsoredMessagesRequest:
		f.calls = append(f.calls, "getSponsored")
		f.sponsoredFor = append(f.sponsoredFor, req.Peer)
		if f.sponsoredErr != nil {
			return f.sponsoredErr
		}
		res = f.sponsored
		if res == nil {
			res = &tg.MessagesSponsoredMessagesEmpty{}
		}
	case *tg.MessagesViewSponsoredMessageRequest:
		f.calls = append(f.calls, "viewSponsored")
		f.viewed = append(f.viewed, req.RandomID)
		if f.viewErr != nil {
			return f.viewErr
		}
		res = &tg.BoolTrue{}
	case *tg.ChannelsGetChannelsRequest:
		f.calls = append(f.calls, "getChannels")
		if f.lookupErr != nil {
			return f.lookupErr
		}
		out := &tg.MessagesChats{}
		for _, ic := range req.ID {
			if c, ok := f.channels[ic.(*tg.InputChannel).ChannelID]; ok {
				out.Chats = append(out.Chats, c)
			}
		}
		res = out
	case *tg.ChannelsGetMessagesRequest:
		f.calls = append(f.calls, "channelGetMessages")
		res = &tg.MessagesMessages{}
	case *tg.MessagesGetMessagesRequest:
		f.calls = append(f.calls, "getMessages")
		res = &tg.MessagesMessages{}
	default:
		return fmt.Errorf("fakeMTProto: unexpected request %T", input)
	}
	var b bin.Buffer
	if err := res.Encode(&b); err != nil {
		return err
	}
	return output.Decode(&b)
}

func (f *fakeMTProto) called(name string) bool {
	for _, c := range f.calls {
		if c == name {
			return true
		}
	}
	return false
}

func peerOf(p tg.InputPeerClass) tg.PeerClass {
	switch v := p.(type) {
	case *tg.InputPeerUser:
		return &tg.PeerUser{UserID: v.UserID}
	case *tg.InputPeerChannel:
		return &tg.PeerChannel{ChannelID: v.ChannelID}
	case *tg.InputPeerChat:
		return &tg.PeerChat{ChatID: v.ChatID}
	}
	return &tg.PeerUser{}
}

// bcDialogs lists Alice, News and Team, each with unread messages.
func bcDialogs() *tg.MessagesDialogs {
	return &tg.MessagesDialogs{
		Dialogs: []tg.DialogClass{
			&tg.Dialog{Peer: &tg.PeerChannel{ChannelID: bcNewsID}, UnreadCount: 40},
			&tg.Dialog{Peer: &tg.PeerUser{UserID: bcAliceID}, UnreadCount: 2},
			&tg.Dialog{Peer: &tg.PeerChannel{ChannelID: bcTeamID}, UnreadCount: 1},
		},
		Users: []tg.UserClass{bcAlice},
		Chats: []tg.ChatClass{bcNews, bcTeam},
	}
}

func newFake() (*fakeMTProto, *tg.Client) {
	f := &fakeMTProto{
		dialogs:  bcDialogs(),
		channels: map[int64]tg.ChatClass{bcNewsID: bcNews, bcTeamID: bcTeam},
	}
	return f, tg.NewClient(f)
}

func historyHasChannel(f *fakeMTProto, id int64) bool {
	for _, p := range f.history {
		if ch, ok := p.(*tg.InputPeerChannel); ok && ch.ChannelID == id {
			return true
		}
	}
	return false
}

func TestRefuseBroadcastPeer(t *testing.T) {
	cases := []struct {
		name      string
		input     tg.InputPeerClass
		channels  map[int64]tg.ChatClass
		lookupErr error
		wantErr   bool
		wantBC    bool
		wantCall  bool
	}{
		{name: "user passes without a call", input: &tg.InputPeerUser{UserID: bcAliceID, AccessHash: 1}},
		{name: "self passes", input: &tg.InputPeerSelf{}},
		{name: "legacy group passes", input: &tg.InputPeerChat{ChatID: 5}},
		{name: "megagroup passes", input: &tg.InputPeerChannel{ChannelID: bcTeamID, AccessHash: 3},
			channels: map[int64]tg.ChatClass{bcTeamID: bcTeam}, wantCall: true},
		{name: "broadcast refused", input: &tg.InputPeerChannel{ChannelID: bcNewsID, AccessHash: 2},
			channels: map[int64]tg.ChatClass{bcNewsID: bcNews}, wantErr: true, wantBC: true, wantCall: true},
		{name: "channel absent from reply refused", input: &tg.InputPeerChannel{ChannelID: bcNewsID, AccessHash: 2},
			channels: map[int64]tg.ChatClass{}, wantErr: true, wantBC: true, wantCall: true},
		{name: "forbidden channel refused", input: &tg.InputPeerChannel{ChannelID: bcTeamID, AccessHash: 3},
			channels: map[int64]tg.ChatClass{bcTeamID: &tg.ChannelForbidden{ID: bcTeamID, Megagroup: true}}, wantErr: true, wantBC: true, wantCall: true},
		{name: "channel from message refused", input: &tg.InputPeerChannelFromMessage{ChannelID: bcNewsID},
			wantErr: true, wantBC: true},
		{name: "failed lookup is an error, not a pass and not a refusal",
			input:     &tg.InputPeerChannel{ChannelID: bcTeamID, AccessHash: 3},
			lookupErr: tgerr.New(500, "INTERNAL"), wantErr: true, wantCall: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeMTProto{channels: tc.channels, lookupErr: tc.lookupErr}
			err := refuseBroadcastPeer(context.Background(), tg.NewClient(f), "spec", tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if got := errors.Is(err, ErrBroadcastContent); got != tc.wantBC {
				t.Errorf("errors.Is(ErrBroadcastContent) = %v, want %v (err %v)", got, tc.wantBC, err)
			}
			if got := f.called("getChannels"); got != tc.wantCall {
				t.Errorf("getChannels called = %v, want %v", got, tc.wantCall)
			}
		})
	}
}

func TestBroadcastRefusalIsCallerRefusal(t *testing.T) {
	if !IsCallerRefusal(&broadcastContentError{peer: "channel:1"}) {
		t.Error("a broadcast refusal is this server's policy, not an outage")
	}
	if IsCallerRefusal(fmt.Errorf("check: %w", tgerr.New(500, "INTERNAL"))) {
		t.Error("a failed lookup must not count as a caller refusal")
	}
}

// Switch off (BROADCAST_CONTENT_ENABLED=false): the issue #851 refusal.

func TestGetUnread_SwitchOff_UnscopedSkipsBroadcastChannels(t *testing.T) {
	f, api := newFake()
	msgs, _, sp, err := getUnreadMessagesWith(context.Background(), api, "", 50, BroadcastContentRefused)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if historyHasChannel(f, bcNewsID) {
		t.Error("the broadcast channel's history was fetched")
	}
	if !historyHasChannel(f, bcTeamID) {
		t.Error("the megagroup's unread must still be read")
	}
	got := map[string]bool{}
	for _, m := range msgs {
		got[m.Peer] = true
	}
	for _, want := range []string{fmt.Sprintf("user:%d", bcAliceID), fmt.Sprintf("channel:%d", bcTeamID)} {
		if !got[want] {
			t.Errorf("missing unread from %s (got %v)", want, got)
		}
	}
	if got[fmt.Sprintf("channel:%d", bcNewsID)] {
		t.Error("returned a broadcast channel post")
	}
	if f.called("getSponsored") || len(sp.Messages) != 0 {
		t.Error("sponsored messages fetched although no channel post was read")
	}
}

func TestGetUnread_SwitchOff_ScopedToBroadcastRefused(t *testing.T) {
	for _, unread := range []int{40, 0} {
		f, api := newFake()
		f.dialogs.Dialogs[0].(*tg.Dialog).UnreadCount = unread
		_, _, _, err := getUnreadMessagesWith(context.Background(), api, fmt.Sprintf("channel:%d", bcNewsID), 50, BroadcastContentRefused)
		if !errors.Is(err, ErrBroadcastContent) {
			t.Errorf("unread=%d: err = %v, want ErrBroadcastContent", unread, err)
		}
		if f.called("getHistory") {
			t.Errorf("unread=%d: history fetched before refusing", unread)
		}
	}
}

func TestGetUnread_ScopedToMegagroupAllowed(t *testing.T) {
	for _, bc := range []BroadcastContent{BroadcastContentRefused, BroadcastContentAllowed} {
		f, api := newFake()
		msgs, _, _, err := getUnreadMessagesWith(context.Background(), api, fmt.Sprintf("channel:%d", bcTeamID), 50, bc)
		if err != nil || len(msgs) == 0 {
			t.Fatalf("bc=%v megagroup unread: msgs=%d err=%v", bc, len(msgs), err)
		}
		if f.called("getSponsored") {
			t.Errorf("bc=%v: sponsored messages fetched for a megagroup", bc)
		}
	}
}

func noResolve(context.Context) (tg.InputPeerClass, error) {
	return nil, errors.New("resolve must not be called")
}

func TestGetMessages_SwitchOff_BroadcastInDialogsRefused(t *testing.T) {
	f, api := newFake()
	_, _, _, _, err := getMessagesWith(context.Background(), api, noResolve, nil, fmt.Sprintf("channel:%d", bcNewsID), 20, 0, nil, 0, BroadcastContentRefused)
	if !errors.Is(err, ErrBroadcastContent) {
		t.Fatalf("err = %v, want ErrBroadcastContent", err)
	}
	if f.called("getHistory") {
		t.Error("history fetched before refusing")
	}
}

func TestGetMessages_MegagroupAndUserAllowed(t *testing.T) {
	for _, bc := range []BroadcastContent{BroadcastContentRefused, BroadcastContentAllowed} {
		for _, spec := range []string{fmt.Sprintf("channel:%d", bcTeamID), fmt.Sprintf("user:%d", bcAliceID)} {
			f, api := newFake()
			msgs, _, _, _, err := getMessagesWith(context.Background(), api, noResolve, nil, spec, 20, 0, nil, 0, bc)
			if err != nil || len(msgs) == 0 {
				t.Errorf("bc=%v %s: msgs=%d err=%v", bc, spec, len(msgs), err)
			}
			if f.called("getSponsored") {
				t.Errorf("bc=%v %s: sponsored messages fetched for a non-broadcast peer", bc, spec)
			}
		}
	}
}

func resolveTo(p tg.InputPeerClass) func(context.Context) (tg.InputPeerClass, error) {
	return func(context.Context) (tg.InputPeerClass, error) { return p, nil }
}

func TestGetMessages_SwitchOff_FallbackResolvedBroadcastRefused(t *testing.T) {
	f, api := newFake()
	f.dialogs = &tg.MessagesDialogs{} // not in the dialog list: direct resolution
	_, _, _, _, err := getMessagesWith(context.Background(), api, resolveTo(&tg.InputPeerChannel{ChannelID: bcNewsID, AccessHash: 2}), nil, "@news", 20, 0, nil, 0, BroadcastContentRefused)
	if !errors.Is(err, ErrBroadcastContent) {
		t.Fatalf("err = %v, want ErrBroadcastContent", err)
	}
	if f.called("getHistory") {
		t.Error("history fetched before refusing")
	}
}

func TestGetMessages_SwitchOff_ReResolvedBroadcastRefused(t *testing.T) {
	f, api := newFake()
	f.dialogs = &tg.MessagesDialogs{}
	f.historyErrOnce = tgerr.New(400, "CHANNEL_INVALID")
	_, _, _, _, err := getMessagesWith(context.Background(), api,
		resolveTo(&tg.InputPeerUser{UserID: bcAliceID, AccessHash: 1}),
		resolveTo(&tg.InputPeerChannel{ChannelID: bcNewsID, AccessHash: 2}),
		"@news", 20, 0, nil, 0, BroadcastContentRefused)
	if !errors.Is(err, ErrBroadcastContent) {
		t.Fatalf("err = %v, want ErrBroadcastContent", err)
	}
	if historyHasChannel(f, bcNewsID) {
		t.Error("history of the re-resolved broadcast channel fetched before refusing")
	}
}

func TestGetMessages_FallbackResolvedMegagroupAllowed(t *testing.T) {
	f, api := newFake()
	f.dialogs = &tg.MessagesDialogs{}
	f.historyChats = []tg.ChatClass{bcTeam}
	if _, _, _, _, err := getMessagesWith(context.Background(), api, resolveTo(&tg.InputPeerChannel{ChannelID: bcTeamID, AccessHash: 3}), nil, "@team", 20, 0, nil, 0, BroadcastContentRefused); err != nil {
		t.Fatalf("megagroup fallback: %v", err)
	}
	f, api = newFake()
	f.dialogs = &tg.MessagesDialogs{}
	f.historyChats = []tg.ChatClass{bcTeam}
	if _, _, _, _, err := getMessagesWith(context.Background(), api, resolveTo(&tg.InputPeerChannel{ChannelID: bcTeamID, AccessHash: 3}), nil, "@team", 20, 0, nil, 0, BroadcastContentAllowed); err != nil {
		t.Fatalf("megagroup fallback, switch on: %v", err)
	}
	if f.called("getSponsored") {
		t.Error("sponsored messages fetched for a megagroup the history reply shows")
	}
}

func TestPrepareMedia_SwitchOff_BroadcastRefused(t *testing.T) {
	f, api := newFake()
	_, _, err := prepareMediaRefWith(context.Background(), api, "channel:news", &tg.InputPeerChannel{ChannelID: bcNewsID, AccessHash: 2}, 7, BroadcastContentRefused)
	if !errors.Is(err, ErrBroadcastContent) {
		t.Fatalf("err = %v, want ErrBroadcastContent", err)
	}
	if f.called("channelGetMessages") {
		t.Error("message fetched before refusing")
	}
}

func TestPrepareMedia_MegagroupReachesFetch(t *testing.T) {
	f, api := newFake()
	_, _, err := prepareMediaRefWith(context.Background(), api, "channel:team", &tg.InputPeerChannel{ChannelID: bcTeamID, AccessHash: 3}, 7, BroadcastContentRefused)
	if errors.Is(err, ErrBroadcastContent) {
		t.Fatalf("megagroup refused: %v", err)
	}
	if !f.called("channelGetMessages") {
		t.Error("megagroup message was not fetched")
	}
}

// Switch on (the default): channel posts are read, with their sponsored
// messages.

// twoAds is a sponsored reply with two items and no posts_between, so only
// the first may be shown.
func twoAds() *tg.MessagesSponsoredMessages {
	return &tg.MessagesSponsoredMessages{Messages: []tg.SponsoredMessage{
		{RandomID: []byte{0xa1, 0xa2}, Title: "Ad one", Message: "Buy one", URL: "https://example.test/one", ButtonText: "Open"},
		{RandomID: []byte{0xb1, 0xb2}, Title: "Ad two", Message: "Buy two", URL: "https://example.test/two", Recommended: true},
	}}
}

func TestPrepareMedia_SwitchOn_BroadcastReachesFetch(t *testing.T) {
	f, api := newFake()
	_, _, err := prepareMediaRefWith(context.Background(), api, "channel:news", &tg.InputPeerChannel{ChannelID: bcNewsID, AccessHash: 2}, 7, BroadcastContentAllowed)
	if errors.Is(err, ErrBroadcastContent) {
		t.Fatalf("broadcast media refused with the switch on: %v", err)
	}
	if !f.called("channelGetMessages") {
		t.Error("broadcast message was not fetched")
	}
	if f.called("getChannels") || f.called("getSponsored") {
		t.Errorf("unexpected calls for a single media item: %v", f.calls)
	}
}

func TestGetMessages_SwitchOn_BroadcastReturnedWithSponsored(t *testing.T) {
	f, api := newFake()
	f.sponsored = twoAds()
	spec := fmt.Sprintf("channel:%d", bcNewsID)
	msgs, _, _, sp, err := getMessagesWith(context.Background(), api, noResolve, nil, spec, 20, 0, nil, 0, BroadcastContentAllowed)
	if err != nil {
		t.Fatalf("err = %v, want channel posts", err)
	}
	if len(msgs) == 0 || !historyHasChannel(f, bcNewsID) {
		t.Fatalf("channel posts not returned: msgs=%d calls=%v", len(msgs), f.calls)
	}
	for _, m := range msgs {
		if m.Peer != spec || m.Text != "hi" {
			t.Errorf("messages hold something other than the channel's posts: %+v", m)
		}
	}
	if len(f.sponsoredFor) != 1 || peerOf(f.sponsoredFor[0]).(*tg.PeerChannel).ChannelID != bcNewsID {
		t.Fatalf("getSponsoredMessages peers = %v, want the channel once", f.sponsoredFor)
	}
	if len(sp.Messages) != 1 {
		t.Fatalf("sponsored = %+v, want the one item allowed without posts_between", sp.Messages)
	}
	ad := sp.Messages[0]
	if ad.Label != SponsoredLabel || ad.Channel != spec || ad.Title != "Ad one" || ad.Text != "Buy one" ||
		ad.URL != "https://example.test/one" || ad.ButtonText != "Open" || ad.RandomID != "oaI=" {
		t.Errorf("sponsored item = %+v", ad)
	}
	if len(sp.Unavailable) != 0 {
		t.Errorf("unavailable = %v, want none", sp.Unavailable)
	}
}

func TestGetMessages_SwitchOn_FallbackBroadcastReturnedWithSponsored(t *testing.T) {
	f, api := newFake()
	f.dialogs = &tg.MessagesDialogs{}
	f.historyChats = []tg.ChatClass{bcNews}
	f.sponsored = twoAds()
	msgs, _, _, sp, err := getMessagesWith(context.Background(), api, resolveTo(&tg.InputPeerChannel{ChannelID: bcNewsID, AccessHash: 2}), nil, "@news", 20, 0, nil, 0, BroadcastContentAllowed)
	if err != nil || len(msgs) == 0 {
		t.Fatalf("fallback broadcast: msgs=%d err=%v", len(msgs), err)
	}
	if f.called("getChannels") {
		t.Error("the refusal lookup ran with the switch on")
	}
	if len(sp.Messages) != 1 || sp.Messages[0].Channel != fmt.Sprintf("channel:%d", bcNewsID) {
		t.Errorf("sponsored = %+v, want one item for the channel", sp.Messages)
	}
}

func TestGetMessages_SwitchOn_ReResolvedBroadcastReturnedWithSponsored(t *testing.T) {
	f, api := newFake()
	f.dialogs = &tg.MessagesDialogs{}
	f.historyChats = []tg.ChatClass{bcNews}
	f.historyErrOnce = tgerr.New(400, "CHANNEL_INVALID")
	f.sponsored = twoAds()
	msgs, _, _, sp, err := getMessagesWith(context.Background(), api,
		resolveTo(&tg.InputPeerChannel{ChannelID: bcNewsID, AccessHash: 9}),
		resolveTo(&tg.InputPeerChannel{ChannelID: bcNewsID, AccessHash: 2}),
		"@news", 20, 0, nil, 0, BroadcastContentAllowed)
	if err != nil || len(msgs) == 0 {
		t.Fatalf("re-resolved broadcast: msgs=%d err=%v", len(msgs), err)
	}
	if len(sp.Messages) != 1 {
		t.Errorf("sponsored = %+v, want one item", sp.Messages)
	}
}

func TestGetMessages_SwitchOn_EmptyPageFetchesNoSponsored(t *testing.T) {
	f, api := newFake()
	f.emptyHistory = true
	f.sponsored = twoAds()
	_, _, _, sp, err := getMessagesWith(context.Background(), api, noResolve, nil, fmt.Sprintf("channel:%d", bcNewsID), 20, 0, nil, 0, BroadcastContentAllowed)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if f.called("getSponsored") || len(sp.Messages) != 0 {
		t.Errorf("sponsored messages fetched for a page with no posts: calls=%v", f.calls)
	}
}

func TestGetMessages_SwitchOn_FailedSponsoredFetchIsUnknownNotNone(t *testing.T) {
	f, api := newFake()
	f.sponsoredErr = tgerr.New(500, "INTERNAL")
	spec := fmt.Sprintf("channel:%d", bcNewsID)
	msgs, _, _, sp, err := getMessagesWith(context.Background(), api, noResolve, nil, spec, 20, 0, nil, 0, BroadcastContentAllowed)
	if err != nil {
		t.Fatalf("a failed ad fetch must not fail the read: %v", err)
	}
	if len(msgs) == 0 {
		t.Error("channel posts dropped because ads could not be fetched")
	}
	if len(sp.Unavailable) != 1 || sp.Unavailable[0] != spec {
		t.Errorf("unavailable = %v, want [%s]", sp.Unavailable, spec)
	}
	if len(sp.Messages) != 0 {
		t.Errorf("sponsored = %+v, want none", sp.Messages)
	}
}

func TestGetMessages_SwitchOn_EmptySponsoredReplyIsNoneNotUnknown(t *testing.T) {
	_, api := newFake() // f.sponsored nil: messages.sponsoredMessagesEmpty
	_, _, _, sp, err := getMessagesWith(context.Background(), api, noResolve, nil, fmt.Sprintf("channel:%d", bcNewsID), 20, 0, nil, 0, BroadcastContentAllowed)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(sp.Messages) != 0 || len(sp.Unavailable) != 0 {
		t.Errorf("sponsored = %+v, unavailable = %v; want both empty", sp.Messages, sp.Unavailable)
	}
}

func TestFetchSponsored_PostsBetweenBoundsTheItems(t *testing.T) {
	for _, tc := range []struct {
		postsBetween, shown, want int
	}{
		{0, 3, 1}, // one item after all posts
		{2, 1, 1}, // at least one when any post is shown
		{2, 4, 2},
		{1, 5, 2}, // never more than Telegram served
	} {
		f := &fakeMTProto{sponsored: func() *tg.MessagesSponsoredMessages {
			r := twoAds()
			r.PostsBetween = tc.postsBetween
			return r
		}()}
		sp := &Sponsored{}
		fetchSponsored(context.Background(), tg.NewClient(f), bcNewsID, &tg.InputPeerChannel{ChannelID: bcNewsID}, tc.shown, sp)
		if len(sp.Messages) != tc.want {
			t.Errorf("posts_between=%d shown=%d: kept %d, want %d", tc.postsBetween, tc.shown, len(sp.Messages), tc.want)
		}
	}
}

func TestReportSponsoredViews_OnlyReturnedItems(t *testing.T) {
	f, api := newFake()
	f.sponsored = twoAds()
	_, _, _, sp, err := getMessagesWith(context.Background(), api, noResolve, nil, fmt.Sprintf("channel:%d", bcNewsID), 20, 0, nil, 0, BroadcastContentAllowed)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if failed := reportSponsoredViewsWith(context.Background(), api, sp.Messages); len(failed) != 0 {
		t.Fatalf("failed = %+v", failed)
	}
	if len(f.viewed) != 1 || string(f.viewed[0]) != string([]byte{0xa1, 0xa2}) {
		t.Errorf("viewed = %x, want only the returned item a1a2, once", f.viewed)
	}

	f.viewed = nil
	reportSponsoredViewsWith(context.Background(), api, nil)
	if len(f.viewed) != 0 {
		t.Errorf("views reported with nothing returned: %x", f.viewed)
	}
}

func TestReportSponsoredViews_FailureCounted(t *testing.T) {
	f, api := newFake()
	f.viewErr = tgerr.New(500, "INTERNAL")
	msgs := []SponsoredMessage{{Channel: "channel:1", randomID: []byte{1}}, {Channel: "channel:1", randomID: []byte{2}}}
	if failed := reportSponsoredViewsWith(context.Background(), api, msgs); len(failed) != 2 {
		t.Errorf("failed = %d items, want 2", len(failed))
	}
}

func TestGetUnread_SwitchOn_UnscopedIncludesChannelsLast(t *testing.T) {
	f, api := newFake()
	f.sponsored = twoAds()
	msgs, _, sp, err := getUnreadMessagesWith(context.Background(), api, "", 50, BroadcastContentAllowed)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// News comes first in the dialog list but is read last.
	if len(f.history) != 3 {
		t.Fatalf("history calls = %d, want 3", len(f.history))
	}
	if ch, ok := f.history[2].(*tg.InputPeerChannel); !ok || ch.ChannelID != bcNewsID {
		t.Errorf("last history call = %v, want the broadcast channel", f.history[2])
	}
	var news int
	for _, m := range msgs {
		if m.Peer == fmt.Sprintf("channel:%d", bcNewsID) {
			news++
		}
	}
	if news == 0 {
		t.Error("unscoped unread dropped the broadcast channel's posts")
	}
	if len(f.sponsoredFor) != 1 || len(sp.Messages) != 1 || sp.Messages[0].Channel != fmt.Sprintf("channel:%d", bcNewsID) {
		t.Errorf("sponsored = %+v (fetched for %v), want one item for the channel", sp.Messages, f.sponsoredFor)
	}
}

func TestGetUnread_SwitchOn_ScopedToBroadcastReturned(t *testing.T) {
	f, api := newFake()
	msgs, _, _, err := getUnreadMessagesWith(context.Background(), api, fmt.Sprintf("channel:%d", bcNewsID), 50, BroadcastContentAllowed)
	if err != nil || len(msgs) == 0 {
		t.Fatalf("scoped broadcast unread: msgs=%d err=%v", len(msgs), err)
	}
	if !f.called("getSponsored") {
		t.Error("sponsored messages not fetched for returned channel posts")
	}
}

func TestFetchSponsored_RecommendedItemIsLabelledRecommended(t *testing.T) {
	r := twoAds()
	r.PostsBetween = 1
	f := &fakeMTProto{sponsored: r}
	sp := &Sponsored{}
	fetchSponsored(context.Background(), tg.NewClient(f), bcNewsID, &tg.InputPeerChannel{ChannelID: bcNewsID}, 2, sp)
	if len(sp.Messages) != 2 {
		t.Fatalf("kept %d items, want 2", len(sp.Messages))
	}
	if sp.Messages[0].Label != SponsoredLabel || sp.Messages[1].Label != RecommendedLabel {
		t.Errorf("labels = %q, %q; want %q, %q", sp.Messages[0].Label, sp.Messages[1].Label, SponsoredLabel, RecommendedLabel)
	}
}

// Twelve broadcast channels with unread posts: an unscoped read asks for the
// ads of the first maxSponsoredChannelsPerCall only, and lists the rest as
// unavailable rather than ad-free (issue #906).
func TestGetUnread_SponsoredFetchesCappedPerCall(t *testing.T) {
	const n = maxSponsoredChannelsPerCall + 2
	dl := &tg.MessagesDialogs{}
	for i := 0; i < n; i++ {
		id := int64(700100001 + i)
		dl.Dialogs = append(dl.Dialogs, &tg.Dialog{Peer: &tg.PeerChannel{ChannelID: id}, UnreadCount: 1})
		dl.Chats = append(dl.Chats, &tg.Channel{ID: id, AccessHash: id, Title: "Channel", Broadcast: true, Photo: &tg.ChatPhotoEmpty{}})
	}
	f := &fakeMTProto{dialogs: dl, sponsored: twoAds()}
	msgs, _, sp, err := getUnreadMessagesWith(context.Background(), tg.NewClient(f), "", 50, BroadcastContentAllowed)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(msgs) != n {
		t.Errorf("posts = %d, want one from each of the %d channels", len(msgs), n)
	}
	if len(f.sponsoredFor) != maxSponsoredChannelsPerCall {
		t.Errorf("getSponsoredMessages calls = %d, want the cap %d", len(f.sponsoredFor), maxSponsoredChannelsPerCall)
	}
	if len(sp.Messages) != maxSponsoredChannelsPerCall {
		t.Errorf("sponsored items = %d, want one per queried channel", len(sp.Messages))
	}
	want := []string{fmt.Sprintf("channel:%d", 700100001+n-2), fmt.Sprintf("channel:%d", 700100001+n-1)}
	if fmt.Sprint(sp.Unavailable) != fmt.Sprint(want) {
		t.Errorf("unavailable = %v, want the channels past the cap %v", sp.Unavailable, want)
	}
}

func TestBroadcastContentError_NoRetryGuidance(t *testing.T) {
	err := error(&broadcastContentError{peer: "channel:1"})
	if !errors.Is(err, ErrBroadcastContent) {
		t.Fatal("errors.Is(ErrBroadcastContent) must hold")
	}
	for _, want := range []string{"Retrying will not change that", "get_unread_messages without peer", "list_dialogs"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal text missing %q: %s", want, err)
		}
	}
}
