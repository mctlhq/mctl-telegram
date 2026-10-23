package telegram

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

// Synthetic ids for issue #851: Alice is a private chat, News a broadcast
// channel, Team a megagroup.
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
		res = &tg.MessagesMessages{Messages: []tg.MessageClass{&tg.Message{ID: 1, Message: "hi", PeerID: peerOf(req.Peer)}}}
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

func TestGetUnread_UnscopedSkipsBroadcastChannels(t *testing.T) {
	f, api := newFake()
	msgs, _, err := getUnreadMessagesWith(context.Background(), api, "", 50)
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
}

func TestGetUnread_ScopedToBroadcastRefused(t *testing.T) {
	for _, unread := range []int{40, 0} {
		f, api := newFake()
		f.dialogs.Dialogs[0].(*tg.Dialog).UnreadCount = unread
		_, _, err := getUnreadMessagesWith(context.Background(), api, fmt.Sprintf("channel:%d", bcNewsID), 50)
		if !errors.Is(err, ErrBroadcastContent) {
			t.Errorf("unread=%d: err = %v, want ErrBroadcastContent", unread, err)
		}
		if f.called("getHistory") {
			t.Errorf("unread=%d: history fetched before refusing", unread)
		}
	}
}

func TestGetUnread_ScopedToMegagroupAllowed(t *testing.T) {
	_, api := newFake()
	msgs, _, err := getUnreadMessagesWith(context.Background(), api, fmt.Sprintf("channel:%d", bcTeamID), 50)
	if err != nil || len(msgs) == 0 {
		t.Fatalf("megagroup unread: msgs=%d err=%v", len(msgs), err)
	}
}

func noResolve(context.Context) (tg.InputPeerClass, error) {
	return nil, errors.New("resolve must not be called")
}

func TestGetMessages_BroadcastInDialogsRefused(t *testing.T) {
	f, api := newFake()
	_, _, _, err := getMessagesWith(context.Background(), api, noResolve, nil, fmt.Sprintf("channel:%d", bcNewsID), 20, 0, nil, 0)
	if !errors.Is(err, ErrBroadcastContent) {
		t.Fatalf("err = %v, want ErrBroadcastContent", err)
	}
	if f.called("getHistory") {
		t.Error("history fetched before refusing")
	}
}

func TestGetMessages_MegagroupAndUserAllowed(t *testing.T) {
	for _, spec := range []string{fmt.Sprintf("channel:%d", bcTeamID), fmt.Sprintf("user:%d", bcAliceID)} {
		_, api := newFake()
		msgs, _, _, err := getMessagesWith(context.Background(), api, noResolve, nil, spec, 20, 0, nil, 0)
		if err != nil || len(msgs) == 0 {
			t.Errorf("%s: msgs=%d err=%v", spec, len(msgs), err)
		}
	}
}

func TestGetMessages_FallbackResolvedBroadcastRefused(t *testing.T) {
	f, api := newFake()
	f.dialogs = &tg.MessagesDialogs{} // not in the dialog list: direct resolution
	resolve := func(context.Context) (tg.InputPeerClass, error) {
		return &tg.InputPeerChannel{ChannelID: bcNewsID, AccessHash: 2}, nil
	}
	_, _, _, err := getMessagesWith(context.Background(), api, resolve, nil, "@news", 20, 0, nil, 0)
	if !errors.Is(err, ErrBroadcastContent) {
		t.Fatalf("err = %v, want ErrBroadcastContent", err)
	}
	if f.called("getHistory") {
		t.Error("history fetched before refusing")
	}
}

func TestGetMessages_FallbackResolvedMegagroupAllowed(t *testing.T) {
	f, api := newFake()
	f.dialogs = &tg.MessagesDialogs{}
	resolve := func(context.Context) (tg.InputPeerClass, error) {
		return &tg.InputPeerChannel{ChannelID: bcTeamID, AccessHash: 3}, nil
	}
	if _, _, _, err := getMessagesWith(context.Background(), api, resolve, nil, "@team", 20, 0, nil, 0); err != nil {
		t.Fatalf("megagroup fallback: %v", err)
	}
}

func TestPrepareMedia_BroadcastRefused(t *testing.T) {
	f, api := newFake()
	_, _, err := prepareMediaRefWith(context.Background(), api, "channel:news", &tg.InputPeerChannel{ChannelID: bcNewsID, AccessHash: 2}, 7)
	if !errors.Is(err, ErrBroadcastContent) {
		t.Fatalf("err = %v, want ErrBroadcastContent", err)
	}
	if f.called("channelGetMessages") {
		t.Error("message fetched before refusing")
	}
}

func TestPrepareMedia_MegagroupReachesFetch(t *testing.T) {
	f, api := newFake()
	_, _, err := prepareMediaRefWith(context.Background(), api, "channel:team", &tg.InputPeerChannel{ChannelID: bcTeamID, AccessHash: 3}, 7)
	if errors.Is(err, ErrBroadcastContent) {
		t.Fatalf("megagroup refused: %v", err)
	}
	if !f.called("channelGetMessages") {
		t.Error("megagroup message was not fetched")
	}
}
