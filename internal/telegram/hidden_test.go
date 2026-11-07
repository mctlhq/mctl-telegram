package telegram

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/gotd/td/tg"
)

func hiddenCtx(refs ...string) context.Context {
	set := HiddenPeers{}
	for _, r := range refs {
		set[r] = true
	}
	return WithHiddenPeers(context.Background(), set)
}

func TestDropHidden(t *testing.T) {
	ctx := hiddenCtx("chat:2")
	ds := dropHiddenDialogs(ctx, []Dialog{{ID: "user:1"}, {ID: "chat:2"}, {ID: "channel:3"}})
	if len(ds) != 2 || ds[0].ID != "user:1" || ds[1].ID != "channel:3" {
		t.Fatalf("dialogs = %+v", ds)
	}
	ms := dropHiddenMessages(ctx, []Message{{Peer: "chat:2"}, {Peer: "user:1"}})
	if len(ms) != 1 || ms[0].Peer != "user:1" {
		t.Fatalf("messages = %+v", ms)
	}
	// No set on ctx hides nothing.
	if ds := dropHiddenDialogs(context.Background(), []Dialog{{ID: "chat:2"}}); len(ds) != 1 {
		t.Fatal("an empty context dropped a dialog")
	}
}

func TestInputPeerRef(t *testing.T) {
	for _, tc := range []struct {
		in   tg.InputPeerClass
		want string
	}{
		{&tg.InputPeerUser{UserID: 5}, "user:5"},
		{&tg.InputPeerChat{ChatID: 6}, "chat:6"},
		{&tg.InputPeerChannel{ChannelID: 7}, "channel:7"},
		{&tg.InputPeerUserFromMessage{UserID: 8}, "user:8"},
		{&tg.InputPeerChannelFromMessage{ChannelID: 9}, "channel:9"},
		{&tg.InputPeerSelf{}, ""},
	} {
		if got := inputPeerRef(tc.in); got != tc.want {
			t.Errorf("%T = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A resolution cached before the chat was hidden is refused all the same.
func TestResolvePeerCached_HiddenAfterCaching(t *testing.T) {
	cache := NewPeerCache()
	cache.Set(1, "@bob_news", &tg.InputPeerChannel{ChannelID: 42, AccessHash: 1})
	if _, err := ResolvePeerCached(hiddenCtx("channel:42"), nil, "@bob_news", cache, 1); !errors.Is(err, ErrPeerHidden) {
		t.Fatalf("cached hidden peer = %v, want ErrPeerHidden", err)
	}
	if p, err := ResolvePeerCached(hiddenCtx("channel:43"), nil, "@bob_news", cache, 1); err != nil || p == nil {
		t.Fatalf("visible cached peer = %v, %v", p, err)
	}
}

func TestGetUnread_HiddenChatSkippedInScan(t *testing.T) {
	f, api := newFake()
	ctx := hiddenCtx(fmt.Sprintf("channel:%d", bcTeamID))
	msgs, _, _, err := getUnreadMessagesWith(ctx, api, "", 50, BroadcastContentAllowed)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if historyHasChannel(f, bcTeamID) {
		t.Error("the hidden chat's history was fetched")
	}
	for _, m := range msgs {
		if m.Peer == fmt.Sprintf("channel:%d", bcTeamID) {
			t.Fatal("a hidden chat's unread was returned")
		}
	}
	if len(msgs) == 0 {
		t.Error("visible chats lost their unread too")
	}
}

func TestGetUnread_HiddenChatNamedIsRefused(t *testing.T) {
	f, api := newFake()
	ref := fmt.Sprintf("channel:%d", bcTeamID)
	_, _, _, err := getUnreadMessagesWith(hiddenCtx(ref), api, ref, 50, BroadcastContentAllowed)
	if !errors.Is(err, ErrPeerHidden) {
		t.Fatalf("err = %v, want ErrPeerHidden", err)
	}
	if f.called("getHistory") {
		t.Error("history fetched before refusing")
	}
}
