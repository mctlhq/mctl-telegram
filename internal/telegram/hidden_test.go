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

// The get_messages dialog scan matches by username without ResolvePeer, so
// it refuses a hidden chat itself, before any history RPC.
func TestGetMessagesFromDialogs_HiddenChatRefused(t *testing.T) {
	f, api := newFake()
	ref := fmt.Sprintf("channel:%d", bcTeamID)
	_, _, _, _, matched, err := getMessagesFromDialogs(hiddenCtx(ref), api, f.dialogs, ref, 20, 0, nil, 0, BroadcastContentAllowed, &Sponsored{})
	if !errors.Is(err, ErrPeerHidden) || !matched {
		t.Fatalf("err = %v matched = %v, want ErrPeerHidden", err, matched)
	}
	if f.called("getHistory") {
		t.Error("history fetched for a hidden chat")
	}
}

// Hidden hits must not shrink the page: Telegram is asked for more and the
// visible result is trimmed back to the limit.
func TestSearchGlobal_HiddenHitsKeepPageSize(t *testing.T) {
	f := &fakeSearchInvoker{result: globalSearchMixedResult(), broadcastIDs: map[int64]bool{}}
	ctx := hiddenCtx("user:8511")
	msgs, err := searchGlobalWith(ctx, f, SearchParams{Query: "q", Limit: 2, BroadcastContent: BroadcastContentAllowed})
	if err != nil {
		t.Fatal(err)
	}
	if f.lastGlobal.Limit != 3 {
		t.Errorf("asked Telegram for %d, want 3", f.lastGlobal.Limit)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	for _, m := range msgs {
		if m.Peer == "user:8511" {
			t.Fatal("hidden hit returned")
		}
	}
}

// A hidden chat with no hit in this page still widens the request; the
// result is trimmed back to the asked size.
func TestSearchGlobal_WidenedPageTrimmedToLimit(t *testing.T) {
	f := &fakeSearchInvoker{result: globalSearchMixedResult(), broadcastIDs: map[int64]bool{}}
	msgs, err := searchGlobalWith(hiddenCtx("user:9999"), f, SearchParams{Query: "q", Limit: 2, BroadcastContent: BroadcastContentAllowed})
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
}

func TestWidenForHidden(t *testing.T) {
	if got := widenForHidden(context.Background(), 50, 200); got != 50 {
		t.Errorf("nothing hidden = %d", got)
	}
	if got := widenForHidden(hiddenCtx("user:1", "user:2"), 50, 200); got != 52 {
		t.Errorf("two hidden = %d", got)
	}
	if got := widenForHidden(hiddenCtx("user:1", "user:2"), 199, 200); got != 200 {
		t.Errorf("cap = %d", got)
	}
}
