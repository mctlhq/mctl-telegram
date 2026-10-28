package telegram

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/tg"
)

// fakeSearchInvoker implements searchInvoker and records the last request it
// was asked to send, so tests can assert on the constructed MTProto request
// without a live client.
type fakeSearchInvoker struct {
	lastGlobal *tg.MessagesSearchGlobalRequest
	lastPeer   *tg.MessagesSearchRequest
	result     *tg.MessagesMessages
	// broadcastIDs are the channels ChannelsGetChannels reports as broadcast.
	broadcastIDs map[int64]bool
	lookups      int
}

func (f *fakeSearchInvoker) MessagesSearchGlobal(_ context.Context, req *tg.MessagesSearchGlobalRequest) (tg.MessagesMessagesClass, error) {
	f.lastGlobal = req
	return f.result, nil
}

func (f *fakeSearchInvoker) MessagesSearch(_ context.Context, req *tg.MessagesSearchRequest) (tg.MessagesMessagesClass, error) {
	f.lastPeer = req
	return f.result, nil
}

// ChannelsGetChannels reports every channel as a megagroup unless
// broadcastIDs lists it, so the existing per-peer tests keep searching.
func (f *fakeSearchInvoker) ChannelsGetChannels(_ context.Context, id []tg.InputChannelClass) (tg.MessagesChatsClass, error) {
	f.lookups++
	out := &tg.MessagesChats{}
	for _, ic := range id {
		chID := ic.(*tg.InputChannel).ChannelID
		out.Chats = append(out.Chats, &tg.Channel{ID: chID, Megagroup: !f.broadcastIDs[chID], Broadcast: f.broadcastIDs[chID]})
	}
	return out, nil
}

func fakeSearchResult() *tg.MessagesMessages {
	return &tg.MessagesMessages{
		Messages: []tg.MessageClass{
			&tg.Message{ID: 1, Message: "hello"},
		},
	}
}

// T1: bounded search sets MinDate/MaxDate to the resolved Unix seconds and
// leaves every other field as before.
func TestSearchGlobalWith_SetsDateBounds(t *testing.T) {
	fake := &fakeSearchInvoker{result: fakeSearchResult()}
	minDate := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	maxDate := time.Date(2026, 9, 27, 23, 59, 59, 0, time.UTC)

	if _, err := searchGlobalWith(context.Background(), fake, SearchParams{
		Query:   "roof rack",
		Limit:   20,
		MinDate: minDate,
		MaxDate: maxDate,
	}); err != nil {
		t.Fatalf("searchGlobalWith: %v", err)
	}

	req := fake.lastGlobal
	if req == nil {
		t.Fatal("MessagesSearchGlobal was not called")
	}
	if want := int(minDate.Unix()) - 1; req.MinDate != want {
		t.Errorf("MinDate = %d, want %d", req.MinDate, want)
	}
	if want := int(maxDate.Unix()) + 1; req.MaxDate != want {
		t.Errorf("MaxDate = %d, want %d", req.MaxDate, want)
	}
	if req.Q != "roof rack" {
		t.Errorf("Q = %q, want %q", req.Q, "roof rack")
	}
	if _, ok := req.Filter.(*tg.InputMessagesFilterEmpty); !ok {
		t.Errorf("Filter = %T, want *tg.InputMessagesFilterEmpty", req.Filter)
	}
	if _, ok := req.OffsetPeer.(*tg.InputPeerEmpty); !ok {
		t.Errorf("OffsetPeer = %T, want *tg.InputPeerEmpty", req.OffsetPeer)
	}
	if req.Limit != 20 {
		t.Errorf("Limit = %d, want 20", req.Limit)
	}
}

func TestSearchPeerWith_SetsDateBounds(t *testing.T) {
	fake := &fakeSearchInvoker{result: fakeSearchResult()}
	minDate := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	maxDate := time.Date(2026, 9, 27, 23, 59, 59, 0, time.UTC)
	peer := &tg.InputPeerUser{UserID: 100, AccessHash: 1}

	if _, err := searchPeerWith(context.Background(), fake, peer, SearchParams{
		Peer:    "user:100",
		Query:   "roof rack",
		Limit:   20,
		MinDate: minDate,
		MaxDate: maxDate,
	}); err != nil {
		t.Fatalf("searchPeerWith: %v", err)
	}

	req := fake.lastPeer
	if req == nil {
		t.Fatal("MessagesSearch was not called")
	}
	if want := int(minDate.Unix()) - 1; req.MinDate != want {
		t.Errorf("MinDate = %d, want %d", req.MinDate, want)
	}
	if want := int(maxDate.Unix()) + 1; req.MaxDate != want {
		t.Errorf("MaxDate = %d, want %d", req.MaxDate, want)
	}
	if req.Peer != peer {
		t.Errorf("Peer = %v, want %v", req.Peer, peer)
	}
	if req.Q != "roof rack" {
		t.Errorf("Q = %q, want %q", req.Q, "roof rack")
	}
	if _, ok := req.Filter.(*tg.InputMessagesFilterEmpty); !ok {
		t.Errorf("Filter = %T, want *tg.InputMessagesFilterEmpty", req.Filter)
	}
	if req.Limit != 20 {
		t.Errorf("Limit = %d, want 20", req.Limit)
	}
}

// T2: with no date bounds, the encoded request bytes must be identical to
// those produced by the pre-change code (Q, Filter, OffsetPeer/Peer, Limit
// only — MinDate/MaxDate both zero).
func TestSearchGlobalWith_UnboundedEncodingUnchanged(t *testing.T) {
	fake := &fakeSearchInvoker{result: fakeSearchResult()}
	if _, err := searchGlobalWith(context.Background(), fake, SearchParams{
		Query: "roof rack",
		Limit: 20,
	}); err != nil {
		t.Fatalf("searchGlobalWith: %v", err)
	}

	got := &bin.Buffer{}
	if err := fake.lastGlobal.Encode(got); err != nil {
		t.Fatalf("encode captured request: %v", err)
	}

	want := &bin.Buffer{}
	wantReq := &tg.MessagesSearchGlobalRequest{
		Q:          "roof rack",
		Filter:     &tg.InputMessagesFilterEmpty{},
		OffsetPeer: &tg.InputPeerEmpty{},
		Limit:      20,
	}
	if err := wantReq.Encode(want); err != nil {
		t.Fatalf("encode reference request: %v", err)
	}

	if !bytes.Equal(got.Buf, want.Buf) {
		t.Errorf("encoded bytes differ:\n got  = %x\n want = %x", got.Buf, want.Buf)
	}
}

func TestSearchPeerWith_UnboundedEncodingUnchanged(t *testing.T) {
	fake := &fakeSearchInvoker{result: fakeSearchResult()}
	peer := &tg.InputPeerUser{UserID: 100, AccessHash: 1}
	if _, err := searchPeerWith(context.Background(), fake, peer, SearchParams{
		Peer:  "user:100",
		Query: "roof rack",
		Limit: 20,
	}); err != nil {
		t.Fatalf("searchPeerWith: %v", err)
	}

	got := &bin.Buffer{}
	if err := fake.lastPeer.Encode(got); err != nil {
		t.Fatalf("encode captured request: %v", err)
	}

	want := &bin.Buffer{}
	wantReq := &tg.MessagesSearchRequest{
		Peer:   peer,
		Q:      "roof rack",
		Filter: &tg.InputMessagesFilterEmpty{},
		Limit:  20,
	}
	if err := wantReq.Encode(want); err != nil {
		t.Fatalf("encode reference request: %v", err)
	}

	if !bytes.Equal(got.Buf, want.Buf) {
		t.Errorf("encoded bytes differ:\n got  = %x\n want = %x", got.Buf, want.Buf)
	}
}

func TestMinDateUnix(t *testing.T) {
	if got := minDateUnix(time.Time{}); got != 0 {
		t.Errorf("minDateUnix(zero) = %d, want 0", got)
	}
	tm := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	if got, want := minDateUnix(tm), int(tm.Unix())-1; got != want {
		t.Errorf("minDateUnix(%v) = %d, want %d", tm, got, want)
	}
}

func TestMaxDateUnix(t *testing.T) {
	if got := maxDateUnix(time.Time{}); got != 0 {
		t.Errorf("maxDateUnix(zero) = %d, want 0", got)
	}
	tm := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
	if got, want := maxDateUnix(tm), int(tm.Unix())+1; got != want {
		t.Errorf("maxDateUnix(%v) = %d, want %d", tm, got, want)
	}
}

func TestCheckSearchBound(t *testing.T) {
	for _, tc := range []struct {
		name    string
		t       time.Time
		wantErr bool
	}{
		{"zero is unbounded", time.Time{}, false},
		{"epoch would go negative after -1", time.Unix(0, 0), true},
		{"one second after epoch", time.Unix(1, 0), false},
		{"int32 edge would wrap after +1", time.Unix(math.MaxInt32, 0), true},
		{"one second below int32 edge", time.Unix(math.MaxInt32-1, 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkSearchBound("MaxDate", tc.t); (err != nil) != tc.wantErr {
				t.Fatalf("checkSearchBound(%v) err = %v, wantErr %v", tc.t, err, tc.wantErr)
			}
		})
	}
}

func TestSearchPeer_SwitchOff_BroadcastRefusedBeforeSearching(t *testing.T) {
	f := &fakeSearchInvoker{result: fakeSearchResult(), broadcastIDs: map[int64]bool{8521: true}}
	_, err := searchPeerWith(context.Background(), f, &tg.InputPeerChannel{ChannelID: 8521, AccessHash: 2}, SearchParams{Peer: "channel:8521", Query: "q", Limit: 10})
	if !errors.Is(err, ErrBroadcastContent) {
		t.Fatalf("err = %v, want ErrBroadcastContent", err)
	}
	if f.lastPeer != nil {
		t.Error("messages.search was sent for a broadcast channel")
	}
}

func TestSearchPeer_MegagroupSearched(t *testing.T) {
	f := &fakeSearchInvoker{result: fakeSearchResult()}
	if _, err := searchPeerWith(context.Background(), f, &tg.InputPeerChannel{ChannelID: 8522, AccessHash: 3}, SearchParams{Peer: "channel:8522", Query: "q", Limit: 10}); err != nil {
		t.Fatalf("megagroup search: %v", err)
	}
	if f.lastPeer == nil {
		t.Error("megagroup was not searched")
	}
}

func TestSearchPeer_SwitchOn_BroadcastSearched(t *testing.T) {
	f := &fakeSearchInvoker{result: fakeSearchResult(), broadcastIDs: map[int64]bool{8521: true}}
	_, err := searchPeerWith(context.Background(), f, &tg.InputPeerChannel{ChannelID: 8521, AccessHash: 2}, SearchParams{Peer: "channel:8521", Query: "q", Limit: 10, BroadcastContent: BroadcastContentAllowed})
	if err != nil {
		t.Fatalf("broadcast search with the switch on: %v", err)
	}
	if f.lastPeer == nil {
		t.Error("messages.search was not sent for the broadcast channel")
	}
	if f.lookups != 0 {
		t.Errorf("the refusal lookup ran %d times with the switch on", f.lookups)
	}
}

func globalSearchMixedResult() *tg.MessagesMessages {
	return &tg.MessagesMessages{
		Messages: []tg.MessageClass{
			&tg.Message{ID: 1, Message: "from Alice", PeerID: &tg.PeerUser{UserID: 8511}},
			&tg.Message{ID: 2, Message: "channel post", PeerID: &tg.PeerChannel{ChannelID: 8521}},
			&tg.Message{ID: 3, Message: "team chat", PeerID: &tg.PeerChannel{ChannelID: 8522}},
			&tg.Message{ID: 4, Message: "unknown channel", PeerID: &tg.PeerChannel{ChannelID: 8523}},
		},
		Users: []tg.UserClass{&tg.User{ID: 8511, FirstName: "Alice"}},
		Chats: []tg.ChatClass{
			&tg.Channel{ID: 8521, Title: "News", Broadcast: true},
			&tg.Channel{ID: 8522, Title: "Team", Megagroup: true},
		},
	}
}

func TestSearchGlobal_SwitchOff_DropsBroadcastHits(t *testing.T) {
	f := &fakeSearchInvoker{result: globalSearchMixedResult()}
	msgs, err := searchGlobalWith(context.Background(), f, SearchParams{Query: "q", Limit: 10})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	var ids []int
	for _, m := range msgs {
		ids = append(ids, m.ID)
	}
	if len(ids) != 2 || ids[0] != 1 || ids[1] != 3 {
		t.Errorf("ids = %v, want [1 3]: broadcast and unknown-channel hits dropped, user and megagroup kept", ids)
	}
}

func TestSearchGlobal_SwitchOn_KeepsBroadcastHits(t *testing.T) {
	f := &fakeSearchInvoker{result: globalSearchMixedResult()}
	msgs, err := searchGlobalWith(context.Background(), f, SearchParams{Query: "q", Limit: 10, BroadcastContent: BroadcastContentAllowed})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	var ids []int
	for _, m := range msgs {
		ids = append(ids, m.ID)
	}
	if len(ids) != 4 {
		t.Errorf("ids = %v, want all four hits with the switch on", ids)
	}
}
