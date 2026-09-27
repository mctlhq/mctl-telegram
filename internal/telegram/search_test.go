package telegram

import (
	"bytes"
	"context"
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
}

func (f *fakeSearchInvoker) MessagesSearchGlobal(_ context.Context, req *tg.MessagesSearchGlobalRequest) (tg.MessagesMessagesClass, error) {
	f.lastGlobal = req
	return f.result, nil
}

func (f *fakeSearchInvoker) MessagesSearch(_ context.Context, req *tg.MessagesSearchRequest) (tg.MessagesMessagesClass, error) {
	f.lastPeer = req
	return f.result, nil
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
