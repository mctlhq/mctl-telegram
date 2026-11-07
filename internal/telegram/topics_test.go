package telegram

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

type fakeTopics struct {
	topicsReq  *tg.MessagesGetForumTopicsRequest
	topics     *tg.MessagesForumTopics
	repliesReq *tg.MessagesGetRepliesRequest
	replies    tg.MessagesMessagesClass
	err        error
	broadcast  bool
	notForum   bool
	lookupErr  error
	omitChat   bool
	lookups    int
	byIDReq    *tg.MessagesGetForumTopicsByIDRequest
}

func (f *fakeTopics) MessagesGetForumTopicsByID(_ context.Context, req *tg.MessagesGetForumTopicsByIDRequest) (*tg.MessagesForumTopics, error) {
	f.byIDReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.topics, nil
}

func (f *fakeTopics) MessagesGetForumTopics(_ context.Context, req *tg.MessagesGetForumTopicsRequest) (*tg.MessagesForumTopics, error) {
	f.topicsReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.topics, nil
}

func (f *fakeTopics) MessagesGetReplies(_ context.Context, req *tg.MessagesGetRepliesRequest) (tg.MessagesMessagesClass, error) {
	f.repliesReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.replies, nil
}

func (f *fakeTopics) ChannelsGetChannels(_ context.Context, id []tg.InputChannelClass) (tg.MessagesChatsClass, error) {
	f.lookups++
	if f.lookupErr != nil {
		return nil, f.lookupErr
	}
	if f.omitChat {
		return &tg.MessagesChats{}, nil
	}
	chID := id[0].(*tg.InputChannel).ChannelID
	return &tg.MessagesChats{Chats: []tg.ChatClass{&tg.Channel{ID: chID, Megagroup: !f.broadcast, Broadcast: f.broadcast, Forum: !f.notForum}}}, nil
}

// forum is the synthetic forum supergroup used throughout (Carol's team chat).
var forum = &tg.InputPeerChannel{ChannelID: 4601, AccessHash: 7}

func TestTopicsFrom_DecodesTopicsAndSaysWhetherTheListEnded(t *testing.T) {
	when := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	peer := &tg.PeerChannel{ChannelID: 4601}
	res := &tg.MessagesForumTopics{
		Count: 3,
		Topics: []tg.ForumTopicClass{
			&tg.ForumTopic{ID: 1, Title: "General", Pinned: true, UnreadCount: 2, TopMessage: 90, Peer: peer},
			&tg.ForumTopicDeleted{ID: 4611},
			&tg.ForumTopic{ID: 4612, Title: "Releases", Closed: true, Hidden: true, UnreadMentionsCount: 1, TopMessage: 91, Peer: peer},
		},
		Messages: []tg.MessageClass{&tg.Message{ID: 91, PeerID: peer, Date: int(when.Unix())}},
	}
	got, list, err := topicsFrom(res)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ID != 1 || got[1].ID != 4612 {
		t.Fatalf("topics = %+v, want General and Releases with the deleted one left out", got)
	}
	if !got[0].Pinned || got[0].UnreadCount != 2 || got[0].Title != "General" {
		t.Errorf("General = %+v", got[0])
	}
	if !got[1].Closed || !got[1].Hidden || got[1].UnreadMentionsCount != 1 {
		t.Errorf("Releases = %+v", got[1])
	}
	if !got[1].LastMessageDate.Equal(when) || !got[0].LastMessageDate.IsZero() {
		t.Errorf("last message dates = %v / %v, want zero / %v", got[0].LastMessageDate, got[1].LastMessageDate, when)
	}
	if !list.Complete || list.Total != 3 {
		t.Errorf("list = %+v, want complete total 3 (a deleted topic still came back)", list)
	}

	res.Count = 40
	if _, list, _ = topicsFrom(res); list.Complete || list.Total != 40 {
		t.Errorf("list = %+v, want incomplete when Telegram reports more topics than returned", list)
	}
	if _, _, err := topicsFrom(nil); err == nil {
		t.Error("nil reply must be an error, not an empty forum")
	}
}

func TestListTopicsWith_SendsQueryAndBoundsTheLimit(t *testing.T) {
	f := &fakeTopics{topics: &tg.MessagesForumTopics{}}
	if _, _, err := listTopicsWith(context.Background(), f, forum, "rel", 500); err != nil {
		t.Fatal(err)
	}
	if f.topicsReq.Limit != 100 || f.topicsReq.Q != "rel" || f.topicsReq.Peer != forum {
		t.Errorf("request = %+v, want limit capped at 100, q rel, the forum peer", f.topicsReq)
	}
	if _, _, err := listTopicsWith(context.Background(), f, forum, "", 7); err != nil {
		t.Fatal(err)
	}
	if _, set := f.topicsReq.GetQ(); set || f.topicsReq.Limit != 7 {
		t.Errorf("request = %+v, want no q and limit 7", f.topicsReq)
	}
	if _, _, err := listTopicsWith(context.Background(), f, forum, "", 0); err != nil || f.topicsReq.Limit != 50 {
		t.Errorf("limit 0: err=%v limit=%d, want the default 50", err, f.topicsReq.Limit)
	}
}

func TestTopicRPCError_NamesForumAndTopicFailures(t *testing.T) {
	for msg, want := range map[string]error{
		"CHANNEL_FORUM_MISSING": ErrNotAForum,
		"TOPIC_ID_INVALID":      ErrTopicNotFound,
		"MSG_ID_INVALID":        ErrTopicNotFound,
	} {
		f := &fakeTopics{err: tgerr.New(400, msg)}
		if _, _, err := listTopicsWith(context.Background(), f, forum, "", 10); !errors.Is(err, want) {
			t.Errorf("%s from list = %v, want %v", msg, err, want)
		}
		if _, _, _, err := getTopicMessagesWith(context.Background(), f, forum, "carol_team", 4612, 10, 0, false); !errors.Is(err, want) {
			t.Errorf("%s from read = %v, want %v", msg, err, want)
		}
	}
	f := &fakeTopics{err: errors.New("network down")}
	_, _, err := listTopicsWith(context.Background(), f, forum, "", 10)
	if err == nil || errors.Is(err, ErrNotAForum) || !strings.Contains(err.Error(), "network down") {
		t.Errorf("a transport failure = %v, want it passed through, never 'not a forum'", err)
	}
}

func TestGetTopicMessagesWith_ReadsTheTopicThreadAndPages(t *testing.T) {
	f := &fakeTopics{replies: &tg.MessagesChannelMessages{
		Count:    30,
		Messages: []tg.MessageClass{&tg.Message{ID: 95, Message: "ship it"}, &tg.Message{ID: 94, Message: "tests green"}},
	}}
	msgs, raw, next, err := getTopicMessagesWith(context.Background(), f, forum, "carol_team", 4612, 2, 96, false)
	if err != nil {
		t.Fatal(err)
	}
	r := f.repliesReq
	if r.MsgID != 4612 || r.OffsetID != 96 || r.Limit != 2 || r.Peer != forum {
		t.Errorf("request = %+v, want msg_id 4612 (the topic), offset 96, limit 2", r)
	}
	if len(msgs) != 2 || len(raw) != 2 || msgs[0].Text != "ship it" {
		t.Errorf("messages = %+v", msgs)
	}
	if next != 94 {
		t.Errorf("next cursor = %d, want 94 (oldest id on the page)", next)
	}
	if f.lookups != 2 {
		t.Errorf("channel lookups = %d, want 2 with the switch off (broadcast check, forum check)", f.lookups)
	}
}

func TestGetTopicMessagesWith_RefusesBadTopicAndBroadcastBeforeReading(t *testing.T) {
	f := &fakeTopics{replies: &tg.MessagesChannelMessages{}}
	if _, _, _, err := getTopicMessagesWith(context.Background(), f, forum, "carol_team", 0, 10, 0, false); err == nil {
		t.Error("topic 0 must be refused")
	}
	f.broadcast = true
	_, _, _, err := getTopicMessagesWith(context.Background(), f, forum, "carol_news", 4612, 10, 0, false)
	if !errors.Is(err, ErrBroadcastContent) {
		t.Errorf("err = %v, want the broadcast refusal", err)
	}
	if f.repliesReq != nil {
		t.Error("a refused peer must not be read")
	}
}

// TestGetTopicMessagesWith_NonForumSupergroupIsRefused: on an ordinary
// supergroup getReplies would return message N's reply thread, so the forum
// flag is checked first; a lookup that fails or leaves the chat out is an
// error, never "not a forum".
func TestGetTopicMessagesWith_NonForumSupergroupIsRefused(t *testing.T) {
	f := &fakeTopics{replies: &tg.MessagesChannelMessages{}, notForum: true}
	_, _, _, err := getTopicMessagesWith(context.Background(), f, forum, "carol_team", 4612, 10, 0, true)
	if !errors.Is(err, ErrNotAForum) || f.repliesReq != nil {
		t.Errorf("err = %v, read = %v; want not-a-forum before getReplies", err, f.repliesReq != nil)
	}
	for name, f := range map[string]*fakeTopics{
		"lookup failed": {replies: &tg.MessagesChannelMessages{}, lookupErr: errors.New("flood wait")},
		"chat missing":  {replies: &tg.MessagesChannelMessages{}, omitChat: true},
	} {
		_, _, _, err := getTopicMessagesWith(context.Background(), f, forum, "carol_team", 4612, 10, 0, true)
		if err == nil || errors.Is(err, ErrNotAForum) || f.repliesReq != nil {
			t.Errorf("%s: err = %v, read = %v; want an error that is not 'not a forum', and no read", name, err, f.repliesReq != nil)
		}
	}
}

func TestCheckTopicScope(t *testing.T) {
	for _, c := range []struct {
		p    SearchParams
		fail bool
	}{
		{SearchParams{}, false},
		{SearchParams{Peer: "carol_team", TopicID: 4612}, false},
		{SearchParams{TopicID: 4612}, true},
		{SearchParams{Peer: "carol_team", TopicID: -1}, true},
	} {
		if err := checkTopicScope(c.p); (err != nil) != c.fail {
			t.Errorf("checkTopicScope(%+v) = %v, want fail=%v", c.p, err, c.fail)
		}
	}
}

func TestSearchPeerWith_TopicSetsTopMsgIDOnlyOnAChannel(t *testing.T) {
	f := &fakeSearchInvoker{result: fakeSearchResult(), forum: true}
	if _, err := searchPeerWith(context.Background(), f, forum, SearchParams{Peer: "carol_team", Query: "x", Limit: 5, TopicID: 4612}); err != nil {
		t.Fatal(err)
	}
	if id, ok := f.lastPeer.GetTopMsgID(); !ok || id != 4612 {
		t.Errorf("top_msg_id = %d set=%v, want 4612", id, ok)
	}
	if _, err := searchPeerWith(context.Background(), f, forum, SearchParams{Peer: "carol_team", Query: "x", Limit: 5}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.lastPeer.GetTopMsgID(); ok {
		t.Error("top_msg_id set without a topic")
	}
	f.lastPeer = nil
	f.forum = false
	if _, err := searchPeerWith(context.Background(), f, forum, SearchParams{Peer: "carol_team", Query: "x", Limit: 5, TopicID: 4612}); !errors.Is(err, ErrNotAForum) || f.lastPeer != nil {
		t.Errorf("non-forum supergroup: err = %v, searched = %v; want not-a-forum before any search", err, f.lastPeer != nil)
	}
	_, err := searchPeerWith(context.Background(), f, &tg.InputPeerUser{UserID: 4602}, SearchParams{Peer: "bob", Query: "x", Limit: 5, TopicID: 4612})
	if !errors.Is(err, ErrNotAForum) || f.lastPeer != nil {
		t.Errorf("err = %v, searched = %v; want not-a-forum before any search", err, f.lastPeer != nil)
	}
}
