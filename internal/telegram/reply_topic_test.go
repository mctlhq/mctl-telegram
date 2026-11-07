package telegram

import (
	"context"
	"errors"
	"testing"

	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

func forumTarget() *ReplyTarget {
	return &ReplyTarget{Peer: forum, Ref: "channel:4601", Title: "Carol's team"}
}

func TestReplyTopic_BindsAnOpenTopic(t *testing.T) {
	f := &fakeTopics{topics: &tg.MessagesForumTopics{Topics: []tg.ForumTopicClass{&tg.ForumTopic{ID: 12, Title: "Releases"}}}}
	in := forumTarget()
	got, err := replyTopicWith(context.Background(), f, in, 12)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if got.TopicID != 12 || got.TopicTitle != "Releases" || got.Ref != "channel:4601" {
		t.Fatalf("target = %+v", got)
	}
	if in.TopicID != 0 {
		t.Fatal("the input target was modified; drafts share it")
	}
	if f.byIDReq == nil || len(f.byIDReq.Topics) != 1 || f.byIDReq.Topics[0] != 12 {
		t.Fatalf("request = %+v", f.byIDReq)
	}
}

func TestReplyTopic_Refusals(t *testing.T) {
	cases := []struct {
		name string
		f    *fakeTopics
		id   int
		want error
	}{
		{"absent", &fakeTopics{topics: &tg.MessagesForumTopics{}}, 12, ErrTopicNotFound},
		{"deleted", &fakeTopics{topics: &tg.MessagesForumTopics{Topics: []tg.ForumTopicClass{&tg.ForumTopicDeleted{ID: 12}}}}, 12, ErrTopicNotFound},
		{"another id", &fakeTopics{topics: &tg.MessagesForumTopics{Topics: []tg.ForumTopicClass{&tg.ForumTopic{ID: 13}}}}, 12, ErrTopicNotFound},
		{"closed", &fakeTopics{topics: &tg.MessagesForumTopics{Topics: []tg.ForumTopicClass{&tg.ForumTopic{ID: 12, Closed: true}}}}, 12, ErrTopicClosed},
		{"not a forum", &fakeTopics{notForum: true, topics: &tg.MessagesForumTopics{}}, 12, ErrNotAForum},
		{"invalid id rpc", &fakeTopics{err: tgerr.New(400, "TOPIC_ID_INVALID")}, 12, ErrTopicNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := replyTopicWith(context.Background(), c.f, forumTarget(), c.id); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
	// A private chat has no topics; refused before any topic lookup.
	f := &fakeTopics{}
	if _, err := replyTopicWith(context.Background(), f, &ReplyTarget{Peer: &tg.InputPeerUser{UserID: 7120}, Ref: "user:7120"}, 12); !errors.Is(err, ErrNotAForum) || f.byIDReq != nil {
		t.Fatalf("user peer: err = %v, lookup = %v", err, f.byIDReq)
	}
	// A failed read is an error, never "not found".
	f = &fakeTopics{err: errors.New("network down")}
	if _, err := replyTopicWith(context.Background(), f, forumTarget(), 12); err == nil || errors.Is(err, ErrTopicNotFound) {
		t.Fatalf("network error: err = %v", err)
	}
}

func TestReplyToFor(t *testing.T) {
	if replyToFor(0) != nil || replyToFor(generalTopicID) != nil {
		t.Fatal("no topic and General must send without reply_to")
	}
	r, ok := replyToFor(12).(*tg.InputReplyToMessage)
	if !ok || r.ReplyToMsgID != 12 {
		t.Fatalf("reply_to = %#v", replyToFor(12))
	}
}

func TestDraftReplyToFor(t *testing.T) {
	if draftReplyToFor(0) != nil || draftReplyToFor(generalTopicID) != nil {
		t.Fatal("no topic and General keep the chat's own draft, without reply_to")
	}
	r, ok := draftReplyToFor(12).(*tg.InputReplyToMessage)
	if !ok || r.ReplyToMsgID != 12 {
		t.Fatalf("reply_to = %#v", draftReplyToFor(12))
	}
	if top, ok := r.GetTopMsgID(); !ok || top != 12 {
		t.Fatalf("top_msg_id = %d/%t, want 12", top, ok)
	}
	if !isTopicHeader(r, 12) {
		t.Fatal("the draft's own header must read back as the topic header, not an attachment")
	}
}

// The bound topic reaches the wire: a reply into topic 12 carries reply_to
// 12, and a reply without a topic carries none.
func TestSendReplyRequest(t *testing.T) {
	peer := &tg.InputPeerChannel{ChannelID: 4601, AccessHash: 7}
	req := sendReplyRequest(&ReplyTarget{Peer: peer, TopicID: 12}, "Shipped", 99)
	r, ok := req.GetReplyTo()
	if m, isMsg := r.(*tg.InputReplyToMessage); !ok || !isMsg || m.ReplyToMsgID != 12 {
		t.Fatalf("topic reply: reply_to = %#v", r)
	}
	if req.Peer != peer || req.Message != "Shipped" || req.RandomID != 99 {
		t.Fatalf("request = %+v", req)
	}
	if _, ok := sendReplyRequest(&ReplyTarget{Peer: peer}, "hi", 1).GetReplyTo(); ok {
		t.Fatal("a reply without a topic carries reply_to")
	}
}
