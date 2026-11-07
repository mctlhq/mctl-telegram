package telegram

import (
	"context"
	"errors"
	"testing"

	"github.com/gotd/td/tg"
)

// writeFake answers the topic lookup like fakeTopics and records the
// read and draft calls slice 4 of #1175 adds.
type writeFake struct {
	fakeTopics
	discussion  *tg.MessagesReadDiscussionRequest
	channelRead *tg.ChannelsReadHistoryRequest
	chatRead    *tg.MessagesReadHistoryRequest
	saved       *tg.MessagesSaveDraftRequest
	dialogs     []tg.DialogClass
	dialogReads int
}

func (f *writeFake) MessagesReadDiscussion(_ context.Context, req *tg.MessagesReadDiscussionRequest) (bool, error) {
	f.discussion = req
	return true, nil
}

func (f *writeFake) ChannelsReadHistory(_ context.Context, req *tg.ChannelsReadHistoryRequest) (bool, error) {
	f.channelRead = req
	return true, nil
}

func (f *writeFake) MessagesReadHistory(_ context.Context, req *tg.MessagesReadHistoryRequest) (*tg.MessagesAffectedMessages, error) {
	f.chatRead = req
	return &tg.MessagesAffectedMessages{}, nil
}

func (f *writeFake) MessagesGetPeerDialogs(context.Context, []tg.InputDialogPeerClass) (*tg.MessagesPeerDialogs, error) {
	f.dialogReads++
	return &tg.MessagesPeerDialogs{Dialogs: f.dialogs}, nil
}

func (f *writeFake) MessagesSaveDraft(_ context.Context, req *tg.MessagesSaveDraftRequest) (bool, error) {
	f.saved = req
	return true, nil
}

func forumWith(topics ...tg.ForumTopicClass) *writeFake {
	return &writeFake{fakeTopics: fakeTopics{topics: &tg.MessagesForumTopics{Topics: topics}}}
}

func TestMarkReadWith_Topic(t *testing.T) {
	releases := &tg.ForumTopic{ID: 12, Title: "Releases"}

	f := forumWith(releases)
	out, err := markReadWith(context.Background(), f, forum, "@carol_team", 90, 12)
	if err != nil || out.TopicID != 12 || out.TopicTitle != "Releases" || out.Ref != "channel:4601" {
		t.Fatalf("topic read = %+v, %v", out, err)
	}
	if f.discussion == nil || f.discussion.MsgID != 12 || f.discussion.ReadMaxID != 90 || f.channelRead != nil {
		t.Fatalf("calls: discussion=%+v channelRead=%+v", f.discussion, f.channelRead)
	}

	// A closed topic can still be read.
	f = forumWith(&tg.ForumTopic{ID: 13, Title: "Old", Closed: true})
	if _, err := markReadWith(context.Background(), f, forum, "@carol_team", 5, 13); err != nil || f.discussion == nil {
		t.Fatalf("closed topic: %v", err)
	}

	// General is the chat's own history.
	f = forumWith(&tg.ForumTopic{ID: 1, Title: "General"})
	if _, err := markReadWith(context.Background(), f, forum, "@carol_team", 5, 1); err != nil || f.discussion != nil || f.channelRead == nil || f.channelRead.MaxID != 5 {
		t.Fatalf("General: err=%v discussion=%+v channelRead=%+v", err, f.discussion, f.channelRead)
	}

	// Missing topic, and a chat with no topics: nothing is marked.
	f = forumWith()
	if _, err := markReadWith(context.Background(), f, forum, "@carol_team", 5, 99); !errors.Is(err, ErrTopicNotFound) || f.discussion != nil || f.channelRead != nil {
		t.Fatalf("missing topic: %v", err)
	}
	f = forumWith(releases)
	if _, err := markReadWith(context.Background(), f, &tg.InputPeerUser{UserID: 7120}, "user:7120", 5, 12); !errors.Is(err, ErrNotAForum) || f.chatRead != nil {
		t.Fatalf("not a forum: %v", err)
	}

	// No topic: the chat route is unchanged.
	f = forumWith()
	if out, err := markReadWith(context.Background(), f, &tg.InputPeerUser{UserID: 7120}, "user:7120", 41, 0); err != nil || out.TopicID != 0 || f.chatRead == nil || f.lookups != 0 {
		t.Fatalf("no topic: %+v %v lookups=%d", out, err, f.lookups)
	}
}

func TestSaveDraftWith_Topic(t *testing.T) {
	typed := &tg.DraftMessage{Message: "Bob, about Friday"}

	// The topic's own draft decides, not the chat's.
	f := forumWith(&tg.ForumTopic{ID: 12, Title: "Releases", Draft: typed})
	f.dialogs = []tg.DialogClass{&tg.Dialog{}}
	if _, err := saveDraftWith(context.Background(), f, forum, "@carol_team", "notes", false, 12); !errors.Is(err, ErrDraftExists) || f.saved != nil {
		t.Fatalf("topic draft kept: err=%v saved=%+v", err, f.saved)
	}
	if f.dialogReads != 0 {
		t.Error("the chat's draft was read for a topic draft")
	}

	// An empty topic draft is written into that topic.
	f = forumWith(&tg.ForumTopic{ID: 12, Title: "Releases"})
	f.dialogs = []tg.DialogClass{&tg.Dialog{Draft: typed}}
	out, err := saveDraftWith(context.Background(), f, forum, "@carol_team", "notes", false, 12)
	if err != nil || out.TopicID != 12 || out.TopicTitle != "Releases" {
		t.Fatalf("topic draft = %+v, %v", out, err)
	}
	r, ok := f.saved.GetReplyTo()
	if m, isMsg := r.(*tg.InputReplyToMessage); !ok || !isMsg || m.ReplyToMsgID != 12 || f.saved.Message != "notes" {
		t.Fatalf("saved = %+v reply_to=%#v", f.saved, r)
	}

	// A closed topic takes no draft.
	f = forumWith(&tg.ForumTopic{ID: 13, Title: "Old", Closed: true})
	if _, err := saveDraftWith(context.Background(), f, forum, "@carol_team", "notes", false, 13); !errors.Is(err, ErrTopicClosed) || f.saved != nil {
		t.Fatalf("closed topic: %v", err)
	}

	// General uses the chat's draft and no reply_to.
	f = forumWith(&tg.ForumTopic{ID: 1, Title: "General"})
	f.dialogs = []tg.DialogClass{&tg.Dialog{Draft: typed}}
	if _, err := saveDraftWith(context.Background(), f, forum, "@carol_team", "notes", false, 1); !errors.Is(err, ErrDraftExists) {
		t.Fatalf("General draft kept: %v", err)
	}
	if _, err := saveDraftWith(context.Background(), f, forum, "@carol_team", "notes", true, 1); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.saved.GetReplyTo(); ok {
		t.Error("a General draft carries reply_to")
	}

	// No topic: no lookup, the chat's draft, no reply_to.
	f = forumWith()
	f.dialogs = []tg.DialogClass{&tg.Dialog{}}
	if out, err := saveDraftWith(context.Background(), f, &tg.InputPeerUser{UserID: 7120}, "user:7120", "hi", false, 0); err != nil || out.TopicID != 0 || f.lookups != 0 || f.dialogReads != 1 {
		t.Fatalf("no topic: %+v %v lookups=%d", out, err, f.lookups)
	}
}
