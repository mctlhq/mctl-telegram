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
	// allDrafts is the getAllDrafts answer; nil answers an empty list.
	allDrafts     tg.UpdatesClass
	allDraftsErr  error
	allDraftReads int
}

func (f *writeFake) MessagesGetAllDrafts(context.Context) (tg.UpdatesClass, error) {
	f.allDraftReads++
	if f.allDraftsErr != nil {
		return nil, f.allDraftsErr
	}
	if f.allDrafts == nil {
		return &tg.Updates{}, nil
	}
	return f.allDrafts, nil
}

// topicDrafts is a getAllDrafts answer holding d as the draft of topic
// topicID in the test forum.
func topicDrafts(topicID int, d *tg.DraftMessage) *tg.Updates {
	u := &tg.UpdateDraftMessage{Peer: &tg.PeerChannel{ChannelID: forum.ChannelID}, Draft: d}
	u.SetTopMsgID(topicID)
	return &tg.Updates{Updates: []tg.UpdateClass{u}}
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
	f := forumWith(&tg.ForumTopic{ID: 12, Title: "Releases"})
	f.allDrafts = topicDrafts(12, typed)
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

// A topic draft's reply header names the topic itself; that only places the
// draft, so the same text is Unchanged and a conflict reports no attachment.
// A reply to another message, or a quote, is still content besides text.
func TestSaveDraftWith_TopicHeaderIsNotAnAttachment(t *testing.T) {
	inTopic := func(rt tg.InputReplyToClass) *tg.DraftMessage {
		d := &tg.DraftMessage{Message: "notes"}
		d.SetReplyTo(rt)
		return d
	}

	f := forumWith(&tg.ForumTopic{ID: 12, Title: "Releases"})
	f.allDrafts = topicDrafts(12, inTopic(&tg.InputReplyToMessage{ReplyToMsgID: 12}))
	out, err := saveDraftWith(context.Background(), f, forum, "@carol_team", "notes", false, 12)
	if err != nil || !out.Unchanged || f.saved != nil {
		t.Fatalf("same text in its own topic: %+v %v saved=%+v", out, err, f.saved)
	}

	f = forumWith(&tg.ForumTopic{ID: 12, Title: "Releases"})
	f.allDrafts = topicDrafts(12, inTopic(&tg.InputReplyToMessage{ReplyToMsgID: 12}))
	_, err = saveDraftWith(context.Background(), f, forum, "@carol_team", "other", false, 12)
	var c *DraftConflict
	if !errors.As(err, &c) || c.HasAttachment {
		t.Fatalf("conflict on a text-only topic draft: %v %+v", err, c)
	}

	quoted := &tg.InputReplyToMessage{ReplyToMsgID: 12}
	quoted.SetQuoteText("Friday")
	for name, rt := range map[string]tg.InputReplyToClass{
		"reply inside the topic": &tg.InputReplyToMessage{ReplyToMsgID: 40, TopMsgID: 12},
		"quote of the opener":    quoted,
	} {
		f = forumWith(&tg.ForumTopic{ID: 12, Title: "Releases"})
		f.allDrafts = topicDrafts(12, inTopic(rt))
		_, err = saveDraftWith(context.Background(), f, forum, "@carol_team", "notes", false, 12)
		if !errors.As(err, &c) || !c.HasAttachment {
			t.Errorf("%s: want a conflict with an attachment, got %v", name, err)
		}
	}

	// Outside a topic any reply header is content.
	if !draftFrom(inTopic(&tg.InputReplyToMessage{ReplyToMsgID: 12}), 0).Other {
		t.Error("a chat draft replying to a message was read as text only")
	}
}

// The live check of #1175 found forumTopic.draft empty while the topic held
// a draft, so the topic's draft is read from getAllDrafts by top_msg_id.
// Drafts of other topics, of the chat itself and of other chats do not
// count, and an answer that cannot list the drafts refuses the write.
func TestSaveDraftWith_TopicDraftComesFromAllDrafts(t *testing.T) {
	typed := &tg.DraftMessage{Message: "Dana, the slides"}

	// What getForumTopicsByID says about the draft is not trusted either
	// way: an empty field there does not let a typed draft be replaced.
	f := forumWith(&tg.ForumTopic{ID: 12, Title: "Releases"})
	f.allDrafts = topicDrafts(12, typed)
	if _, err := saveDraftWith(context.Background(), f, forum, "@carol_team", "notes", false, 12); !errors.Is(err, ErrDraftExists) || f.saved != nil {
		t.Fatalf("typed topic draft replaced: err=%v saved=%+v", err, f.saved)
	}
	if f.allDraftReads != 1 {
		t.Fatalf("getAllDrafts read %d times, want 1", f.allDraftReads)
	}

	other := func() *tg.Updates {
		otherTopic := &tg.UpdateDraftMessage{Peer: &tg.PeerChannel{ChannelID: forum.ChannelID}, Draft: typed}
		otherTopic.SetTopMsgID(13)
		chatOwn := &tg.UpdateDraftMessage{Peer: &tg.PeerChannel{ChannelID: forum.ChannelID}, Draft: typed}
		otherChat := &tg.UpdateDraftMessage{Peer: &tg.PeerChannel{ChannelID: forum.ChannelID + 1}, Draft: typed}
		otherChat.SetTopMsgID(12)
		savedPeer := &tg.UpdateDraftMessage{Peer: &tg.PeerChannel{ChannelID: forum.ChannelID}, Draft: typed}
		savedPeer.SetTopMsgID(12)
		savedPeer.SetSavedPeerID(&tg.PeerUser{UserID: 7120})
		return &tg.Updates{Updates: []tg.UpdateClass{otherTopic, chatOwn, otherChat, savedPeer}}
	}
	f = forumWith(&tg.ForumTopic{ID: 12, Title: "Releases"})
	f.allDrafts = other()
	if out, err := saveDraftWith(context.Background(), f, forum, "@carol_team", "notes", false, 12); err != nil || out.ReplacedExisting || f.saved == nil {
		t.Fatalf("draft elsewhere blocked topic 12: %+v %v", out, err)
	}

	// Clearing a topic draft really writes: an empty text over a typed
	// draft needs overwrite and then reaches Telegram.
	f = forumWith(&tg.ForumTopic{ID: 12, Title: "Releases"})
	f.allDrafts = topicDrafts(12, typed)
	out, err := saveDraftWith(context.Background(), f, forum, "@carol_team", "", true, 12)
	if err != nil || !out.Cleared || !out.ReplacedExisting || f.saved == nil || f.saved.Message != "" {
		t.Fatalf("clear topic draft: %+v %v saved=%+v", out, err, f.saved)
	}

	// The other answer shapes getAllDrafts may use are read the same way.
	one := topicDrafts(12, typed).Updates[0]
	for name, answer := range map[string]tg.UpdatesClass{
		"updatesCombined": &tg.UpdatesCombined{Updates: []tg.UpdateClass{one}},
		"updateShort":     &tg.UpdateShort{Update: one},
	} {
		f = forumWith(&tg.ForumTopic{ID: 12, Title: "Releases"})
		f.allDrafts = answer
		if _, err := saveDraftWith(context.Background(), f, forum, "@carol_team", "notes", false, 12); !errors.Is(err, ErrDraftExists) || f.saved != nil {
			t.Errorf("%s: typed topic draft replaced (err=%v)", name, err)
		}
	}

	for name, fake := range map[string]func(*writeFake){
		"read failed":     func(f *writeFake) { f.allDraftsErr = errors.New("FLOOD_WAIT_3") },
		"updatesTooLong":  func(f *writeFake) { f.allDrafts = &tg.UpdatesTooLong{} },
		"unexpected type": func(f *writeFake) { f.allDrafts = &tg.UpdateShortMessage{} },
	} {
		f = forumWith(&tg.ForumTopic{ID: 12, Title: "Releases"})
		fake(f)
		if _, err := saveDraftWith(context.Background(), f, forum, "@carol_team", "notes", false, 12); err == nil || f.saved != nil {
			t.Errorf("%s: wrote with an unread topic draft (err=%v)", name, err)
		}
	}
}
