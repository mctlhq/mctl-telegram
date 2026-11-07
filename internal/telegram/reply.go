package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// ErrNoExistingDialog means the peer resolved, but the account has no
// message history with it. draft_reply (core-reply profile) only drafts into
// conversations that already exist, so a bare @username the account never
// talked to is refused rather than turned into a first contact.
var ErrNoExistingDialog = errors.New("peer is not an existing conversation of this account")

// ErrCannotPost means the account is in the conversation but may not post a
// text message there: a broadcast channel it does not administer, or a group
// whose rights ban sending. draft_reply refuses it up front, because the
// one-shot confirmation would otherwise be spent on a refusal at send time.
var ErrCannotPost = errors.New("account may not post text messages in this conversation")

// ErrPeerDeleted means the conversation exists but the other side is a
// deleted account: the dialog and history remain, and Telegram refuses any
// send to it (INPUT_USER_DEACTIVATED). Unlike ErrCannotPost there is nothing
// the user can change to make the reply possible.
var ErrPeerDeleted = errors.New("the other account in this conversation has been deleted")

// ReplyTarget is a peer resolved for a reply: the InputPeer to send to,
// including its access hash, so the later send cannot be re-pointed by a
// username that changed hands between the draft and the send.
type ReplyTarget struct {
	Peer tg.InputPeerClass
	// Ref is the canonical reference, "user:<id>", "chat:<id>" or
	// "channel:<id>". It is what the draft shows as the recipient.
	Ref string
	// Title is the display name of the chat, when the history response
	// carried it.
	Title string
	// TopicID is the forum topic the reply goes to, 0 for none. It is set
	// only by ResolveReplyTopic, so a draft names a topic only after the
	// topic was checked to exist in this chat.
	TopicID int
	// TopicTitle is the topic's title, shown with the recipient.
	TopicTitle string
}

// generalTopicID is the id of a forum's General topic. A message sent
// without reply_to lands there, and its id names no message to reply to.
const generalTopicID = 1

// ErrTopicClosed is returned when the topic exists but is closed to new
// messages.
var ErrTopicClosed = errors.New("this topic is closed to new messages")

// topicByIDInvoker is the subset of *tg.Client ResolveReplyTopic uses, so
// the decision can be tested without a live MTProto client.
type topicByIDInvoker interface {
	MessagesGetForumTopicsByID(ctx context.Context, req *tg.MessagesGetForumTopicsByIDRequest) (*tg.MessagesForumTopics, error)
	channelLookup
}

// ResolveReplyTopic returns a copy of target bound to topicID, after
// checking that the chat is a forum and the topic exists and is open. A
// draft that names a topic carries it to send_reply, which cannot change it.
func ResolveReplyTopic(ctx context.Context, c *telegram.Client, target *ReplyTarget, topicID int) (*ReplyTarget, error) {
	return replyTopicWith(ctx, c.API(), target, topicID)
}

func replyTopicWith(ctx context.Context, api topicByIDInvoker, target *ReplyTarget, topicID int) (*ReplyTarget, error) {
	if target == nil || target.Peer == nil {
		return nil, errors.New("reply target required")
	}
	t, err := lookupTopic(ctx, api, target.Ref, target.Peer, topicID)
	if err != nil {
		return nil, err
	}
	if t.Closed {
		return nil, ErrTopicClosed
	}
	out := *target
	out.TopicID, out.TopicTitle = t.ID, t.Title
	return &out, nil
}

// lookupTopic returns topicID of the forum peer, after checking that peer
// is a forum at all. Whether a closed topic is acceptable is the caller's
// decision: reading one is fine, writing into one is not.
func lookupTopic(ctx context.Context, api topicByIDInvoker, ref string, peer tg.InputPeerClass, topicID int) (*tg.ForumTopic, error) {
	if topicID <= 0 {
		return nil, fmt.Errorf("topic_id must be a positive topic id")
	}
	if err := requireForum(ctx, api, ref, peer); err != nil {
		return nil, err
	}
	res, err := api.MessagesGetForumTopicsByID(ctx, &tg.MessagesGetForumTopicsByIDRequest{Peer: peer, Topics: []int{topicID}})
	if err != nil {
		return nil, topicRPCError("MessagesGetForumTopicsByID", err)
	}
	if res == nil {
		return nil, errors.New("MessagesGetForumTopicsByID: empty reply")
	}
	for _, tc := range res.Topics {
		if t, ok := tc.(*tg.ForumTopic); ok && t.ID == topicID {
			return t, nil
		}
	}
	// The reply answered and does not hold the topic (or holds it as
	// forumTopicDeleted): Telegram's own statement that it is not there.
	return nil, ErrTopicNotFound
}

// replyToFor is the reply_to of a message sent to topicID. The General
// topic and "no topic" send without one.
func replyToFor(topicID int) tg.InputReplyToClass {
	if topicID <= generalTopicID {
		return nil
	}
	return &tg.InputReplyToMessage{ReplyToMsgID: topicID}
}

// draftReplyToFor is the reply_to of a draft left in topicID. Unlike a sent
// message, a draft is not placed into a topic by replying to the topic's
// opening message: Telegram keeps a draft whose reply_to has no top_msg_id as
// the chat's own draft, with a reply header to that message, and getAllDrafts
// then lists no entry for the topic (live check, mctl-telegram#1175). The
// topic's own draft slot is chosen by top_msg_id, so a topic draft carries it.
func draftReplyToFor(topicID int) tg.InputReplyToClass {
	if topicID <= generalTopicID {
		return nil
	}
	r := &tg.InputReplyToMessage{ReplyToMsgID: topicID}
	r.SetTopMsgID(topicID)
	return r
}

// ResolveExistingDialog resolves peer and requires it to be a conversation
// the account already has: the peer is in the account's dialog list with at
// least one message, and for a group or channel the account is a member.
// Being able to read a peer is not enough: a public channel or supergroup
// resolves by @username with a usable access hash, and its history reads
// fine, for an account that never joined it. Any other outcome is an error;
// ErrNoExistingDialog marks the "not a conversation of this account" case.
func ResolveExistingDialog(ctx context.Context, c *telegram.Client, peer string, cache *PeerCache, userID int64) (*ReplyTarget, error) {
	inputPeer, err := ResolvePeerCached(ctx, c, peer, cache, userID)
	if err != nil {
		return nil, err
	}
	res, err := c.API().MessagesGetPeerDialogs(ctx, []tg.InputDialogPeerClass{&tg.InputDialogPeer{Peer: inputPeer}})
	if err != nil {
		return nil, fmt.Errorf("MessagesGetPeerDialogs: %w", err)
	}
	return replyTargetFromPeerDialogs(inputPeer, res)
}

// replyTargetFromPeerDialogs is ResolveExistingDialog's decision, split out
// so it can be tested without a Telegram connection. It fails closed on
// membership: a group or channel whose membership the response does not show
// is refused. A user peer is proven by its dialog alone; its user object, when
// present, can only refuse it (a deleted account).
func replyTargetFromPeerDialogs(inputPeer tg.InputPeerClass, res *tg.MessagesPeerDialogs) (*ReplyTarget, error) {
	ref, err := canonicalPeerRef(inputPeer)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return nil, errors.New("empty peer dialogs response")
	}
	var dialog *tg.Dialog
	for _, d := range res.Dialogs {
		if dd, ok := d.(*tg.Dialog); ok && samePeer(inputPeer, dd.Peer) {
			dialog = dd
		}
	}
	if dialog == nil || dialog.TopMessage == 0 {
		return nil, ErrNoExistingDialog
	}
	switch v := inputPeer.(type) {
	case *tg.InputPeerUser:
		// For a user the dialog above is the proof of the conversation, and the
		// user object can only add a refusal: a response without it is
		// accepted. Groups and channels are the opposite, below: membership is
		// the proof, so a missing object is refused.
		for _, u := range res.Users {
			if user, ok := u.(*tg.User); ok && user.ID == v.UserID && user.Deleted {
				return nil, ErrPeerDeleted
			}
		}
	case *tg.InputPeerChat:
		var chat *tg.Chat
		for _, c := range res.Chats {
			if ch, ok := c.(*tg.Chat); ok && ch.ID == v.ChatID && !ch.Left && !ch.Deactivated {
				chat = ch
			}
		}
		if chat == nil {
			return nil, ErrNoExistingDialog
		}
		if !chatAllowsPosting(chat) {
			return nil, ErrCannotPost
		}
	case *tg.InputPeerChannel:
		var channel *tg.Channel
		for _, c := range res.Chats {
			if ch, ok := c.(*tg.Channel); ok && ch.ID == v.ChannelID && !ch.Left && !ch.Min {
				channel = ch
			}
		}
		if channel == nil {
			return nil, ErrNoExistingDialog
		}
		if !channelAllowsPosting(channel) {
			return nil, ErrCannotPost
		}
	}
	return &ReplyTarget{Peer: inputPeer, Ref: ref, Title: peerTitle(inputPeer, res.Users, res.Chats)}, nil
}

// channelAllowsPosting reports whether the account may post a text message
// in a channel or supergroup it is a member of.
func channelAllowsPosting(ch *tg.Channel) bool {
	if ch.Creator {
		return true
	}
	admin, isAdmin := ch.GetAdminRights()
	// In a broadcast channel only admins with post_messages may post; in a
	// gigagroup only admins may.
	if ch.Broadcast {
		return isAdmin && admin.PostMessages
	}
	if ch.Gigagroup {
		return isAdmin
	}
	if isAdmin {
		return true
	}
	// The account's own banned_rights are its effective rights: they are how
	// Telegram stores a per-member exception, which overrides the group's
	// defaults in either direction. Only without them do the defaults apply.
	// A ban is honoured even if its until_date may already have passed.
	if own, ok := ch.GetBannedRights(); ok {
		return !own.ViewMessages && !bansText(own)
	}
	def, ok := ch.GetDefaultBannedRights()
	return !ok || !bansText(def)
}

// chatAllowsPosting is channelAllowsPosting for a basic group, which has no
// per-member rights: the creator and admins are exempt from the defaults.
func chatAllowsPosting(chat *tg.Chat) bool {
	if _, isAdmin := chat.GetAdminRights(); chat.Creator || isAdmin {
		return true
	}
	def, ok := chat.GetDefaultBannedRights()
	return !ok || !bansText(def)
}

// bansText reports whether rights forbid sending a plain text message.
func bansText(r tg.ChatBannedRights) bool {
	return r.SendMessages || r.SendPlain
}

func samePeer(in tg.InputPeerClass, p tg.PeerClass) bool {
	switch v := in.(type) {
	case *tg.InputPeerUser:
		u, ok := p.(*tg.PeerUser)
		return ok && u.UserID == v.UserID
	case *tg.InputPeerChat:
		c, ok := p.(*tg.PeerChat)
		return ok && c.ChatID == v.ChatID
	case *tg.InputPeerChannel:
		c, ok := p.(*tg.PeerChannel)
		return ok && c.ChannelID == v.ChannelID
	}
	return false
}

func canonicalPeerRef(p tg.InputPeerClass) (string, error) {
	switch v := p.(type) {
	case *tg.InputPeerUser:
		return fmt.Sprintf("user:%d", v.UserID), nil
	case *tg.InputPeerChat:
		return fmt.Sprintf("chat:%d", v.ChatID), nil
	case *tg.InputPeerChannel:
		return fmt.Sprintf("channel:%d", v.ChannelID), nil
	}
	return "", fmt.Errorf("peer type %T cannot be replied to", p)
}

func peerTitle(p tg.InputPeerClass, users []tg.UserClass, chats []tg.ChatClass) string {
	switch v := p.(type) {
	case *tg.InputPeerUser:
		for _, u := range users {
			if user, ok := u.(*tg.User); ok && user.ID == v.UserID {
				return strings.TrimSpace(user.FirstName + " " + user.LastName)
			}
		}
	case *tg.InputPeerChat:
		for _, c := range chats {
			if chat, ok := c.(*tg.Chat); ok && chat.ID == v.ChatID {
				return chat.Title
			}
		}
	case *tg.InputPeerChannel:
		for _, c := range chats {
			if ch, ok := c.(*tg.Channel); ok && ch.ID == v.ChannelID {
				return ch.Title
			}
		}
	}
	return ""
}

// sendReplyRequest builds the request SendReply sends: to the stored peer,
// and into the bound topic when there is one.
func sendReplyRequest(target *ReplyTarget, text string, randomID int64) *tg.MessagesSendMessageRequest {
	req := &tg.MessagesSendMessageRequest{
		Peer:     target.Peer,
		Message:  text,
		RandomID: randomID,
	}
	if replyTo := replyToFor(target.TopicID); replyTo != nil {
		req.SetReplyTo(replyTo)
	}
	return req
}

// SendReply delivers text to a target ResolveExistingDialog produced. It
// sends to the stored InputPeer and never re-resolves: the recipient is the
// one the draft showed.
func SendReply(ctx context.Context, c *telegram.Client, target *ReplyTarget, text string, userID int64) (*SendResult, error) {
	if target == nil || target.Peer == nil {
		return nil, errors.New("reply target required")
	}
	if text == "" {
		return nil, errors.New("text required")
	}
	randomID, err := newRandomID()
	if err != nil {
		return nil, err
	}
	updates, err := c.API().MessagesSendMessage(ctx, sendReplyRequest(target, text, randomID))
	if err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	messageID := extractMessageID(updates)
	notifyAgentSent(userID, int64(messageID))
	return &SendResult{
		Sent:      true,
		Mode:      "send",
		PeerInput: target.Ref,
		Text:      text,
		MessageID: messageID,
	}, nil
}
