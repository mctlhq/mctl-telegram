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
// so it can be tested without a Telegram connection. It fails closed: a
// group or channel whose membership the response does not show is refused.
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
	case *tg.InputPeerChat:
		member := false
		for _, c := range res.Chats {
			if chat, ok := c.(*tg.Chat); ok && chat.ID == v.ChatID && !chat.Left && !chat.Deactivated {
				member = true
			}
		}
		if !member {
			return nil, ErrNoExistingDialog
		}
	case *tg.InputPeerChannel:
		member := false
		for _, c := range res.Chats {
			if ch, ok := c.(*tg.Channel); ok && ch.ID == v.ChannelID && !ch.Left && !ch.Min {
				member = true
			}
		}
		if !member {
			return nil, ErrNoExistingDialog
		}
	}
	return &ReplyTarget{Peer: inputPeer, Ref: ref, Title: peerTitle(inputPeer, res.Users, res.Chats)}, nil
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
	updates, err := c.API().MessagesSendMessage(ctx, &tg.MessagesSendMessageRequest{
		Peer:     target.Peer,
		Message:  text,
		RandomID: randomID,
	})
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
