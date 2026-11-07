package telegram

import (
	"context"
	"errors"
	"fmt"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// errReadNotAChat is returned for a peer that resolves to no chat the
// account could have unread messages in (self, empty).
var errReadNotAChat = errors.New("peer names no chat")

// readHistoryRequest builds the Telegram call that marks peer read up to
// maxID. Channels and supergroups have their own method; every other chat
// uses messages.readHistory. It is separate from MarkRead so the routing is
// testable without a Telegram session.
func readHistoryRequest(peer tg.InputPeerClass, maxID int) (channel *tg.ChannelsReadHistoryRequest, chat *tg.MessagesReadHistoryRequest, err error) {
	switch p := peer.(type) {
	case *tg.InputPeerChannel:
		return &tg.ChannelsReadHistoryRequest{Channel: &tg.InputChannel{ChannelID: p.ChannelID, AccessHash: p.AccessHash}, MaxID: maxID}, nil, nil
	case *tg.InputPeerChannelFromMessage:
		return &tg.ChannelsReadHistoryRequest{Channel: &tg.InputChannelFromMessage{Peer: p.Peer, MsgID: p.MsgID, ChannelID: p.ChannelID}, MaxID: maxID}, nil, nil
	case *tg.InputPeerUser, *tg.InputPeerChat, *tg.InputPeerUserFromMessage:
		return nil, &tg.MessagesReadHistoryRequest{Peer: peer, MaxID: maxID}, nil
	default:
		return nil, nil, errReadNotAChat
	}
}

// MarkReadResult is what MarkRead marked.
type MarkReadResult struct {
	// Ref is the canonical ref of the chat.
	Ref string
	// TopicID and TopicTitle name the forum topic marked read, 0 and ""
	// when the call named none.
	TopicID    int
	TopicTitle string
}

// readInvoker is the subset of *tg.Client MarkRead uses, so the routing can
// be tested without a live MTProto client.
type readInvoker interface {
	topicByIDInvoker
	ChannelsReadHistory(ctx context.Context, req *tg.ChannelsReadHistoryRequest) (bool, error)
	MessagesReadHistory(ctx context.Context, req *tg.MessagesReadHistoryRequest) (*tg.MessagesAffectedMessages, error)
	MessagesReadDiscussion(ctx context.Context, req *tg.MessagesReadDiscussionRequest) (bool, error)
}

// MarkRead marks every message in peerSpec up to and including maxID as
// read in the user's own account. The other side of a private chat sees
// the read receipt, so callers gate it like a send.
//
// A non-zero topicID marks only that forum topic read: the chat must be a
// forum and the topic must exist (a closed topic can still be read). The
// General topic is the chat's own history, so topic 1 reads it the way a
// call without a topic does.
func MarkRead(ctx context.Context, c *gotdtelegram.Client, peerSpec string, maxID, topicID int, cache *PeerCache, userID int64) (MarkReadResult, error) {
	inputPeer, err := ResolvePeerCached(ctx, c, peerSpec, cache, userID)
	if err != nil {
		return MarkReadResult{}, fmt.Errorf("resolve peer: %w", err)
	}
	return markReadWith(ctx, c.API(), inputPeer, peerSpec, maxID, topicID)
}

func markReadWith(ctx context.Context, api readInvoker, inputPeer tg.InputPeerClass, peerSpec string, maxID, topicID int) (MarkReadResult, error) {
	out := MarkReadResult{Ref: inputPeerRef(inputPeer)}
	if topicID != 0 {
		t, err := lookupTopic(ctx, api, peerSpec, inputPeer, topicID)
		if err != nil {
			return MarkReadResult{}, err
		}
		out.TopicID, out.TopicTitle = t.ID, t.Title
		if topicID > generalTopicID {
			if _, err := api.MessagesReadDiscussion(ctx, &tg.MessagesReadDiscussionRequest{Peer: inputPeer, MsgID: topicID, ReadMaxID: maxID}); err != nil {
				return MarkReadResult{}, topicRPCError("MessagesReadDiscussion", err)
			}
			return out, nil
		}
	}
	channel, chat, err := readHistoryRequest(inputPeer, maxID)
	if err != nil {
		return MarkReadResult{}, fmt.Errorf("resolve peer: %q: %w", peerSpec, err)
	}
	if channel != nil {
		if _, err := api.ChannelsReadHistory(ctx, channel); err != nil {
			return MarkReadResult{}, fmt.Errorf("ChannelsReadHistory: %w", err)
		}
	} else if _, err := api.MessagesReadHistory(ctx, chat); err != nil {
		return MarkReadResult{}, fmt.Errorf("MessagesReadHistory: %w", err)
	}
	return out, nil
}
