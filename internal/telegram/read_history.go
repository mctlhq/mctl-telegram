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

// MarkRead marks every message in peerSpec up to and including maxID as
// read in the user's own account. The other side of a private chat sees
// the read receipt, so callers gate it like a send.
func MarkRead(ctx context.Context, c *gotdtelegram.Client, peerSpec string, maxID int, cache *PeerCache, userID int64) (string, error) {
	inputPeer, err := ResolvePeerCached(ctx, c, peerSpec, cache, userID)
	if err != nil {
		return "", fmt.Errorf("resolve peer: %w", err)
	}
	channel, chat, err := readHistoryRequest(inputPeer, maxID)
	if err != nil {
		return "", fmt.Errorf("resolve peer: %q: %w", peerSpec, err)
	}
	if channel != nil {
		if _, err := c.API().ChannelsReadHistory(ctx, channel); err != nil {
			return "", fmt.Errorf("ChannelsReadHistory: %w", err)
		}
	} else if _, err := c.API().MessagesReadHistory(ctx, chat); err != nil {
		return "", fmt.Errorf("MessagesReadHistory: %w", err)
	}
	return inputPeerRef(inputPeer), nil
}
