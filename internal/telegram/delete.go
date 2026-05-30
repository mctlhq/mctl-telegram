package telegram

import (
	"context"
	"fmt"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// DeleteResult is returned by DeleteMessages on success.
type DeleteResult struct {
	Deleted    bool   `json:"deleted"`
	Count      int    `json:"count"`
	Peer       string `json:"peer"`
	MessageIDs []int  `json:"message_ids"`
}

// DeleteMessages deletes one or more messages from a chat.
// For channel peers, uses the channel-specific delete API.
// Revoke=true removes the messages for all parties, matching Telegram's
// default behavior for user accounts.
func DeleteMessages(ctx context.Context, c *gotdtelegram.Client, peerSpec string, messageIDs []int, cache *PeerCache, userID int64) (*DeleteResult, error) {
	if len(messageIDs) == 0 {
		return nil, fmt.Errorf("message_ids must not be empty")
	}
	inputPeer, err := ResolvePeerCached(ctx, c, peerSpec, cache, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve peer: %w", err)
	}

	ids := make([]int, len(messageIDs))
	copy(ids, messageIDs)

	switch p := inputPeer.(type) {
	case *tg.InputPeerChannel:
		_, err = c.API().ChannelsDeleteMessages(ctx, &tg.ChannelsDeleteMessagesRequest{
			Channel: &tg.InputChannel{ChannelID: p.ChannelID, AccessHash: p.AccessHash},
			ID:      ids,
		})
	default:
		_, err = c.API().MessagesDeleteMessages(ctx, &tg.MessagesDeleteMessagesRequest{
			Revoke: true,
			ID:     ids,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("DeleteMessages: %w", err)
	}
	return &DeleteResult{Deleted: true, Count: len(messageIDs), Peer: peerSpec, MessageIDs: messageIDs}, nil
}
