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
		// messages.deleteMessages carries no peer parameter — it deletes by
		// global message ID regardless of chat. Without this check a caller
		// could delete messages from a different chat than peerSpec while the
		// audit log (which only ever sees peerSpec) records the wrong one.
		if verifyErr := verifyMessagesBelongToPeer(ctx, c, inputPeer, peerSpec, ids); verifyErr != nil {
			return nil, verifyErr
		}
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

// verifyMessagesBelongToPeer confirms every id in ids resolves to a message
// whose owning dialog is inputPeer, fetching them via the same global
// messages.getMessages call messages.deleteMessages implicitly relies on.
// Fails closed: a missing or mismatched id aborts the whole batch rather than
// silently deleting only the matching subset.
func verifyMessagesBelongToPeer(ctx context.Context, c *gotdtelegram.Client, inputPeer tg.InputPeerClass, peerSpec string, ids []int) error {
	inputIDs := make([]tg.InputMessageClass, len(ids))
	for i, id := range ids {
		inputIDs[i] = &tg.InputMessageID{ID: id}
	}
	result, err := c.API().MessagesGetMessages(ctx, inputIDs)
	if err != nil {
		return fmt.Errorf("verify message ownership: %w", err)
	}
	var rawMsgs []tg.MessageClass
	switch v := result.(type) {
	case *tg.MessagesMessages:
		rawMsgs = v.Messages
	case *tg.MessagesMessagesSlice:
		rawMsgs = v.Messages
	case *tg.MessagesChannelMessages:
		rawMsgs = v.Messages
	}
	found := make(map[int]*tg.Message, len(rawMsgs))
	for _, mc := range rawMsgs {
		if m, ok := mc.(*tg.Message); ok {
			found[m.ID] = m
		}
	}
	for _, id := range ids {
		msg, ok := found[id]
		if !ok {
			return fmt.Errorf("message %d not found", id)
		}
		if !messageBelongsToPeer(msg, inputPeer) {
			return fmt.Errorf("message %d does not belong to peer %q", id, peerSpec)
		}
	}
	return nil
}
