package telegram

import (
	"context"
	"fmt"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// EditResult is returned by EditMessage on success.
type EditResult struct {
	Edited    bool   `json:"edited"`
	MessageID int    `json:"message_id"`
	Peer      string `json:"peer"`
}

// EditMessage edits the text of a previously sent message. The caller must
// own the message (bot accounts can edit their own messages; user accounts
// can edit messages they sent themselves).
func EditMessage(ctx context.Context, c *gotdtelegram.Client, peerSpec string, messageID int, newText string, cache *PeerCache, userID int64) (*EditResult, error) {
	inputPeer, err := ResolvePeerCached(ctx, c, peerSpec, cache, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve peer: %w", err)
	}
	_, err = c.API().MessagesEditMessage(ctx, &tg.MessagesEditMessageRequest{
		Peer:    inputPeer,
		ID:      messageID,
		Message: newText,
	})
	if err != nil {
		return nil, fmt.Errorf("MessagesEditMessage: %w", err)
	}
	return &EditResult{Edited: true, MessageID: messageID, Peer: peerSpec}, nil
}
