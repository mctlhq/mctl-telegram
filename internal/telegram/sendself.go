package telegram

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// SendToInputPeer sends a plain text message to an already-resolved peer and
// returns the new Telegram message id. Unlike SendMessage it takes an
// InputPeerClass directly — the communication agent's executor derives the
// peer from the conversation row (never from model output), and the owner
// notifier targets InputPeerSelf, so neither has a peer string to resolve.
func SendToInputPeer(ctx context.Context, c *telegram.Client, peer tg.InputPeerClass, text string) (int, error) {
	if text == "" {
		return 0, fmt.Errorf("text required")
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	randomID := int64(binary.LittleEndian.Uint64(b[:]))
	updates, err := c.API().MessagesSendMessage(ctx, &tg.MessagesSendMessageRequest{
		Peer:     peer,
		Message:  text,
		RandomID: randomID,
	})
	if err != nil {
		return 0, fmt.Errorf("send: %w", err)
	}
	return extractMessageID(updates), nil
}

// SendToSelf sends a message to the account's own Saved Messages. This is the
// owner-notification path: a bot token cannot post into Saved Messages, so
// summaries and approval requests go through the owner's own MTProto session.
func SendToSelf(ctx context.Context, c *telegram.Client, text string) (int, error) {
	return SendToInputPeer(ctx, c, &tg.InputPeerSelf{}, text)
}
