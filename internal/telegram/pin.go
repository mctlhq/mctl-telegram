package telegram

import (
	"context"
	"fmt"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// PinMessage pins (or unpins when unpin=true) a message in any dialog type.
// The operator must have the "Pin Messages" admin right in groups/channels.
func PinMessage(ctx context.Context, c *telegram.Client, peerSpec string, messageID int, unpin bool) error {
	if peerSpec == "" {
		return fmt.Errorf("peer is required")
	}
	if messageID <= 0 {
		return fmt.Errorf("message_id must be positive")
	}
	api := c.API()

	dlgRes, err := api.MessagesGetDialogs(ctx, &tg.MessagesGetDialogsRequest{
		Limit:      200,
		OffsetPeer: &tg.InputPeerEmpty{},
	})
	if err != nil {
		return fmt.Errorf("MessagesGetDialogs: %w", err)
	}
	users, chats, dialogs := decodeDialogsResult(dlgRes)

	for _, dc := range dialogs {
		d, ok := dc.(*tg.Dialog)
		if !ok {
			continue
		}
		hint := dialogFromPeer(d, users, chats)
		if hint == nil {
			continue
		}
		if hint.ID != peerSpec && !matchUsername(hint.Username, peerSpec) {
			continue
		}
		input := inputPeerFromPeer(d.Peer, users, chats)
		if input == nil {
			return fmt.Errorf("cannot build InputPeer for %q", peerSpec)
		}

		req := &tg.MessagesUpdatePinnedMessageRequest{
			Peer:  input,
			ID:    messageID,
			Unpin: unpin,
		}
		if _, err := api.MessagesUpdatePinnedMessage(ctx, req); err != nil {
			action := "pin"
			if unpin {
				action = "unpin"
			}
			return fmt.Errorf("%s message: %w", action, err)
		}
		return nil
	}
	return fmt.Errorf("peer %q not found in dialogs", peerSpec)
}
