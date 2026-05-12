package telegram

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

type SendResult struct {
	Mode       string `json:"mode"` // "send" or "draft"
	PeerInput  string `json:"peer"`
	Text       string `json:"text"`
	Truncated  bool   `json:"truncated,omitempty"`
	MessageID  int    `json:"message_id,omitempty"`
	DryReason  string `json:"dry_reason,omitempty"`
}

// SendMessage either sends a real message (mode="send" and gate allows) or
// returns a dry-run preview (mode="draft" or gate denies).
//
// Gate is evaluated by the caller; this fn assumes the green light when
// realSend is true.
func SendMessage(ctx context.Context, c *telegram.Client, peer string, text string, realSend bool, dryReason string) (*SendResult, error) {
	if text == "" {
		return nil, fmt.Errorf("text required")
	}
	if !realSend {
		return &SendResult{
			Mode:      "draft",
			PeerInput: peer,
			Text:      text,
			DryReason: dryReason,
		}, nil
	}

	inputPeer, err := ResolvePeer(ctx, c, peer)
	if err != nil {
		return nil, err
	}
	var randomID int64
	{
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		randomID = int64(binary.LittleEndian.Uint64(b[:]))
	}
	updates, err := c.API().MessagesSendMessage(ctx, &tg.MessagesSendMessageRequest{
		Peer:     inputPeer,
		Message:  text,
		RandomID: randomID,
	})
	if err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	msgID := extractMessageID(updates)
	return &SendResult{
		Mode:      "send",
		PeerInput: peer,
		Text:      text,
		MessageID: msgID,
	}, nil
}

func extractMessageID(u tg.UpdatesClass) int {
	switch v := u.(type) {
	case *tg.UpdateShortSentMessage:
		return v.ID
	case *tg.Updates:
		for _, upd := range v.Updates {
			if id := messageIDFromUpdate(upd); id > 0 {
				return id
			}
		}
	case *tg.UpdatesCombined:
		for _, upd := range v.Updates {
			if id := messageIDFromUpdate(upd); id > 0 {
				return id
			}
		}
	}
	return 0
}

func messageIDFromUpdate(u tg.UpdateClass) int {
	switch v := u.(type) {
	case *tg.UpdateNewMessage:
		if m, ok := v.Message.(*tg.Message); ok {
			return m.ID
		}
	case *tg.UpdateNewChannelMessage:
		if m, ok := v.Message.(*tg.Message); ok {
			return m.ID
		}
	case *tg.UpdateMessageID:
		return v.ID
	}
	return 0
}
