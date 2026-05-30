package telegram

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// ForwardResult is returned by ForwardMessages on success.
type ForwardResult struct {
	Forwarded bool   `json:"forwarded"`
	Count     int    `json:"count"`
	FromPeer  string `json:"from_peer"`
	ToPeer    string `json:"to_peer"`
}

// ForwardMessages forwards one or more messages from fromPeerSpec to toPeerSpec.
// Each message gets a unique random ID as required by the Telegram API.
func ForwardMessages(ctx context.Context, c *gotdtelegram.Client, fromPeerSpec, toPeerSpec string, messageIDs []int, cache *PeerCache, userID int64) (*ForwardResult, error) {
	if len(messageIDs) == 0 {
		return nil, fmt.Errorf("message_ids must not be empty")
	}
	fromPeer, err := ResolvePeerCached(ctx, c, fromPeerSpec, cache, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve from_peer: %w", err)
	}
	toPeer, err := ResolvePeerCached(ctx, c, toPeerSpec, cache, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve to_peer: %w", err)
	}

	randomIDs := make([]int64, len(messageIDs))
	for i := range randomIDs {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, fmt.Errorf("random id: %w", err)
		}
		randomIDs[i] = int64(binary.LittleEndian.Uint64(b[:]))
	}

	ids := make([]int, len(messageIDs))
	copy(ids, messageIDs)

	_, err = c.API().MessagesForwardMessages(ctx, &tg.MessagesForwardMessagesRequest{
		FromPeer: fromPeer,
		ToPeer:   toPeer,
		ID:       ids,
		RandomID: randomIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("MessagesForwardMessages: %w", err)
	}
	return &ForwardResult{Forwarded: true, Count: len(messageIDs), FromPeer: fromPeerSpec, ToPeer: toPeerSpec}, nil
}
