package telegram

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

type SendResult struct {
	// Sent is the unambiguous "did this reach Telegram?" flag. It is the
	// first field so any client (including ChatGPT mobile) reading the result
	// gets a clear boolean rather than having to interpret Mode. false ⇒ a
	// dry-run preview; true ⇒ a real send.
	Sent      bool   `json:"sent"`
	Mode      string `json:"mode"` // "send" or "draft"
	Notice    string `json:"notice,omitempty"`
	PeerInput string `json:"peer"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated,omitempty"`
	MessageID int    `json:"message_id,omitempty"`
	DryReason string `json:"dry_reason,omitempty"`
}

// SendMessage either sends a real message (mode="send" and gate allows) or
// returns a dry-run preview (mode="draft" or gate denies).
//
// Gate is evaluated by the caller; this fn assumes the green light when
// realSend is true.
//
// cache and userID enable peer resolution caching; pass nil and 0 to disable.
func SendMessage(ctx context.Context, c *telegram.Client, peer string, text string, realSend bool, dryReason string, cache *PeerCache, userID int64) (*SendResult, error) {
	if text == "" {
		return nil, fmt.Errorf("text required")
	}
	if !realSend {
		return &SendResult{
			Sent:      false,
			Mode:      "draft",
			Notice:    "Draft preview — this message was NOT sent.",
			PeerInput: peer,
			Text:      text,
			DryReason: dryReason,
		}, nil
	}

	var randomID int64
	{
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		randomID = int64(binary.LittleEndian.Uint64(b[:]))
	}
	updates, err := sendWithPeerRetry(ctx, c, peer, cache, userID, func(inputPeer tg.InputPeerClass) (tg.UpdatesClass, error) {
		return c.API().MessagesSendMessage(ctx, &tg.MessagesSendMessageRequest{
			Peer:     inputPeer,
			Message:  text,
			RandomID: randomID,
		})
	})
	if err != nil {
		return nil, err
	}
	return &SendResult{
		Sent:      true,
		Mode:      "send",
		PeerInput: peer,
		Text:      text,
		MessageID: extractMessageID(updates),
	}, nil
}

// sendWithPeerRetry resolves peer via ResolvePeerCached and invokes send once
// with the resolved InputPeerClass. If send fails with PEER_ID_INVALID (and a
// cache is configured), it evicts the stale cache entry, re-resolves once,
// and retries send exactly once with the fresh peer. PEER_ID_INVALID
// guarantees the prior RPC did NOT deliver anything, so this single retry
// carries no double-send risk. Shared by SendMessage and SendMedia so the
// retry dance lives in exactly one place.
func sendWithPeerRetry(ctx context.Context, c *telegram.Client, peer string, cache *PeerCache, userID int64, send func(tg.InputPeerClass) (tg.UpdatesClass, error)) (tg.UpdatesClass, error) {
	inputPeer, err := ResolvePeerCached(ctx, c, peer, cache, userID)
	if err != nil {
		return nil, err
	}
	updates, sendErr := send(inputPeer)
	if sendErr != nil {
		var rpcErr *tgerr.Error
		if errors.As(sendErr, &rpcErr) && rpcErr.Message == "PEER_ID_INVALID" && cache != nil {
			cache.Evict(userID, peer)
			if inputPeer2, err2 := ResolvePeerCached(ctx, c, peer, cache, userID); err2 == nil {
				if updates2, sendErr2 := send(inputPeer2); sendErr2 == nil {
					return updates2, nil
				}
			}
		}
		return nil, fmt.Errorf("send: %w", sendErr)
	}
	return updates, nil
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
