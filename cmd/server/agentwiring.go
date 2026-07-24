package main

import (
	"context"
	"fmt"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// poolSender adapts telegram.ClientPool to executor.Sender: borrow the
// account's pooled MTProto client and send with the caller-supplied
// peerAccessHash and random_id (crash-recovery dedup — see
// internal/agent/executor's package doc). Builds the InputPeerUser directly
// from (peerTGID, peerAccessHash) rather than going through
// telegram.ResolvePeer's string-based path: ResolvePeer has no way to
// recover an access_hash for a bare "user:<id>" spec (it returns a
// zero-hash peer, which MTProto's messages.* RPCs reject with
// PEER_ID_INVALID), whereas the conversation row already carries a real one
// captured by the listener from the peer's own incoming messages — see
// db.Store.SetConversationPeerAccessHash.
type poolSender struct {
	pool *telegram.ClientPool
}

func (s *poolSender) SendWithRandomID(ctx context.Context, userID, peerTGID, peerAccessHash, randomID int64, text string) (int64, error) {
	var messageID int
	err := s.pool.Borrow(ctx, userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		peer := &tg.InputPeerUser{UserID: peerTGID, AccessHash: peerAccessHash}
		id, err := telegram.SendToInputPeerWithRandomID(ctx, c, userID, peer, text, randomID)
		if err != nil {
			return err
		}
		messageID = id
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("send via pool: %w", err)
	}
	return int64(messageID), nil
}

// poolSelfSender adapts telegram.ClientPool to control.SelfSender: posts
// into the account owner's own Saved Messages.
type poolSelfSender struct {
	pool *telegram.ClientPool
}

func (s *poolSelfSender) SendToSelf(ctx context.Context, userID int64, text string) (int64, error) {
	var messageID int
	err := s.pool.Borrow(ctx, userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		id, err := telegram.SendToSelf(ctx, c, userID, text)
		if err != nil {
			return err
		}
		messageID = id
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("send to self via pool: %w", err)
	}
	return int64(messageID), nil
}

func (s *poolSelfSender) SendToSelfWithRandomID(ctx context.Context, userID, randomID int64, text string) (int64, error) {
	var messageID int
	err := s.pool.Borrow(ctx, userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		id, err := telegram.SendToSelfWithRandomID(ctx, c, userID, randomID, text)
		if err != nil {
			return err
		}
		messageID = id
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("send to self via pool: %w", err)
	}
	return int64(messageID), nil
}
