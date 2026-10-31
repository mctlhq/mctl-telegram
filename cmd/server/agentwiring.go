package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
	"github.com/mctlhq/mctl-telegram/internal/db"
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
	pool      *telegram.ClientPool
	store     *db.Store
	peerCache *telegram.PeerCache
}

func (s *poolSender) SendWithRandomID(ctx context.Context, userID, peerTGID, peerAccessHash, randomID int64, text string) (int64, error) {
	var messageID int
	err := s.pool.Borrow(ctx, userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		peer := &tg.InputPeerUser{UserID: peerTGID, AccessHash: peerAccessHash}
		if peerAccessHash == 0 {
			resolved, err := telegram.ResolveUserPeerFromDialogs(ctx, c, peerTGID, s.peerCache, userID)
			if err != nil {
				return fmt.Errorf("recover peer access hash: %w", err)
			}
			peer = resolved
			if s.store != nil {
				if err := s.store.SetConversationPeerAccessHash(ctx, userID, peerTGID, resolved.AccessHash); err != nil {
					return fmt.Errorf("persist recovered peer access hash: %w", err)
				}
			}
		}
		id, err := telegram.SendToInputPeerWithRandomID(ctx, c, userID, peer, text, randomID)
		if err != nil {
			return err
		}
		messageID = id
		return nil
	})
	if err != nil {
		return 0, mapPoolSendError(err)
	}
	return int64(messageID), nil
}

// The executor only looks the id up when its Sender has this capability.
var _ executor.DeliveryLocator = (*poolSender)(nil)

// LocateDelivered implements executor.DeliveryLocator over the account's
// recent history with the peer (#1029). It does not recover a missing access
// hash: a send that reached Telegram was built with a working peer, so a
// zero hash here means there is nothing safe to look up with.
func (s *poolSender) LocateDelivered(ctx context.Context, userID, peerTGID, peerAccessHash int64, text string, since time.Time) (int64, bool, error) {
	if peerAccessHash == 0 {
		return 0, false, nil
	}
	var (
		messageID int
		found     bool
	)
	err := s.pool.Borrow(ctx, userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		var err error
		messageID, found, err = telegram.LocateOwnOutgoing(ctx, c, userID,
			&tg.InputPeerUser{UserID: peerTGID, AccessHash: peerAccessHash}, text, since)
		return err
	})
	if err != nil {
		return 0, false, fmt.Errorf("locate delivered via pool: %w", err)
	}
	return int64(messageID), found, nil
}

// mapPoolSendError translates telegram.ErrRandomIDDuplicate into the
// executor's ErrAlreadyDelivered, the contract executor.Sender documents.
func mapPoolSendError(err error) error {
	if errors.Is(err, telegram.ErrRandomIDDuplicate) {
		return fmt.Errorf("send via pool: %w: %w", executor.ErrAlreadyDelivered, err)
	}
	return fmt.Errorf("send via pool: %w", err)
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
