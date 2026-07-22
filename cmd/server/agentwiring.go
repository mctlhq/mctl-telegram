package main

import (
	"context"
	"fmt"
	"strconv"

	gotdtelegram "github.com/gotd/td/telegram"

	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// poolSender adapts telegram.ClientPool to executor.Sender: borrow the
// account's pooled MTProto client, resolve the conversation's peer by
// Telegram id, and send with the caller-supplied random_id (crash-recovery
// dedup — see internal/agent/executor's package doc). Peers are addressed
// as "user:<id>" — communication-agent conversations are private-user chats
// only, matching internal/telegram.ResolvePeer's supported forms.
type poolSender struct {
	pool *telegram.ClientPool
}

func (s *poolSender) SendWithRandomID(ctx context.Context, userID, peerTGID, randomID int64, text string) (int64, error) {
	var messageID int
	err := s.pool.Borrow(ctx, userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		res, err := telegram.SendMessageWithRandomID(ctx, c, "user:"+strconv.FormatInt(peerTGID, 10), text, randomID, nil, userID)
		if err != nil {
			return err
		}
		messageID = res.MessageID
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
