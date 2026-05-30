package telegram

import (
	"context"
	"fmt"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// SetReaction adds or removes a reaction on a message.
// When emoji is non-empty the reaction is added (or replaced); when emoji is
// empty the reaction is removed (empty Reaction list instructs Telegram to clear).
// big=true sends the animated "big" reaction if the client supports it.
func SetReaction(ctx context.Context, c *gotdtelegram.Client, peerSpec string, messageID int, emoji string, big bool, cache *PeerCache, userID int64) error {
	inputPeer, err := ResolvePeerCached(ctx, c, peerSpec, cache, userID)
	if err != nil {
		return fmt.Errorf("resolve peer: %w", err)
	}

	// Use an explicit empty slice (not nil) when removing a reaction.
	// In the TL encoding, nil may leave the Reaction field absent (flag not
	// set), which means "no change" rather than "clear". An empty non-nil
	// slice encodes as an empty Vector with the flag set, which Telegram
	// interprets as "remove all reactions from this message".
	reactions := []tg.ReactionClass{}
	if emoji != "" {
		reactions = []tg.ReactionClass{&tg.ReactionEmoji{Emoticon: emoji}}
	}

	_, err = c.API().MessagesSendReaction(ctx, &tg.MessagesSendReactionRequest{
		Peer:        inputPeer,
		MsgID:       messageID,
		Reaction:    reactions,
		Big:         big,
		AddToRecent: emoji != "",
	})
	if err != nil {
		return fmt.Errorf("MessagesSendReaction: %w", err)
	}
	return nil
}
