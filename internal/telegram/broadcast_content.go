package telegram

import (
	"context"
	"errors"
	"fmt"

	"github.com/gotd/td/tg"
)

// BroadcastContent says whether the content tools hand broadcast channel
// posts to the caller. It is the BROADCAST_CONTENT_ENABLED kill switch: on,
// channel posts are read and get_messages/get_unread_messages attach the
// channel's sponsored messages (Telegram API terms §3.3); off, every content
// read refuses a broadcast channel exactly as issue #851 did. The zero value
// refuses, so a caller that forgets to pass it fails closed.
type BroadcastContent bool

const (
	BroadcastContentRefused BroadcastContent = false
	BroadcastContentAllowed BroadcastContent = true
)

// ErrBroadcastContent marks a refusal to read the content of a broadcast
// channel. It is returned only while the BroadcastContent switch is off
// (issue #851): Telegram's API terms (§3.3) require an app that displays
// channel posts to show official sponsored messages, and with the switch off
// this server does not hand channel posts to the AI at all. Match it with
// errors.Is.
//
// Only content is refused. A channel's name, id and unread count stay in
// list_dialogs, and private chats, legacy groups and megagroups (supergroups,
// gigagroups) are not affected.
var ErrBroadcastContent = errors.New("telegram: broadcast channel content is not available")

// broadcastContentError is the refusal returned for one peer. Its text tells
// the caller what still works so the model does not retry with another spec.
type broadcastContentError struct {
	peer string
}

func (e *broadcastContentError) Error() string {
	return fmt.Sprintf("peer %q is a broadcast channel: MCTL Assistant does not read channel posts, "+
		"so get_messages, get_unread_messages, search_messages and get_media refuse it. "+
		"The channel stays listed in list_dialogs (name and unread count); private chats and groups are not affected", e.peer)
}

func (e *broadcastContentError) Is(target error) bool {
	return target == ErrBroadcastContent
}

// channelLookup is the one call refuseBroadcastPeer needs, so tests can
// answer it without a live MTProto client.
type channelLookup interface {
	ChannelsGetChannels(ctx context.Context, id []tg.InputChannelClass) (tg.MessagesChatsClass, error)
}

// refuseBroadcastPeer returns a broadcastContentError unless input is
// positively known not to be a broadcast channel. Users, Saved Messages and
// legacy groups pass without a call. A channel peer is looked up with
// channels.getChannels and passes only when Telegram reports it as a
// megagroup; a channel missing from a successful reply is refused, because
// a type that could not be observed is not a group. A failed lookup is
// returned as an ordinary error, never as a pass.
func refuseBroadcastPeer(ctx context.Context, api channelLookup, peerSpec string, input tg.InputPeerClass) error {
	switch v := input.(type) {
	case *tg.InputPeerUser, *tg.InputPeerSelf, *tg.InputPeerChat, *tg.InputPeerUserFromMessage:
		return nil
	case *tg.InputPeerChannel:
		res, err := api.ChannelsGetChannels(ctx, []tg.InputChannelClass{
			&tg.InputChannel{ChannelID: v.ChannelID, AccessHash: v.AccessHash},
		})
		if err != nil {
			return fmt.Errorf("check whether %q is a broadcast channel: ChannelsGetChannels: %w", peerSpec, err)
		}
		var chats []tg.ChatClass
		switch r := res.(type) {
		case *tg.MessagesChats:
			chats = r.Chats
		case *tg.MessagesChatsSlice:
			chats = r.Chats
		}
		for _, c := range chats {
			if ch, ok := c.(*tg.Channel); ok && ch.ID == v.ChannelID && ch.Megagroup {
				return nil
			}
		}
		return &broadcastContentError{peer: peerSpec}
	default:
		// InputPeerChannelFromMessage, InputPeerEmpty and any constructor
		// added later: the type is unknown, so the content is not read.
		return &broadcastContentError{peer: peerSpec}
	}
}
