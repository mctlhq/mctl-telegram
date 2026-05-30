package telegram

import (
	"context"
	"fmt"
	"strings"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// SearchMessages searches for messages matching query.
// When peerSpec is non-empty the search is scoped to that chat;
// when empty a global Telegram search is performed.
func SearchMessages(ctx context.Context, c *gotdtelegram.Client, peerSpec, query string, limit int, cache *PeerCache, userID int64) ([]Message, error) {
	if query == "" {
		return nil, fmt.Errorf("query must not be empty")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	api := c.API()

	if peerSpec == "" {
		res, err := api.MessagesSearchGlobal(ctx, &tg.MessagesSearchGlobalRequest{
			Q:          query,
			Filter:     &tg.InputMessagesFilterEmpty{},
			OffsetPeer: &tg.InputPeerEmpty{},
			Limit:      limit,
		})
		if err != nil {
			return nil, fmt.Errorf("MessagesSearchGlobal: %w", err)
		}
		users, chats := extractSearchMaps(res)
		return decodeGlobalSearchMessages(res, users, chats, limit), nil
	}

	inputPeer, err := ResolvePeerCached(ctx, c, peerSpec, cache, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve peer: %w", err)
	}
	res, err := api.MessagesSearch(ctx, &tg.MessagesSearchRequest{
		Peer:   inputPeer,
		Q:      query,
		Filter: &tg.InputMessagesFilterEmpty{},
		Limit:  limit,
	})
	if err != nil {
		return nil, fmt.Errorf("MessagesSearch: %w", err)
	}
	hint := &Dialog{ID: peerSpec, Title: peerSpec}
	users, chats := extractSearchMaps(res)
	return decodeMessages(res, hint, users, chats, limit), nil
}

// decodeGlobalSearchMessages decodes global-search results preserving the
// per-message peer identity derived from msg.PeerID. Unlike decodeMessages,
// which uses a single Dialog hint for all messages, this function resolves
// each message's Peer and PeerTitle from its own PeerID so callers can
// distinguish which chat each result came from.
func decodeGlobalSearchMessages(r tg.MessagesMessagesClass, users map[int64]*tg.User, chats map[int64]tg.ChatClass, max int) []Message {
	var raw []tg.MessageClass
	switch v := r.(type) {
	case *tg.MessagesMessages:
		raw = v.Messages
	case *tg.MessagesMessagesSlice:
		raw = v.Messages
	case *tg.MessagesChannelMessages:
		raw = v.Messages
	}
	out := make([]Message, 0, len(raw))
	for _, m := range raw {
		msg, ok := m.(*tg.Message)
		if !ok {
			continue
		}
		peerID, peerTitle := resolvePeerIDCanonical(msg.PeerID, users, chats)
		out = append(out, Message{
			ID:        msg.ID,
			Peer:      peerID,
			PeerTitle: peerTitle,
			From:      resolveSender(msg.FromID, users, chats),
			Text:      msg.Message,
			Date:      time.Unix(int64(msg.Date), 0).UTC(),
		})
		if len(out) >= max {
			break
		}
	}
	return out
}

// resolvePeerIDCanonical converts a PeerClass into a canonical peer string
// (e.g. "user:123", "chat:456", "channel:789") and a human-readable title.
func resolvePeerIDCanonical(p tg.PeerClass, users map[int64]*tg.User, chats map[int64]tg.ChatClass) (id, title string) {
	if p == nil {
		return "", ""
	}
	switch v := p.(type) {
	case *tg.PeerUser:
		id = fmt.Sprintf("user:%d", v.UserID)
		if u, ok := users[v.UserID]; ok {
			title = strings.TrimSpace(u.FirstName + " " + u.LastName)
			if u.Username != "" {
				title = "@" + u.Username
			}
		}
	case *tg.PeerChat:
		id = fmt.Sprintf("chat:%d", v.ChatID)
		if c, ok := chats[v.ChatID]; ok {
			if ch, ok2 := c.(*tg.Chat); ok2 {
				title = ch.Title
			}
		}
	case *tg.PeerChannel:
		id = fmt.Sprintf("channel:%d", v.ChannelID)
		if c, ok := chats[v.ChannelID]; ok {
			if ch, ok2 := c.(*tg.Channel); ok2 {
				title = ch.Title
				if ch.Username != "" {
					title = "@" + ch.Username
				}
			}
		}
	}
	return id, title
}

// extractSearchMaps pulls the user and chat maps out of a MessagesMessagesClass,
// which the search API uses for the same response type as history queries.
func extractSearchMaps(r tg.MessagesMessagesClass) (map[int64]*tg.User, map[int64]tg.ChatClass) {
	users := map[int64]*tg.User{}
	chats := map[int64]tg.ChatClass{}
	switch v := r.(type) {
	case *tg.MessagesMessages:
		fillUserChatIndex(users, chats, v.Users, v.Chats)
	case *tg.MessagesMessagesSlice:
		fillUserChatIndex(users, chats, v.Users, v.Chats)
	case *tg.MessagesChannelMessages:
		fillUserChatIndex(users, chats, v.Users, v.Chats)
	}
	return users, chats
}
