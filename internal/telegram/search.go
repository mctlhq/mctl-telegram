package telegram

import (
	"context"
	"fmt"

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
		// Global search results carry user/chat maps in the response.
		users, chats := extractSearchMaps(res)
		return decodeMessages(res, &Dialog{}, users, chats, limit), nil
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
