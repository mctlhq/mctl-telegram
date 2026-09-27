package telegram

import (
	"context"
	"fmt"
	"strings"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// SearchParams describes one search_messages query. Zero MinDate/MaxDate mean
// unbounded, which is Telegram's own encoding for those fields.
type SearchParams struct {
	Peer    string
	Query   string
	Limit   int
	MinDate time.Time
	MaxDate time.Time
}

// searchInvoker is the slice of *tg.Client the search path uses. It exists so
// tests can capture the constructed requests without a live MTProto client.
type searchInvoker interface {
	MessagesSearchGlobal(ctx context.Context, req *tg.MessagesSearchGlobalRequest) (tg.MessagesMessagesClass, error)
	MessagesSearch(ctx context.Context, req *tg.MessagesSearchRequest) (tg.MessagesMessagesClass, error)
}

// minDateUnix converts a min_date bound to the Unix seconds value for the
// MTProto MinDate field. The user-facing min_date bound is inclusive, but
// MessagesSearch(Global) treats MinDate as exclusive (it returns only
// messages with date > MinDate), so the bound is shifted back by one second
// to include messages sent exactly at min_date. Returns 0 (Telegram's
// "unbounded" value) for the zero time.
func minDateUnix(t time.Time) int {
	if t.IsZero() {
		return 0
	}
	return int(t.Unix()) - 1
}

// maxDateUnix converts a max_date bound to the Unix seconds value for the
// MTProto MaxDate field. The user-facing max_date bound is inclusive, but
// MessagesSearch(Global) treats MaxDate as exclusive (it returns only
// messages with date < MaxDate), so the bound is shifted forward by one
// second to include messages sent exactly at max_date. Returns 0
// (Telegram's "unbounded" value) for the zero time.
func maxDateUnix(t time.Time) int {
	if t.IsZero() {
		return 0
	}
	return int(t.Unix()) + 1
}

// SearchMessages searches for messages matching query.
// When p.Peer is non-empty the search is scoped to that chat;
// when empty a global Telegram search is performed.
func SearchMessages(ctx context.Context, c *gotdtelegram.Client, p SearchParams, cache *PeerCache, userID int64) ([]Message, error) {
	if p.Query == "" {
		return nil, fmt.Errorf("query must not be empty")
	}
	if p.Limit <= 0 {
		p.Limit = 20
	} else if p.Limit > 100 {
		p.Limit = 100
	}
	api := c.API()

	if p.Peer == "" {
		return searchGlobalWith(ctx, api, p)
	}

	inputPeer, err := ResolvePeerCached(ctx, c, p.Peer, cache, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve peer: %w", err)
	}
	return searchPeerWith(ctx, api, inputPeer, p)
}

// searchGlobalWith runs a global search_messages query against api.
func searchGlobalWith(ctx context.Context, api searchInvoker, p SearchParams) ([]Message, error) {
	res, err := api.MessagesSearchGlobal(ctx, &tg.MessagesSearchGlobalRequest{
		Q:          p.Query,
		Filter:     &tg.InputMessagesFilterEmpty{},
		OffsetPeer: &tg.InputPeerEmpty{},
		Limit:      p.Limit,
		MinDate:    minDateUnix(p.MinDate),
		MaxDate:    maxDateUnix(p.MaxDate),
	})
	if err != nil {
		return nil, fmt.Errorf("MessagesSearchGlobal: %w", err)
	}
	users, chats := extractSearchMaps(res)
	return decodeGlobalSearchMessages(res, users, chats, p.Limit), nil
}

// searchPeerWith runs a per-peer search_messages query against api.
func searchPeerWith(ctx context.Context, api searchInvoker, peer tg.InputPeerClass, p SearchParams) ([]Message, error) {
	res, err := api.MessagesSearch(ctx, &tg.MessagesSearchRequest{
		Peer:    peer,
		Q:       p.Query,
		Filter:  &tg.InputMessagesFilterEmpty{},
		Limit:   p.Limit,
		MinDate: minDateUnix(p.MinDate),
		MaxDate: maxDateUnix(p.MaxDate),
	})
	if err != nil {
		return nil, fmt.Errorf("MessagesSearch: %w", err)
	}
	hint := &Dialog{ID: p.Peer, Title: p.Peer}
	users, chats := extractSearchMaps(res)
	return decodeMessages(res, hint, users, chats, p.Limit), nil
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
