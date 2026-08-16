package telegram

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

type Dialog struct {
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	Title           string    `json:"title"`
	Username        string    `json:"username,omitempty"`
	UnreadCount     int       `json:"unread_count"`
	LastMessageDate time.Time `json:"last_message_date,omitempty"`
}

// ListDialogs returns up to `limit` dialogs from the operator's main dialog
// list, optionally filtered (case-insensitive substring) by `query`.
//
// When cache and userID are provided it seeds the shared PeerCache with the
// access_hash for every returned peer, so a follow-up get_messages/send_message
// for one of these dialogs resolves correctly instead of failing with
// PEER_ID_INVALID/CHANNEL_INVALID. Pass a nil cache / zero userID to skip seeding.
func ListDialogs(ctx context.Context, c *telegram.Client, limit int, query string, cache *PeerCache, userID int64) ([]Dialog, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	api := c.API()
	res, err := api.MessagesGetDialogs(ctx, &tg.MessagesGetDialogsRequest{
		Limit:      limit,
		OffsetPeer: &tg.InputPeerEmpty{},
	})
	if err != nil {
		return nil, fmt.Errorf("MessagesGetDialogs: %w", err)
	}

	users, chats, dialogs := decodeDialogsResult(res)
	seedPeerCache(cache, userID, users, chats)
	return dialogEntries(dialogs, users, chats, dialogsTopMessages(res), query), nil
}

// dialogEntries maps MessagesGetDialogs dialogs (plus the sibling message
// objects) into []Dialog. LastMessageDate is taken from the top-message
// object when present; missing or undated messages leave the zero time.
func dialogEntries(dialogs []tg.DialogClass, users map[int64]*tg.User, chats map[int64]tg.ChatClass, messages []tg.MessageClass, query string) []Dialog {
	dates := topMessageDates(messages)
	out := make([]Dialog, 0, len(dialogs))
	for _, dc := range dialogs {
		d, ok := dc.(*tg.Dialog)
		if !ok {
			continue
		}
		entry := dialogFromPeer(d, users, chats)
		if entry == nil {
			continue
		}
		if ts, ok := lastMessageDateFor(d, dates); ok {
			entry.LastMessageDate = ts
		}
		if query != "" && !strings.Contains(strings.ToLower(entry.Title), strings.ToLower(query)) &&
			!strings.Contains(strings.ToLower(entry.Username), strings.ToLower(query)) {
			continue
		}
		out = append(out, *entry)
	}
	return out
}

// ResolveUserPeerFromDialogs recovers a hash-bearing InputPeerUser when a
// short update did not include Entities.Users. UpdateShortMessage commonly
// has exactly that shape, so relying only on update-local entities leaves a
// zero access_hash and makes messages.sendMessage fail with PEER_ID_INVALID.
//
// The most recent 200 dialogs are sufficient for an actively messaging peer;
// the result is also seeded into the shared cache and persisted by the caller.
func ResolveUserPeerFromDialogs(ctx context.Context, c *telegram.Client, peerTGID int64, cache *PeerCache, userID int64) (*tg.InputPeerUser, error) {
	peerSpec := fmt.Sprintf("user:%d", peerTGID)
	if cache != nil {
		if cached, ok := cache.Get(userID, peerSpec); ok {
			if peer, ok := cached.(*tg.InputPeerUser); ok && peer.AccessHash != 0 {
				return peer, nil
			}
		}
	}
	res, err := c.API().MessagesGetDialogs(ctx, &tg.MessagesGetDialogsRequest{
		Limit:      200,
		OffsetPeer: &tg.InputPeerEmpty{},
	})
	if err != nil {
		return nil, fmt.Errorf("MessagesGetDialogs: %w", err)
	}
	users, chats, _ := decodeDialogsResult(res)
	seedPeerCache(cache, userID, users, chats)
	u, ok := users[peerTGID]
	if !ok || u == nil || u.Min || u.AccessHash == 0 {
		return nil, fmt.Errorf("user:%d has no resolvable access hash in recent dialogs", peerTGID)
	}
	peer := &tg.InputPeerUser{UserID: peerTGID, AccessHash: u.AccessHash}
	if cache != nil {
		cache.Set(userID, peerSpec, peer)
	}
	return peer, nil
}

func decodeDialogsResult(r tg.MessagesDialogsClass) (users map[int64]*tg.User, chats map[int64]tg.ChatClass, dialogs []tg.DialogClass) {
	users = make(map[int64]*tg.User)
	chats = make(map[int64]tg.ChatClass)
	switch v := r.(type) {
	case *tg.MessagesDialogs:
		dialogs = v.Dialogs
		fillUserChatIndex(users, chats, v.Users, v.Chats)
	case *tg.MessagesDialogsSlice:
		dialogs = v.Dialogs
		fillUserChatIndex(users, chats, v.Users, v.Chats)
	case *tg.MessagesDialogsNotModified:
		// nothing
	}
	return users, chats, dialogs
}

func dialogsTopMessages(r tg.MessagesDialogsClass) []tg.MessageClass {
	switch v := r.(type) {
	case *tg.MessagesDialogs:
		return v.Messages
	case *tg.MessagesDialogsSlice:
		return v.Messages
	default:
		return nil
	}
}

type topMessageKey struct {
	peer string
	id   int
}

func peerClassKey(p tg.PeerClass) string {
	switch v := p.(type) {
	case *tg.PeerUser:
		return fmt.Sprintf("user:%d", v.UserID)
	case *tg.PeerChat:
		return fmt.Sprintf("chat:%d", v.ChatID)
	case *tg.PeerChannel:
		return fmt.Sprintf("channel:%d", v.ChannelID)
	default:
		return ""
	}
}

// topMessageDates maps (peer, message id) to the message Date from a
// MessagesGetDialogs result. Message IDs are not globally unique (each
// channel has its own id space), so the peer is part of the key. Messages
// with Date==0 are skipped so callers do not invent timestamps.
func topMessageDates(messages []tg.MessageClass) map[topMessageKey]time.Time {
	out := make(map[topMessageKey]time.Time, len(messages))
	for _, m := range messages {
		id, date, peer, ok := messageIDDatePeer(m)
		if !ok || date == 0 {
			continue
		}
		key := peerClassKey(peer)
		if key == "" {
			continue
		}
		out[topMessageKey{peer: key, id: id}] = time.Unix(int64(date), 0).UTC()
	}
	return out
}

func messageIDDatePeer(m tg.MessageClass) (id, date int, peer tg.PeerClass, ok bool) {
	switch v := m.(type) {
	case *tg.Message:
		return v.ID, v.Date, v.PeerID, true
	case *tg.MessageService:
		return v.ID, v.Date, v.PeerID, true
	default:
		return 0, 0, nil, false
	}
}

func lastMessageDateFor(d *tg.Dialog, dates map[topMessageKey]time.Time) (time.Time, bool) {
	if d == nil || d.TopMessage == 0 {
		return time.Time{}, false
	}
	ts, ok := dates[topMessageKey{peer: peerClassKey(d.Peer), id: d.TopMessage}]
	if !ok || ts.IsZero() {
		return time.Time{}, false
	}
	return ts, true
}

func fillUserChatIndex(users map[int64]*tg.User, chats map[int64]tg.ChatClass, us []tg.UserClass, cs []tg.ChatClass) {
	for _, u := range us {
		if user, ok := u.(*tg.User); ok {
			users[user.ID] = user
		}
	}
	for _, c := range cs {
		switch chat := c.(type) {
		case *tg.Chat:
			chats[chat.ID] = chat
		case *tg.Channel:
			chats[chat.ID] = chat
		case *tg.ChatForbidden:
			chats[chat.ID] = chat
		case *tg.ChannelForbidden:
			chats[chat.ID] = chat
		}
	}
}

func dialogFromPeer(d *tg.Dialog, users map[int64]*tg.User, chats map[int64]tg.ChatClass) *Dialog {
	switch p := d.Peer.(type) {
	case *tg.PeerUser:
		u, ok := users[p.UserID]
		if !ok {
			return nil
		}
		title := strings.TrimSpace(u.FirstName + " " + u.LastName)
		if title == "" {
			title = u.Username
		}
		return &Dialog{
			ID:          fmt.Sprintf("user:%d", u.ID),
			Type:        "user",
			Title:       title,
			Username:    u.Username,
			UnreadCount: d.UnreadCount,
		}
	case *tg.PeerChat:
		c, ok := chats[p.ChatID]
		if !ok {
			return nil
		}
		ch, _ := c.(*tg.Chat)
		title := ""
		if ch != nil {
			title = ch.Title
		}
		return &Dialog{
			ID:          fmt.Sprintf("chat:%d", p.ChatID),
			Type:        "chat",
			Title:       title,
			UnreadCount: d.UnreadCount,
		}
	case *tg.PeerChannel:
		c, ok := chats[p.ChannelID]
		if !ok {
			return nil
		}
		ch, _ := c.(*tg.Channel)
		title := ""
		username := ""
		if ch != nil {
			title = ch.Title
			username = ch.Username
		}
		return &Dialog{
			ID:          fmt.Sprintf("channel:%d", p.ChannelID),
			Type:        "channel",
			Title:       title,
			Username:    username,
			UnreadCount: d.UnreadCount,
		}
	}
	return nil
}
