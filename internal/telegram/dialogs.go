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
func ListDialogs(ctx context.Context, c *telegram.Client, limit int, query string) ([]Dialog, error) {
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
		if query != "" && !strings.Contains(strings.ToLower(entry.Title), strings.ToLower(query)) &&
			!strings.Contains(strings.ToLower(entry.Username), strings.ToLower(query)) {
			continue
		}
		out = append(out, *entry)
	}
	return out, nil
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
