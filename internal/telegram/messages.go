package telegram

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

type Message struct {
	ID        int       `json:"id"`
	Peer      string    `json:"peer"`
	PeerTitle string    `json:"peer_title,omitempty"`
	From      string    `json:"from,omitempty"`
	Text      string    `json:"text"`
	Date      time.Time `json:"date"`
}

// GetUnreadMessages walks the dialog list (limit-bounded) and pulls up to
// `limit` total unread messages, scoped to one peer if provided.
func GetUnreadMessages(ctx context.Context, c *telegram.Client, peerSpec string, limit int) ([]Message, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	api := c.API()

	dlgRes, err := api.MessagesGetDialogs(ctx, &tg.MessagesGetDialogsRequest{
		Limit:      100,
		OffsetPeer: &tg.InputPeerEmpty{},
	})
	if err != nil {
		return nil, fmt.Errorf("MessagesGetDialogs: %w", err)
	}
	users, chats, dialogs := decodeDialogsResult(dlgRes)

	type target struct {
		input  tg.InputPeerClass
		dialog *tg.Dialog
		hint   *Dialog
	}
	var targets []target

	for _, dc := range dialogs {
		d, ok := dc.(*tg.Dialog)
		if !ok || d.UnreadCount == 0 {
			continue
		}
		hint := dialogFromPeer(d, users, chats)
		if hint == nil {
			continue
		}
		input := inputPeerFromPeer(d.Peer, users, chats)
		if input == nil {
			continue
		}
		if peerSpec != "" && hint.ID != peerSpec && !matchUsername(hint.Username, peerSpec) {
			continue
		}
		targets = append(targets, target{input: input, dialog: d, hint: hint})
	}

	// When an explicit peer was requested but not found in the dialog list,
	// return an actionable error rather than a silent empty result.
	if peerSpec != "" && len(targets) == 0 {
		return nil, fmt.Errorf("peer %q not found in recent dialogs — use get_messages for this peer's full history", peerSpec)
	}

	out := make([]Message, 0, limit)
	for _, t := range targets {
		if len(out) >= limit {
			break
		}
		take := t.dialog.UnreadCount
		if take > 50 {
			take = 50
		}
		if remaining := limit - len(out); take > remaining {
			take = remaining
		}
		hist, err := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{
			Peer:  t.input,
			Limit: take,
		})
		if err != nil {
			continue
		}
		out = append(out, decodeMessages(hist, t.hint, users, chats, take)...)
	}
	return out, nil
}

func inputPeerFromPeer(p tg.PeerClass, users map[int64]*tg.User, chats map[int64]tg.ChatClass) tg.InputPeerClass {
	switch v := p.(type) {
	case *tg.PeerUser:
		if u, ok := users[v.UserID]; ok {
			return &tg.InputPeerUser{UserID: u.ID, AccessHash: u.AccessHash}
		}
	case *tg.PeerChat:
		return &tg.InputPeerChat{ChatID: v.ChatID}
	case *tg.PeerChannel:
		if c, ok := chats[v.ChannelID]; ok {
			if ch, ok2 := c.(*tg.Channel); ok2 {
				return &tg.InputPeerChannel{ChannelID: ch.ID, AccessHash: ch.AccessHash}
			}
		}
	}
	return nil
}

func decodeMessages(r tg.MessagesMessagesClass, hint *Dialog, users map[int64]*tg.User, chats map[int64]tg.ChatClass, max int) []Message {
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
		out = append(out, Message{
			ID:        msg.ID,
			Peer:      hint.ID,
			PeerTitle: hint.Title,
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

func resolveSender(from tg.PeerClass, users map[int64]*tg.User, chats map[int64]tg.ChatClass) string {
	if from == nil {
		return ""
	}
	switch v := from.(type) {
	case *tg.PeerUser:
		if u, ok := users[v.UserID]; ok {
			if u.Username != "" {
				return "@" + u.Username
			}
			return strings.TrimSpace(u.FirstName + " " + u.LastName)
		}
	case *tg.PeerChannel:
		if c, ok := chats[v.ChannelID]; ok {
			if ch, ok2 := c.(*tg.Channel); ok2 {
				if ch.Username != "" {
					return "@" + ch.Username
				}
				return ch.Title
			}
		}
	}
	return ""
}

// GetMessages fetches the last `limit` messages from a specific peer
// regardless of read/unread state.
//
// cache and userID enable peer resolution caching; pass nil and 0 to disable.
func GetMessages(ctx context.Context, c *telegram.Client, peerSpec string, limit int, cache *PeerCache, userID int64) ([]Message, error) {
	if peerSpec == "" {
		return nil, fmt.Errorf("peer is required")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	api := c.API()

	dlgRes, err := api.MessagesGetDialogs(ctx, &tg.MessagesGetDialogsRequest{
		Limit:      200,
		OffsetPeer: &tg.InputPeerEmpty{},
	})
	if err != nil {
		return nil, fmt.Errorf("MessagesGetDialogs: %w", err)
	}
	users, chats, dialogs := decodeDialogsResult(dlgRes)

	for _, dc := range dialogs {
		d, ok := dc.(*tg.Dialog)
		if !ok {
			continue
		}
		hint := dialogFromPeer(d, users, chats)
		if hint == nil {
			continue
		}
		if hint.ID != peerSpec && !matchUsername(hint.Username, peerSpec) {
			continue
		}
		input := inputPeerFromPeer(d.Peer, users, chats)
		if input == nil {
			return nil, fmt.Errorf("cannot build InputPeer for %q", peerSpec)
		}
		hist, err := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{
			Peer:  input,
			Limit: limit,
		})
		if err != nil {
			return nil, fmt.Errorf("MessagesGetHistory: %w", err)
		}
		return decodeMessages(hist, hint, users, chats, limit), nil
	}

	// Fallback: peer not in dialog list — resolve directly.
	slog.Debug("peer not in dialog list, falling back to direct resolution", "peer_redacted", RedactPeer(peerSpec))
	input, resolveErr := ResolvePeerCached(ctx, c, peerSpec, cache, userID)
	if resolveErr != nil {
		return nil, fmt.Errorf("peer %q not found in dialogs and direct resolution failed: %w", peerSpec, resolveErr)
	}
	hist, histErr := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{
		Peer:  input,
		Limit: limit,
	})
	if histErr != nil {
		// Evict the cache entry on PEER_ID_INVALID so a stale access hash
		// does not block future calls for the rest of the TTL window.
		var rpcErr *tgerr.Error
		if errors.As(histErr, &rpcErr) && rpcErr.Message == "PEER_ID_INVALID" && cache != nil {
			cache.Evict(userID, peerSpec)
		}
		return nil, fmt.Errorf("MessagesGetHistory (fallback): %w", histErr)
	}
	hint := &Dialog{ID: peerSpec, Title: peerSpec}
	return decodeMessages(hist, hint, users, chats, limit), nil
}

func matchUsername(have, want string) bool {
	have = strings.TrimPrefix(strings.ToLower(have), "@")
	want = strings.TrimPrefix(strings.ToLower(want), "@")
	return have != "" && have == want
}
