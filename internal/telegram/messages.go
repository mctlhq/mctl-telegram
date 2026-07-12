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

// clampLimit clamps a caller-supplied page size to the [1, 200] range,
// defaulting non-positive values to 50.
func clampLimit(limit int) int {
	if limit <= 0 {
		return 50
	} else if limit > 200 {
		return 200
	}
	return limit
}

// GetUnreadMessages walks the dialog list (limit-bounded) and pulls up to
// `limit` total unread messages, scoped to one peer if provided.
func GetUnreadMessages(ctx context.Context, c *telegram.Client, peerSpec string, limit int) ([]Message, error) {
	limit = clampLimit(limit)
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

	var peerFound bool // true if peerSpec matched a dialog entry (even with 0 unread)
	for _, dc := range dialogs {
		d, ok := dc.(*tg.Dialog)
		if !ok {
			continue
		}
		hint := dialogFromPeer(d, users, chats)
		if hint == nil {
			continue
		}
		// Apply peer filter before the unread gate so peerFound is set even
		// when the matching peer has zero unread messages.
		if peerSpec != "" && hint.ID != peerSpec && !matchUsername(hint.Username, peerSpec) {
			continue
		}
		if peerSpec != "" {
			peerFound = true
		}
		if d.UnreadCount == 0 {
			continue
		}
		input := inputPeerFromPeer(d.Peer, users, chats)
		if input == nil {
			continue
		}
		targets = append(targets, target{input: input, dialog: d, hint: hint})
	}

	// Peer explicitly requested but absent from the dialog list → actionable error.
	// Peer found with zero unread messages → correct result is an empty slice.
	if peerSpec != "" && len(targets) == 0 {
		if !peerFound {
			return nil, fmt.Errorf("peer %q not found in recent dialogs — use get_messages for this peer's full history", peerSpec)
		}
		return []Message{}, nil
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

// seedPeerCache populates the shared PeerCache with InputPeer values (including
// the access_hash) for every entity returned alongside a dialog list, keyed by
// the same canonical peer specs that ListDialogs/dialogFromPeer emit
// ("user:<id>", "chat:<id>", "channel:<id>").
//
// This is the access-hash source of truth: MTProto rejects messages.* requests
// for users and channels whose InputPeer carries a zero access_hash
// (PEER_ID_INVALID / CHANNEL_INVALID). ResolvePeer can only build a zero-hash
// InputPeer from a bare numeric "channel:<id>" spec, so without this seeding a
// follow-up get_messages/send_message that misses the live dialog scan fails.
// Seeding from the dialog entities lets ResolvePeerCached return a hash-bearing
// peer instead. No-op when cache is nil or userID is 0.
func seedPeerCache(cache *PeerCache, userID int64, users map[int64]*tg.User, chats map[int64]tg.ChatClass) {
	if cache == nil || userID == 0 {
		return
	}
	for _, u := range users {
		// Skip unusable access hashes. A zero hash obviously can't resolve, and a
		// "min" user (https://core.telegram.org/api/min) carries an access hash
		// valid only for limited contexts (e.g. profile photos) — NOT for
		// messages.* APIs, which still return PEER_ID_INVALID. Seeding either
		// would also overwrite a good full hash previously cached via
		// ContactsResolveUsername.
		if u == nil || u.Min || u.AccessHash == 0 {
			continue
		}
		cache.Set(userID, fmt.Sprintf("user:%d", u.ID),
			&tg.InputPeerUser{UserID: u.ID, AccessHash: u.AccessHash})
	}
	for _, c := range chats {
		switch ch := c.(type) {
		case *tg.Channel:
			// Same guard as users: skip min channels and zero hashes — neither is
			// usable for messages.getHistory and both would clobber a good entry.
			if ch.Min || ch.AccessHash == 0 {
				continue
			}
			cache.Set(userID, fmt.Sprintf("channel:%d", ch.ID),
				&tg.InputPeerChannel{ChannelID: ch.ID, AccessHash: ch.AccessHash})
		case *tg.Chat:
			// Basic groups need no access hash.
			cache.Set(userID, fmt.Sprintf("chat:%d", ch.ID),
				&tg.InputPeerChat{ChatID: ch.ID})
		}
	}
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
// beforeID, when non-zero, is passed as OffsetID to messages.getHistory so
// only messages with ID strictly less than beforeID are returned, enabling
// backward keyset pagination. Pass 0 to start from the most recent message.
//
// cache and userID enable peer resolution caching; pass nil and 0 to disable.
func GetMessages(ctx context.Context, c *telegram.Client, peerSpec string, limit int, beforeID int, cache *PeerCache, userID int64) ([]Message, error) {
	if peerSpec == "" {
		return nil, fmt.Errorf("peer is required")
	}
	limit = clampLimit(limit)
	api := c.API()

	dlgRes, err := api.MessagesGetDialogs(ctx, &tg.MessagesGetDialogsRequest{
		Limit:      200,
		OffsetPeer: &tg.InputPeerEmpty{},
	})
	if err != nil {
		return nil, fmt.Errorf("MessagesGetDialogs: %w", err)
	}
	users, chats, dialogs := decodeDialogsResult(dlgRes)
	// Seed the shared peer cache so a later get_messages/send_message for any of
	// these peers resolves with a valid access_hash even if it misses the live
	// dialog scan below.
	seedPeerCache(cache, userID, users, chats)

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
			Peer:     input,
			Limit:    limit,
			OffsetID: beforeID,
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
		return nil, fmt.Errorf("peer %q is not in your dialog list and could not be resolved directly; "+
			"call list_dialogs first and pass an id exactly as it appears there (e.g. \"channel:<id>\"): %w", peerSpec, resolveErr)
	}
	hist, histErr := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{
		Peer:     input,
		Limit:    limit,
		OffsetID: beforeID,
	})
	if histErr != nil {
		var rpcErr *tgerr.Error
		if errors.As(histErr, &rpcErr) && (rpcErr.Message == "PEER_ID_INVALID" || rpcErr.Message == "CHANNEL_INVALID") {
			if cache != nil {
				// Evict the stale entry and retry once with a fresh resolution.
				// MessagesGetHistory is read-only so the retry is always safe.
				cache.Evict(userID, peerSpec)
				if input2, err2 := ResolvePeerCached(ctx, c, peerSpec, cache, userID); err2 == nil {
					if hist2, err3 := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{
						Peer:     input2,
						Limit:    limit,
						OffsetID: beforeID,
					}); err3 == nil {
						return decodeMessages(hist2, &Dialog{ID: peerSpec, Title: peerSpec}, users, chats, limit), nil
					}
				}
			}
			// A bare numeric "user:<id>"/"channel:<id>" carries no access_hash, so
			// Telegram cannot identify the peer. Tell the caller how to recover
			// instead of surfacing a raw RPC error that invites a retry loop.
			return nil, fmt.Errorf("peer %q could not be accessed (%s): it is not in your dialog list; "+
				"call list_dialogs and use an id exactly as returned there", peerSpec, rpcErr.Message)
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
