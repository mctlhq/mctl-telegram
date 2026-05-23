package telegram

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
)

// ResolvePeer accepts:
//   - "@username" or "username"        — resolved via contacts.ResolveUsername
//   - "user:<id>", "chat:<id>", "channel:<id>"
//   - "<id>" (positive id heuristic — user; negative/large — channel)
//
// Returns an InputPeerClass usable by messages.* requests.
func ResolvePeer(ctx context.Context, c *telegram.Client, raw string) (tg.InputPeerClass, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty peer")
	}
	api := c.API()

	if strings.HasPrefix(raw, "@") || (!strings.Contains(raw, ":") && !isNumeric(raw)) {
		uname := strings.TrimPrefix(raw, "@")
		res, err := api.ContactsResolveUsername(ctx, &tg.ContactsResolveUsernameRequest{Username: uname})
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", uname, err)
		}
		switch p := res.Peer.(type) {
		case *tg.PeerUser:
			for _, u := range res.Users {
				if user, ok := u.(*tg.User); ok && user.ID == p.UserID {
					return &tg.InputPeerUser{UserID: user.ID, AccessHash: user.AccessHash}, nil
				}
			}
		case *tg.PeerChannel:
			for _, ch := range res.Chats {
				if channel, ok := ch.(*tg.Channel); ok && channel.ID == p.ChannelID {
					return &tg.InputPeerChannel{ChannelID: channel.ID, AccessHash: channel.AccessHash}, nil
				}
			}
		case *tg.PeerChat:
			return &tg.InputPeerChat{ChatID: p.ChatID}, nil
		}
		return nil, fmt.Errorf("could not resolve %q", uname)
	}

	switch {
	case strings.HasPrefix(raw, "user:"):
		id, err := strconv.ParseInt(strings.TrimPrefix(raw, "user:"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("user id parse: %w", err)
		}
		return &tg.InputPeerUser{UserID: id}, nil
	case strings.HasPrefix(raw, "chat:"):
		id, err := strconv.ParseInt(strings.TrimPrefix(raw, "chat:"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("chat id parse: %w", err)
		}
		return &tg.InputPeerChat{ChatID: id}, nil
	case strings.HasPrefix(raw, "channel:"):
		id, err := strconv.ParseInt(strings.TrimPrefix(raw, "channel:"), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("channel id parse: %w", err)
		}
		return &tg.InputPeerChannel{ChannelID: id}, nil
	}

	if isNumeric(raw) {
		id, _ := strconv.ParseInt(raw, 10, 64)
		return &tg.InputPeerUser{UserID: id}, nil
	}
	return nil, fmt.Errorf("unrecognized peer format: %q", raw)
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '-' {
		s = s[1:]
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ResolvePeerCached resolves a peer using the provided PeerCache to avoid
// repeated ContactsResolveUsername calls for the same (userID, peerSpec) pair.
// When cache is nil or userID is 0, it falls through to ResolvePeer directly.
// The resolved InputPeerClass is stored in the cache on success.
func ResolvePeerCached(ctx context.Context, c *telegram.Client, peerSpec string, cache *PeerCache, userID int64) (tg.InputPeerClass, error) {
	if cache != nil && userID != 0 {
		if peer, ok := cache.Get(userID, peerSpec); ok {
			return peer, nil
		}
	}
	peer, err := ResolvePeer(ctx, c, peerSpec)
	if err != nil {
		return nil, err
	}
	if cache != nil && userID != 0 {
		cache.Set(userID, peerSpec, peer)
	}
	return peer, nil
}

// RedactPeer turns a peer string into a stable tag suitable for audit logs.
// We never log usernames or numeric ids verbatim — emit type + length only.
func RedactPeer(raw string) string {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		return ""
	case strings.HasPrefix(raw, "@"):
		return fmt.Sprintf("username:len=%d", len(raw)-1)
	case strings.HasPrefix(raw, "user:"):
		return "user:<id>"
	case strings.HasPrefix(raw, "chat:"):
		return "chat:<id>"
	case strings.HasPrefix(raw, "channel:"):
		return "channel:<id>"
	}
	if isNumeric(raw) {
		return "numeric:<id>"
	}
	return "username:len=" + strconv.Itoa(len(raw))
}
