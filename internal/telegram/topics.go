package telegram

import (
	"context"
	"errors"
	"fmt"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

// Topic is one forum topic of a supergroup (mctl-telegram#1155).
type Topic struct {
	ID                  int       `json:"id"`
	Title               string    `json:"title"`
	Closed              bool      `json:"closed,omitempty"`
	Pinned              bool      `json:"pinned,omitempty"`
	Hidden              bool      `json:"hidden,omitempty"`
	UnreadCount         int       `json:"unread_count"`
	UnreadMentionsCount int       `json:"unread_mentions_count,omitempty"`
	LastMessageDate     time.Time `json:"last_message_date,omitempty"`
}

// TopicList says how much of the forum's topic list was returned. Complete
// is false when Telegram reported more topics than came back.
type TopicList struct {
	Total    int  `json:"total"`
	Complete bool `json:"complete"`
}

var (
	// ErrNotAForum is returned when the peer has no forum topics.
	ErrNotAForum = errors.New("this chat has no topics: topics exist only in forum supergroups")
	// ErrTopicNotFound is returned when the topic id does not exist in the chat.
	ErrTopicNotFound = errors.New("topic not found in this chat")
)

// topicsInvoker is the subset of *tg.Client the topic paths use, so tests
// can capture requests without a live MTProto client.
type topicsInvoker interface {
	MessagesGetForumTopics(ctx context.Context, req *tg.MessagesGetForumTopicsRequest) (*tg.MessagesForumTopics, error)
	MessagesGetReplies(ctx context.Context, req *tg.MessagesGetRepliesRequest) (tg.MessagesMessagesClass, error)
	channelLookup
}

// ListTopics returns up to limit topics of a forum supergroup, newest
// activity first, optionally filtered by title.
func ListTopics(ctx context.Context, c *gotdtelegram.Client, peerSpec, query string, limit int, cache *PeerCache, userID int64) ([]Topic, TopicList, error) {
	input, err := resolveForumPeer(ctx, c, peerSpec, cache, userID)
	if err != nil {
		return nil, TopicList{}, err
	}
	return listTopicsWith(ctx, c.API(), input, query, limit)
}

func listTopicsWith(ctx context.Context, api topicsInvoker, input tg.InputPeerClass, query string, limit int) ([]Topic, TopicList, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	req := &tg.MessagesGetForumTopicsRequest{Peer: input, Limit: limit}
	if query != "" {
		req.SetQ(query)
	}
	res, err := api.MessagesGetForumTopics(ctx, req)
	if err != nil {
		return nil, TopicList{}, topicRPCError("MessagesGetForumTopics", err)
	}
	return topicsFrom(res)
}

// topicsFrom decodes a topic page. Deleted topics are left out of the
// result but still count as returned, so Complete compares like with like.
func topicsFrom(res *tg.MessagesForumTopics) ([]Topic, TopicList, error) {
	if res == nil {
		return nil, TopicList{}, errors.New("MessagesGetForumTopics: empty reply")
	}
	dates := topMessageDates(res.Messages)
	out := make([]Topic, 0, len(res.Topics))
	for _, tc := range res.Topics {
		t, ok := tc.(*tg.ForumTopic)
		if !ok {
			continue
		}
		topic := Topic{
			ID: t.ID, Title: t.Title, Closed: t.Closed, Pinned: t.Pinned, Hidden: t.Hidden,
			UnreadCount: t.UnreadCount, UnreadMentionsCount: t.UnreadMentionsCount,
		}
		if ts, ok := dates[topMessageKey{peer: peerClassKey(t.Peer), id: t.TopMessage}]; ok {
			topic.LastMessageDate = ts
		}
		out = append(out, topic)
	}
	return out, TopicList{Total: res.Count, Complete: res.Count <= len(res.Topics)}, nil
}

// GetTopicMessagesRaw fetches one page of a forum topic's history, newest
// first; beforeID pages backward exactly as get_messages does. The second
// slice holds the raw messages behind the decoded page, for fetch_media.
func GetTopicMessagesRaw(ctx context.Context, c *gotdtelegram.Client, peerSpec string, topicID, limit, beforeID int, cache *PeerCache, userID int64, bc BroadcastContent) ([]Message, []*tg.Message, int, error) {
	input, err := resolveForumPeer(ctx, c, peerSpec, cache, userID)
	if err != nil {
		return nil, nil, 0, err
	}
	return getTopicMessagesWith(ctx, c.API(), input, peerSpec, topicID, limit, beforeID, bc)
}

func getTopicMessagesWith(ctx context.Context, api topicsInvoker, input tg.InputPeerClass, peerSpec string, topicID, limit, beforeID int, bc BroadcastContent) ([]Message, []*tg.Message, int, error) {
	if topicID <= 0 {
		return nil, nil, 0, fmt.Errorf("topic_id must be a positive topic id")
	}
	if !bc {
		if err := refuseBroadcastPeer(ctx, api, peerSpec, input); err != nil {
			return nil, nil, 0, err
		}
	}
	limit = clampLimit(limit)
	res, err := api.MessagesGetReplies(ctx, &tg.MessagesGetRepliesRequest{
		Peer:     input,
		MsgID:    topicID,
		OffsetID: beforeID,
		Limit:    limit,
	})
	if err != nil {
		return nil, nil, 0, topicRPCError("MessagesGetReplies", err)
	}
	users, chats := extractSearchMaps(res)
	decoded, raw := decodeMessagesRaw(res, &Dialog{ID: peerSpec, Title: peerSpec}, users, chats, limit)
	return decoded, raw, historyCursor(res), nil
}

// resolveForumPeer resolves peerSpec and refuses anything that cannot hold
// topics before a Telegram call is spent on it.
func resolveForumPeer(ctx context.Context, c *gotdtelegram.Client, peerSpec string, cache *PeerCache, userID int64) (tg.InputPeerClass, error) {
	if peerSpec == "" {
		return nil, fmt.Errorf("peer is required")
	}
	input, err := ResolvePeerCached(ctx, c, peerSpec, cache, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve peer: %w", err)
	}
	if _, ok := input.(*tg.InputPeerChannel); !ok {
		return nil, ErrNotAForum
	}
	return input, nil
}

func topicRPCError(call string, err error) error {
	var rpc *tgerr.Error
	if errors.As(err, &rpc) {
		switch rpc.Message {
		case "CHANNEL_FORUM_MISSING":
			return ErrNotAForum
		case "TOPIC_ID_INVALID", "MSG_ID_INVALID", "TOPIC_DELETED":
			return ErrTopicNotFound
		}
	}
	return fmt.Errorf("%s: %w", call, err)
}
