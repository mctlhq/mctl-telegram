package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

func TestTopicArg_RejectsAnythingButAnID(t *testing.T) {
	if _, in, err := topicArg(map[string]any{}); in || err != nil {
		t.Errorf("absent topic: in=%v err=%v", in, err)
	}
	if id, in, err := topicArg(map[string]any{"topic_id": float64(12)}); !in || id != 12 || err != nil {
		t.Errorf("topic 12: id=%d in=%v err=%v", id, in, err)
	}
	for _, bad := range []any{"Releases", float64(0), float64(-1), float64(1.5)} {
		if _, in, err := topicArg(map[string]any{"topic_id": bad}); err == nil || in {
			t.Errorf("topic_id %v accepted; a bad value must not widen a topic read to the whole forum", bad)
		}
	}
}

// TestGetMessages_TopicGoesToTheBridgeUnderItsOwnName pins the Local Bridge
// fail-closed path: a topic read travels as get_topic_messages, so a daemon
// that predates topics answers "unknown tool" instead of ignoring topic_id
// and returning the whole forum.
func TestGetMessages_TopicGoesToTheBridgeUnderItsOwnName(t *testing.T) {
	cases := []struct {
		name, tool string
		args       map[string]any
		want       string
	}{
		{"plain read", "get_messages", map[string]any{"peer": "carol_team"}, "get_messages"},
		{"topic read", "get_messages", map[string]any{"peer": "carol_team", "topic_id": float64(12)}, "get_topic_messages"},
		{"topic list", "list_topics", map[string]any{"peer": "carol_team"}, "list_topics"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := newToolsTestStore(t)
			uid := seedLocalAccount(t, store, int64(4521+i))
			hub := bridge.NewHub()
			send := hub.Register(uid, "")
			got := make(chan string, 1)
			go func() {
				env := <-send
				got <- env.Tool
				if env.Tool == "get_topic_messages" {
					hub.Deliver(uid, bridge.EncodeError(env.ID, `unknown tool: "get_topic_messages"`))
					return
				}
				hub.Deliver(uid, bridge.EncodeResponse(env.ID, json.RawMessage(`{"messages":[],"topics":[]}`)))
			}()
			srv := (&Server{Store: store, Hub: hub}).newMCPServer()
			id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:read"}}
			res := callTool(t, auth.With(context.Background(), id), srv, c.tool, c.args)
			if tool := <-got; tool != c.want {
				t.Fatalf("bridge tool = %q, want %q", tool, c.want)
			}
			if c.want == "get_topic_messages" {
				if !res.IsError || !strings.Contains(contentText(res), "unknown tool") {
					t.Errorf("old daemon answer not surfaced as an error: %s", contentText(res))
				}
			} else if res.IsError {
				t.Errorf("unexpected error: %s", contentText(res))
			}
		})
	}
}

func TestGetMessages_BadTopicIsRefusedBeforeAnyRead(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedLocalAccount(t, store, 4524)
	hub := bridge.NewHub()
	send := hub.Register(uid, "")
	srv := (&Server{Store: store, Hub: hub}).newMCPServer()
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:read"}}
	res := callTool(t, auth.With(context.Background(), id), srv, "get_messages", map[string]any{"peer": "carol_team", "topic_id": "Releases"})
	if !res.IsError || !strings.Contains(contentText(res), "list_topics") {
		t.Fatalf("bad topic_id not refused: %s", contentText(res))
	}
	select {
	case env := <-send:
		t.Fatalf("bad topic_id still reached the daemon as %q", env.Tool)
	default:
	}
}

func TestSearchMessages_TopicReachesTheSearchAndNeedsAPeer(t *testing.T) {
	var got []telegram.SearchParams
	orig := messageSearcher
	t.Cleanup(func() { messageSearcher = orig })
	messageSearcher = func(_ *Server, _ context.Context, _ int64, p telegram.SearchParams) ([]telegram.Message, error) {
		got = append(got, p)
		if p.TopicID == 99 {
			return nil, telegram.ErrTopicNotFound
		}
		return nil, nil
	}
	srv := (&Server{Store: newToolsTestStore(t)}).newMCPServer()
	ctx := auth.With(context.Background(), &auth.Identity{UserID: 4525, Scopes: []string{"telegram:messages:read"}})

	res := callTool(t, ctx, srv, "search_messages", map[string]any{"query": "ship", "peer": "carol_team", "topic_id": float64(12)})
	if res.IsError || len(got) != 1 || got[0].TopicID != 12 {
		t.Fatalf("topic search: err=%v params=%+v, want TopicID 12 passed through", contentText(res), got)
	}
	res = callTool(t, ctx, srv, "search_messages", map[string]any{"query": "ship", "topic_id": float64(12)})
	if !res.IsError || !strings.Contains(contentText(res), "needs peer") || len(got) != 1 {
		t.Errorf("topic without peer: %s (searches=%d), want a refusal before searching", contentText(res), len(got))
	}
	res = callTool(t, ctx, srv, "search_messages", map[string]any{"query": "ship", "peer": "carol_team", "topic_id": float64(99)})
	if !res.IsError || !strings.Contains(contentText(res), "topic 99 not found") {
		t.Errorf("missing topic: %s, want it named", contentText(res))
	}
}
