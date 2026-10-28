package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// Synthetic sponsored fixture: channel 700100001 is a broadcast channel.
const spChannel = "channel:700100001"

func spFixture() *telegram.Sponsored {
	return &telegram.Sponsored{
		Messages: []telegram.SponsoredMessage{{
			Label: telegram.SponsoredLabel, Channel: spChannel, Title: "Ad", Text: "Buy now",
			URL: "https://example.test/ad", ButtonText: "Open", RandomID: "AQI=",
		}},
	}
}

func TestToolDescriptions_TellTheModelSponsoredItemsAreAds(t *testing.T) {
	s := &Server{}
	for name, tool := range map[string]mcplib.Tool{
		"get_messages":        first(s.toolGetMessages()),
		"get_unread_messages": first(s.toolGetUnreadMessages()),
	} {
		for _, want := range []string{
			`"sponsored" field`,
			"ADVERTISING, not channel content",
			"never mixed into \"messages\"",
			"verbatim",
			"clearly labelled",
			"sponsored_unavailable",
			"unknown, not \"no ads\"",
		} {
			if !strings.Contains(tool.Description, want) {
				t.Errorf("%s description missing %q", name, want)
			}
		}
	}
}

func TestAttachSponsored_SeparateFieldAndUnknownMarker(t *testing.T) {
	srv := &Server{Metrics: metrics.New()}
	result := messagesResult{Messages: wrapMessages([]telegram.Message{{ID: 1, Peer: spChannel, Text: "post"}})}
	sp := spFixture()
	sp.Unavailable = []string{"channel:700100002"}
	srv.attachSponsored("get_messages", &result, sp)

	if len(result.Messages) != 1 || strings.Contains(result.Messages[0].Text, "Buy now") {
		t.Fatalf("sponsored text leaked into messages: %+v", result.Messages)
	}
	if len(result.Sponsored) != 1 {
		t.Fatalf("sponsored = %+v, want one item", result.Sponsored)
	}
	ad := result.Sponsored[0]
	if ad.Label != telegram.SponsoredLabel || ad.Title != "Ad" || ad.URL != "https://example.test/ad" || ad.ButtonText != "Open" || ad.RandomID != "AQI=" {
		t.Errorf("sponsored item = %+v", ad)
	}
	if !strings.Contains(ad.Text, "Buy now") || !strings.Contains(ad.Text, "<telegram-content") {
		t.Errorf("sponsored text not wrapped as untrusted content: %q", ad.Text)
	}
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if _, ok := out["sponsored"]; !ok {
		t.Errorf("no sponsored key in %s", b)
	}
	if u, ok := out["sponsored_unavailable"].([]any); !ok || len(u) != 1 || u[0] != "channel:700100002" {
		t.Errorf("sponsored_unavailable = %v, want the channel whose ads could not be fetched", out["sponsored_unavailable"])
	}
}

func TestAttachSponsored_NoneLeavesFieldsAbsent(t *testing.T) {
	srv := &Server{}
	result := messagesResult{}
	srv.attachSponsored("get_messages", &result, &telegram.Sponsored{})
	b, _ := json.Marshal(result)
	if strings.Contains(string(b), "sponsored") {
		t.Errorf("empty sponsored result produced keys: %s", b)
	}
}

func stubViewReporter(t *testing.T) *[][]telegram.SponsoredMessage {
	t.Helper()
	var calls [][]telegram.SponsoredMessage
	orig := sponsoredViewReporter
	sponsoredViewReporter = func(_ *Server, _ context.Context, _ int64, msgs []telegram.SponsoredMessage) (int, error) {
		calls = append(calls, msgs)
		return 0, nil
	}
	t.Cleanup(func() { sponsoredViewReporter = orig })
	return &calls
}

func TestReportSponsoredViews_OnlyForReturnedResult(t *testing.T) {
	srv := &Server{Metrics: metrics.New()}
	ok := mcplib.NewToolResultText("{}")
	failed := mcplib.NewToolResultError("encode: boom")

	calls := stubViewReporter(t)
	srv.reportSponsoredViews(context.Background(), "get_messages", 4242, spFixture(), failed)
	srv.reportSponsoredViews(context.Background(), "get_messages", 4242, spFixture(), nil)
	srv.reportSponsoredViews(context.Background(), "get_messages", 4242, &telegram.Sponsored{Unavailable: []string{spChannel}}, ok)
	srv.reportSponsoredViews(context.Background(), "get_messages", 4242, nil, ok)
	if len(*calls) != 0 {
		t.Fatalf("views reported without a returned item: %+v", *calls)
	}

	srv.reportSponsoredViews(context.Background(), "get_messages", 4242, spFixture(), ok)
	if len(*calls) != 1 || len((*calls)[0]) != 1 || (*calls)[0][0].RandomID != "AQI=" {
		t.Fatalf("views = %+v, want exactly the returned item, once", *calls)
	}
}

// The switch is the server's: whatever broadcast_content the caller sent,
// the daemon receives the server's value.
func TestLocalBridge_BroadcastContentIsTheServersSwitch(t *testing.T) {
	for _, tc := range []struct {
		name string
		srv  func(*Server) *Server
		want bool
	}{
		{"default on", func(s *Server) *Server { s.BroadcastContent = New(nil, nil, false).BroadcastContent; return s }, true},
		{"switched off", func(s *Server) *Server { return s.WithBroadcastContent(false) }, false},
	} {
		for _, tool := range []string{"get_messages", "get_unread_messages", "prepare_get_media"} {
			t.Run(tc.name+"/"+tool, func(t *testing.T) {
				store := newToolsTestStore(t)
				uid := seedLocalAccount(t, store, 4242)
				hub := bridge.NewHub()
				send := hub.Register(uid, "")
				got := make(chan any, 1)
				go func() {
					env := <-send
					var args map[string]any
					_ = json.Unmarshal(env.Args, &args)
					got <- args["broadcast_content"]
					hub.Deliver(uid, bridge.EncodeResponse(env.ID, json.RawMessage(`{"messages":[]}`)))
				}()
				srv := tc.srv(&Server{Store: store, Hub: hub, MediaStore: NewMediaStore()})
				var handler func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error)
				switch tool {
				case "get_messages":
					_, handler = srv.toolGetMessages()
				case "get_unread_messages":
					_, handler = srv.toolGetUnreadMessages()
				case "prepare_get_media":
					_, handler = srv.toolPrepareGetMedia()
				}
				id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:read", "telegram:media:read"}}
				_, err := handler(auth.With(context.Background(), id), mcplib.CallToolRequest{Params: mcplib.CallToolParams{
					Name:      tool,
					Arguments: map[string]any{"peer": spChannel, "message_id": float64(7), "broadcast_content": !tc.want},
				}})
				if err != nil {
					t.Fatalf("Go error: %v", err)
				}
				if v := <-got; v != tc.want {
					t.Errorf("daemon received broadcast_content=%v, want %v", v, tc.want)
				}
			})
		}
	}
}
