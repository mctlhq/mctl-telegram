package mcp

import (
	"context"
	"errors"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// callSearchMessages builds a CallToolRequest with the given arguments,
// matching the construction convention used throughout tools_test.go.
func callSearchMessages(args map[string]any) mcplib.CallToolRequest {
	return mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "search_messages",
		Arguments: args,
	}}
}

// stubMessageSearcher replaces messageSearcher for the duration of a test,
// restoring the original via t.Cleanup — mirrors stubDownloader in
// bulk_media_test.go for mediaDownloader.
func stubMessageSearcher(t *testing.T, fn func(s *Server, ctx context.Context, userID int64, p telegram.SearchParams) ([]telegram.Message, error)) {
	t.Helper()
	orig := messageSearcher
	messageSearcher = fn
	t.Cleanup(func() { messageSearcher = orig })
}

// TestToolSearchMessages_PassesParsedBounds proves the SearchParams literal
// built inside toolSearchMessages carries the parsed min_date/max_date (and
// peer/query/limit) through to the seam unchanged — the wiring
// parseSearchWindow and telegram.SearchMessages tests cannot reach, because
// the real path between them goes through a live MTProto borrow.
func TestToolSearchMessages_PassesParsedBounds(t *testing.T) {
	newSrv := func(t *testing.T) *Server {
		return &Server{Store: newToolsTestStore(t)}
	}
	newCtx := func() context.Context {
		id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:read"}}
		return auth.With(context.Background(), id)
	}
	call := func(t *testing.T, srv *Server, args map[string]any) telegram.SearchParams {
		t.Helper()
		var got telegram.SearchParams
		called := false
		stubMessageSearcher(t, func(s *Server, ctx context.Context, userID int64, p telegram.SearchParams) ([]telegram.Message, error) {
			called = true
			got = p
			return nil, nil
		})
		_, handler := srv.toolSearchMessages()
		result, err := handler(newCtx(), callSearchMessages(args))
		if err != nil {
			t.Fatalf("unexpected Go error: %v", err)
		}
		if result.IsError {
			t.Fatalf("unexpected tool error: %s", contentText(result))
		}
		if !called {
			t.Fatal("expected messageSearcher to be invoked")
		}
		return got
	}

	t.Run("both bounds", func(t *testing.T) {
		srv := newSrv(t)
		p := call(t, srv, map[string]any{
			"query":    "roof rack",
			"min_date": "2026-08-01",
			"max_date": "2026-08-31",
		})
		wantMin := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
		wantMax := time.Date(2026, 8, 31, 23, 59, 59, 0, time.UTC)
		if !p.MinDate.Equal(wantMin) {
			t.Fatalf("MinDate = %v, want %v", p.MinDate, wantMin)
		}
		if !p.MaxDate.Equal(wantMax) {
			t.Fatalf("MaxDate = %v, want %v", p.MaxDate, wantMax)
		}
	})

	t.Run("RFC3339 bounds used verbatim", func(t *testing.T) {
		srv := newSrv(t)
		p := call(t, srv, map[string]any{
			"query":    "roof rack",
			"min_date": "2026-08-27T00:00:00Z",
			"max_date": "2026-09-27T12:34:56Z",
		})
		wantMin := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
		wantMax := time.Date(2026, 9, 27, 12, 34, 56, 0, time.UTC)
		if !p.MinDate.Equal(wantMin) {
			t.Fatalf("MinDate = %v, want %v", p.MinDate, wantMin)
		}
		if !p.MaxDate.Equal(wantMax) {
			t.Fatalf("MaxDate = %v, want %v", p.MaxDate, wantMax)
		}
	})

	t.Run("only min_date", func(t *testing.T) {
		srv := newSrv(t)
		p := call(t, srv, map[string]any{
			"query":    "roof rack",
			"min_date": "2026-08-27",
		})
		if p.MaxDate.IsZero() != true {
			t.Fatalf("MaxDate should be zero, got %v", p.MaxDate)
		}
		want := time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC)
		if !p.MinDate.Equal(want) {
			t.Fatalf("MinDate = %v, want %v", p.MinDate, want)
		}
	})

	t.Run("only max_date", func(t *testing.T) {
		srv := newSrv(t)
		p := call(t, srv, map[string]any{
			"query":    "roof rack",
			"max_date": "2026-08-27",
		})
		if !p.MinDate.IsZero() {
			t.Fatalf("MinDate should be zero, got %v", p.MinDate)
		}
		want := time.Date(2026, 8, 27, 23, 59, 59, 0, time.UTC)
		if !p.MaxDate.Equal(want) {
			t.Fatalf("MaxDate = %v, want %v", p.MaxDate, want)
		}
	})

	t.Run("no bounds", func(t *testing.T) {
		srv := newSrv(t)
		p := call(t, srv, map[string]any{
			"query": "roof rack",
			"peer":  "user:1",
		})
		if !p.MinDate.IsZero() || !p.MaxDate.IsZero() {
			t.Fatalf("expected both bounds zero, got MinDate=%v MaxDate=%v", p.MinDate, p.MaxDate)
		}
		if p.Peer != "user:1" || p.Query != "roof rack" {
			t.Fatalf("Peer/Query not passed through: %+v", p)
		}
	})

	t.Run("peer, query and limit pass through", func(t *testing.T) {
		srv := newSrv(t)
		p := call(t, srv, map[string]any{
			"query": "roof rack",
			"peer":  "user:1",
			"limit": float64(55),
		})
		if p.Peer != "user:1" {
			t.Fatalf("Peer = %q, want %q", p.Peer, "user:1")
		}
		if p.Query != "roof rack" {
			t.Fatalf("Query = %q, want %q", p.Query, "roof rack")
		}
		if p.Limit != 55 {
			t.Fatalf("Limit = %d, want 55", p.Limit)
		}

		// An out-of-band limit must still reach the seam unclamped — clamping
		// is telegram.SearchMessages's job, tested in internal/telegram.
		p2 := call(t, srv, map[string]any{
			"query": "roof rack",
			"peer":  "user:1",
			"limit": float64(500),
		})
		if p2.Limit != 500 {
			t.Fatalf("Limit = %d, want 500 unclamped", p2.Limit)
		}
	})
}

// TestToolSearchMessages_RendersSeamResults proves messages returned by the
// seam flow through wrapMessages into searchMessagesResult and
// StructuredContent exactly as the direct-borrow path did before the seam
// was extracted.
func TestToolSearchMessages_RendersSeamResults(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t)}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:read"}}
	ctx := auth.With(context.Background(), id)

	want := []telegram.Message{
		{ID: 1, Peer: "user:1", Text: "hello"},
		{ID: 2, Peer: "user:1", Text: "world"},
	}
	stubMessageSearcher(t, func(s *Server, ctx context.Context, userID int64, p telegram.SearchParams) ([]telegram.Message, error) {
		return want, nil
	})

	_, handler := srv.toolSearchMessages()
	result, err := handler(ctx, callSearchMessages(map[string]any{
		"query": "hello",
		"peer":  "user:1",
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %s", contentText(result))
	}
	sc, ok := result.StructuredContent.(searchMessagesResult)
	if !ok {
		t.Fatalf("StructuredContent is not searchMessagesResult: %#v", result.StructuredContent)
	}
	if sc.Query != "hello" {
		t.Fatalf("Query = %q, want %q", sc.Query, "hello")
	}
	wantWrapped := wrapMessages(want)
	if len(sc.Matches) != len(wantWrapped) {
		t.Fatalf("Matches len = %d, want %d", len(sc.Matches), len(wantWrapped))
	}
	for i := range wantWrapped {
		if sc.Matches[i].ID != wantWrapped[i].ID || sc.Matches[i].Text != wantWrapped[i].Text {
			t.Fatalf("Matches[%d] = %+v, want %+v", i, sc.Matches[i], wantWrapped[i])
		}
	}
}

// TestToolSearchMessages_SeamErrorIsToolError proves an error returned by the
// seam is translated into a tool-level error result (never a Go error, never
// a panic), even though Pool is nil in this test's Server.
func TestToolSearchMessages_SeamErrorIsToolError(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t)}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:read"}}
	ctx := auth.With(context.Background(), id)

	stubMessageSearcher(t, func(s *Server, ctx context.Context, userID int64, p telegram.SearchParams) ([]telegram.Message, error) {
		return nil, errors.New("boom")
	})

	_, handler := srv.toolSearchMessages()
	result, err := handler(ctx, callSearchMessages(map[string]any{
		"query": "hello",
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected a tool error result")
	}
}

// TestToolSearchMessages_SeamNotReachedOnInvalidDate proves an unparseable
// min_date is rejected before the seam is ever called.
func TestToolSearchMessages_SeamNotReachedOnInvalidDate(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t)}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:read"}}
	ctx := auth.With(context.Background(), id)

	calls := 0
	stubMessageSearcher(t, func(s *Server, ctx context.Context, userID int64, p telegram.SearchParams) ([]telegram.Message, error) {
		calls++
		return nil, nil
	})

	_, handler := srv.toolSearchMessages()
	result, err := handler(ctx, callSearchMessages(map[string]any{
		"query":    "roof rack",
		"min_date": "yesterday",
	}))
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for unparseable min_date")
	}
	if calls != 0 {
		t.Fatalf("seam invoked %d times, want 0", calls)
	}
}
