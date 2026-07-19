package mcp

import (
	"context"
	"errors"
	"testing"

	"github.com/gotd/td/tg"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// newDownloadableMessage builds a paired (raw *tg.Message, decoded
// telegram.Message) for a document with the given id/size — the shape
// GetMessagesRaw/GetUnreadMessagesRaw hand to fetchMediaInline.
func newDownloadableMessage(id int, size int64) (*tg.Message, telegram.Message) {
	media := &tg.MessageMediaDocument{
		Document: &tg.Document{
			ID:         int64(id),
			AccessHash: int64(id) * 7,
			Size:       size,
			MimeType:   "application/octet-stream",
		},
	}
	raw := &tg.Message{ID: id, Media: media}
	decoded := telegram.Message{ID: id, MediaInfo: telegram.DecodeMediaInfo(media)}
	return raw, decoded
}

// newNonDownloadableMessage builds a paired message carrying poll media:
// MediaInfo is present (media_type=poll) but ExtractMediaLocation returns a
// nil location, so it must never reach the downloader.
func newNonDownloadableMessage(id int) (*tg.Message, telegram.Message) {
	media := &tg.MessageMediaPoll{}
	raw := &tg.Message{ID: id, Media: media}
	decoded := telegram.Message{ID: id, MediaInfo: telegram.DecodeMediaInfo(media)}
	return raw, decoded
}

// stubDownloader swaps the package-level mediaDownloader for the duration of
// the test, restoring the original afterward.
func stubDownloader(t *testing.T, fn func(ctx context.Context, userID int64, loc telegram.MediaFileLocation, maxBytes int64) ([]byte, error)) {
	t.Helper()
	orig := mediaDownloader
	mediaDownloader = func(s *Server, ctx context.Context, userID int64, loc telegram.MediaFileLocation, maxBytes int64) ([]byte, error) {
		return fn(ctx, userID, loc, maxBytes)
	}
	t.Cleanup(func() { mediaDownloader = orig })
}

func TestFetchMediaInline_AllNonDownloadable(t *testing.T) {
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error) {
		t.Fatal("downloader must not be called for non-downloadable items")
		return nil, nil
	})
	var rawMsgs []*tg.Message
	var msgs []telegram.Message
	for i := 1; i <= 3; i++ {
		raw, decoded := newNonDownloadableMessage(i)
		rawMsgs = append(rawMsgs, raw)
		msgs = append(msgs, decoded)
	}
	s := &Server{MediaDownloadMaxBytes: 1000}
	summary, err := s.fetchMediaInline(context.Background(), 1, rawMsgs, msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := FetchMediaSummary{Fetched: 0, Skipped: 0, Cap: BulkMediaFetchCap}
	if summary != want {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
	for i, m := range msgs {
		if m.MediaData != nil {
			t.Errorf("msgs[%d].MediaData should stay nil", i)
		}
	}
}

func TestFetchMediaInline_UnderCap(t *testing.T) {
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error) {
		return []byte("data"), nil
	})
	var rawMsgs []*tg.Message
	var msgs []telegram.Message
	for i := 1; i <= 3; i++ {
		raw, decoded := newDownloadableMessage(i, 100)
		rawMsgs = append(rawMsgs, raw)
		msgs = append(msgs, decoded)
	}
	s := &Server{MediaDownloadMaxBytes: 1000}
	summary, err := s.fetchMediaInline(context.Background(), 1, rawMsgs, msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := FetchMediaSummary{Fetched: 3, Skipped: 0, Cap: BulkMediaFetchCap}
	if summary != want {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
	for i, m := range msgs {
		if m.MediaData == nil {
			t.Errorf("msgs[%d].MediaData should be set", i)
		}
	}
}

func TestFetchMediaInline_OverCap(t *testing.T) {
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error) {
		return []byte("data"), nil
	})
	var rawMsgs []*tg.Message
	var msgs []telegram.Message
	for i := 1; i <= 7; i++ {
		raw, decoded := newDownloadableMessage(i, 100)
		rawMsgs = append(rawMsgs, raw)
		msgs = append(msgs, decoded)
	}
	s := &Server{MediaDownloadMaxBytes: 1000}
	summary, err := s.fetchMediaInline(context.Background(), 1, rawMsgs, msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := FetchMediaSummary{Fetched: 5, Skipped: 2, Cap: BulkMediaFetchCap}
	if summary != want {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
	for i, m := range msgs {
		if i < 5 && m.MediaData == nil {
			t.Errorf("msgs[%d] should have been fetched (within cap)", i)
		}
		if i >= 5 && m.MediaData != nil {
			t.Errorf("msgs[%d] should have been skipped (over cap)", i)
		}
	}
}

func TestFetchMediaInline_SizeExceeded(t *testing.T) {
	called := false
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error) {
		called = true
		return []byte("data"), nil
	})
	raw, decoded := newDownloadableMessage(1, 5000)
	s := &Server{MediaDownloadMaxBytes: 1000}
	summary, err := s.fetchMediaInline(context.Background(), 1, []*tg.Message{raw}, []telegram.Message{decoded})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := FetchMediaSummary{Fetched: 0, Skipped: 1, Cap: BulkMediaFetchCap}
	if summary != want {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
	if called {
		t.Error("downloader must not be called for an oversized item")
	}
}

func TestFetchMediaInline_DownloadError(t *testing.T) {
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error) {
		return nil, errors.New("boom")
	})
	raw, decoded := newDownloadableMessage(1, 100)
	rawMsgs := []*tg.Message{raw}
	msgs := []telegram.Message{decoded}
	s := &Server{MediaDownloadMaxBytes: 1000}
	summary, err := s.fetchMediaInline(context.Background(), 1, rawMsgs, msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := FetchMediaSummary{Fetched: 0, Skipped: 1, Cap: BulkMediaFetchCap}
	if summary != want {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
	if msgs[0].MediaData != nil {
		t.Error("MediaData must stay nil after a download error")
	}
}
