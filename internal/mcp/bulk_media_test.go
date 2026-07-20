package mcp

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/gotd/td/tg"
	"github.com/mctlhq/mctl-telegram/internal/db"
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

// newEmptyMediaConstructorMessage builds a paired message carrying Telegram's
// explicit MessageMediaEmpty constructor: raw.Media is non-nil (it holds a
// concrete *tg.MessageMediaEmpty), but DecodeMediaInfo — correctly — treats
// it as no media at all (MediaInfo == nil), same as a plain text message.
func newEmptyMediaConstructorMessage(id int) (*tg.Message, telegram.Message) {
	media := &tg.MessageMediaEmpty{}
	raw := &tg.Message{ID: id, Media: media}
	decoded := telegram.Message{ID: id, MediaInfo: telegram.DecodeMediaInfo(media)}
	return raw, decoded
}

// stubDownloader swaps the package-level mediaDownloader for the duration of
// the test, restoring the original afterward. The stub's bool return mirrors
// mediaDownloader's "did the download callback actually run" signal — most
// tests want true (simulating a real download attempt); tests covering the
// pre-borrow-failure path pass false.
func stubDownloader(t *testing.T, fn func(ctx context.Context, userID int64, loc telegram.MediaFileLocation, maxBytes int64) ([]byte, error, bool)) {
	t.Helper()
	orig := mediaDownloader
	mediaDownloader = func(s *Server, ctx context.Context, userID int64, loc telegram.MediaFileLocation, maxBytes int64) ([]byte, error, bool) {
		return fn(ctx, userID, loc, maxBytes)
	}
	t.Cleanup(func() { mediaDownloader = orig })
}

// withBulkMediaByteCap temporarily overrides BulkMediaByteCap for a test,
// restoring the original afterward, so aggregate-cap tests don't need to
// allocate megabytes of fixture data.
func withBulkMediaByteCap(t *testing.T, n int64) {
	t.Helper()
	orig := BulkMediaByteCap
	BulkMediaByteCap = n
	t.Cleanup(func() { BulkMediaByteCap = orig })
}

func TestFetchMediaInline_AllNonDownloadable(t *testing.T) {
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		t.Fatal("downloader must not be called for non-downloadable items")
		return nil, nil, true
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
	// Non-downloadable media (poll, here) is still media on the page — the
	// documented fetch_media_summary contract counts it as skipped, unlike
	// a plain text message that never had media at all.
	want := FetchMediaSummary{Fetched: 0, Skipped: 3, Cap: BulkMediaFetchCap}
	if summary != want {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
	for i, m := range msgs {
		if m.MediaData != nil {
			t.Errorf("msgs[%d].MediaData should stay nil", i)
		}
	}
}

func TestFetchMediaInline_NoMediaNotCountedAsSkipped(t *testing.T) {
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		t.Fatal("downloader must not be called for a plain text message")
		return nil, nil, true
	})
	rawMsgs := []*tg.Message{{ID: 1}} // no Media at all: plain text
	msgs := []telegram.Message{{ID: 1}}
	s := &Server{MediaDownloadMaxBytes: 1000}
	summary, err := s.fetchMediaInline(context.Background(), 1, rawMsgs, msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := FetchMediaSummary{Fetched: 0, Skipped: 0, Cap: BulkMediaFetchCap}
	if summary != want {
		t.Errorf("summary = %+v, want %+v (a message with no media at all is not \"skipped\")", summary, want)
	}
}

// TestFetchMediaInline_EmptyMediaConstructorNotCountedAsSkipped locks in the
// fix for Codex's P2 ("Exclude empty-media constructors from skipped"):
// Telegram's explicit MessageMediaEmpty constructor makes raw.Media non-nil,
// but DecodeMediaInfo correctly treats it as no media — the old check keyed
// off rawMsgs[i].Media != nil and over-counted it as skipped, contradicting
// the documented contract that a message with no media at all isn't skipped.
func TestFetchMediaInline_EmptyMediaConstructorNotCountedAsSkipped(t *testing.T) {
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		t.Fatal("downloader must not be called for an empty-media message")
		return nil, nil, true
	})
	raw, decoded := newEmptyMediaConstructorMessage(1)
	rawMsgs := []*tg.Message{raw}
	msgs := []telegram.Message{decoded}
	s := &Server{MediaDownloadMaxBytes: 1000}
	summary, err := s.fetchMediaInline(context.Background(), 1, rawMsgs, msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := FetchMediaSummary{Fetched: 0, Skipped: 0, Cap: BulkMediaFetchCap}
	if summary != want {
		t.Errorf("summary = %+v, want %+v (MessageMediaEmpty is not \"skipped\" — DecodeMediaInfo already treats it as no media)", summary, want)
	}
}

func TestFetchMediaInline_UnderCap(t *testing.T) {
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		return []byte("data"), nil, true
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
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		return []byte("data"), nil, true
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
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		called = true
		return []byte("data"), nil, true
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
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		return nil, errors.New("boom"), true
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

// TestFetchMediaInline_CapBoundsAttempts locks in the fix for the cap being
// keyed on successful downloads rather than attempts: a failing eligible
// item must still consume one of the BulkMediaFetchCap "slots", otherwise a
// page with mostly-failing items would attempt every eligible message
// instead of stopping after five.
func TestFetchMediaInline_CapBoundsAttempts(t *testing.T) {
	calls := 0
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		calls++
		if calls <= 2 {
			return nil, errors.New("transient boom"), true
		}
		return []byte("data"), nil, true
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
	if calls != BulkMediaFetchCap {
		t.Errorf("downloader called %d times, want exactly %d (the cap) — a failing item must still count as an attempt", calls, BulkMediaFetchCap)
	}
	// 2 failed attempts + 3 successes = 5 attempts total (the cap); the
	// remaining 2 items are skipped without ever reaching the downloader.
	want := FetchMediaSummary{Fetched: 3, Skipped: 4, Cap: BulkMediaFetchCap}
	if summary != want {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
}

// TestFetchMediaInline_SystemicErrorAbortsLoop locks in the fix that
// distinguishes a call-wide Pool.Borrow failure (session revoked mid-page)
// from an ordinary per-item error: the former must abort the loop and
// propagate to the caller instead of being silently folded into Skipped.
func TestFetchMediaInline_SystemicErrorAbortsLoop(t *testing.T) {
	calls := 0
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		calls++
		return nil, db.ErrSessionRevoked, true
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
	if !errors.Is(err, db.ErrSessionRevoked) {
		t.Fatalf("err = %v, want db.ErrSessionRevoked", err)
	}
	if calls != 1 {
		t.Errorf("downloader called %d times, want 1 — a systemic error must abort the loop immediately", calls)
	}
	if summary.Fetched != 0 || summary.Skipped != 0 {
		t.Errorf("summary = %+v, want Fetched=0 Skipped=0 (the failing item is not a per-item skip)", summary)
	}
}

// TestFetchMediaInline_ContextCanceledAbortsLoop covers the same abort path
// as TestFetchMediaInline_SystemicErrorAbortsLoop for a client disconnect /
// request deadline: a canceled context surfaced from a download must abort
// the loop immediately rather than being folded into Skipped (which would
// let both handlers audit a canceled invocation as successful).
func TestFetchMediaInline_ContextCanceledAbortsLoop(t *testing.T) {
	calls := 0
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		calls++
		return nil, context.Canceled, true
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
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if calls != 1 {
		t.Errorf("downloader called %d times, want 1 — a canceled context must abort the loop immediately", calls)
	}
	if summary.Fetched != 0 || summary.Skipped != 0 {
		t.Errorf("summary = %+v, want Fetched=0 Skipped=0 (a canceled download is not a per-item skip)", summary)
	}
}

// TestFetchMediaInline_AggregateByteCap locks in the fix for Codex's P1
// ("Enforce an aggregate encoded-response cap"): even with each item well
// under BulkMediaFetchCap and the per-file size limit, the running total
// must stop growing once BulkMediaByteCap is reached. A declared-size item
// that no longer fits the remaining budget is skipped outright (same
// pre-check the per-file size limit already uses), not partially
// downloaded — so calls to the downloader stop as soon as the budget can no
// longer fit another full item.
func TestFetchMediaInline_AggregateByteCap(t *testing.T) {
	withBulkMediaByteCap(t, 250) // room for exactly 2 items at 100 bytes each
	calls := 0
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		calls++
		return make([]byte, 100), nil, true
	})
	var rawMsgs []*tg.Message
	var msgs []telegram.Message
	for i := 1; i <= 5; i++ {
		raw, decoded := newDownloadableMessage(i, 100)
		rawMsgs = append(rawMsgs, raw)
		msgs = append(msgs, decoded)
	}
	s := &Server{MediaDownloadMaxBytes: 1000} // per-file cap is not the binding constraint here
	summary, err := s.fetchMediaInline(context.Background(), 1, rawMsgs, msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Item 1: fits (remaining 250 >= 100), total 100. Item 2: fits
	// (remaining 150 >= 100), total 200. Item 3: declared size 100 exceeds
	// the remaining budget (50), so it — and every item after it, since the
	// budget never grows back — is skipped without ever reaching the
	// downloader.
	if calls != 2 {
		t.Errorf("downloader called %d times, want 2 — the aggregate cap must stop new downloads once the remaining budget can't fit another item", calls)
	}
	if summary.Fetched != 2 {
		t.Errorf("summary.Fetched = %d, want 2", summary.Fetched)
	}
	if summary.Skipped != 3 {
		t.Errorf("summary.Skipped = %d, want 3", summary.Skipped)
	}
	for i, m := range msgs {
		if i < 2 && m.MediaData == nil {
			t.Errorf("msgs[%d] should have been fetched (within the byte budget)", i)
		}
		if i >= 2 && m.MediaData != nil {
			t.Errorf("msgs[%d] should have been skipped (byte budget exhausted)", i)
		}
	}
}

// TestFetchMediaInline_UnclassifiedBorrowFailureAbortsLoop locks in the fix
// for Codex's P2 ("Propagate unclassified pool failures"): an error from a
// download whose callback never ran (Borrow failed in its own
// preflight/acquire/startup path — e.g. a transient CheckSessionValid
// database error) is systemic even though it matches none of
// isSystemicPoolErr's known sentinels, and must abort the loop rather than
// being folded into Skipped.
func TestFetchMediaInline_UnclassifiedBorrowFailureAbortsLoop(t *testing.T) {
	calls := 0
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		calls++
		// attempted=false: Borrow failed before the download callback ran,
		// same shape as a CheckSessionValid DB error or client-startup
		// failure — isSystemicPoolErr would not recognize this error type.
		return nil, errors.New("db: connection reset"), false
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
	if err == nil {
		t.Fatal("expected the unclassified borrow failure to propagate, got nil")
	}
	if calls != 1 {
		t.Errorf("downloader called %d times, want 1 — a pre-callback borrow failure must abort the loop immediately", calls)
	}
	if summary.Fetched != 0 || summary.Skipped != 0 {
		t.Errorf("summary = %+v, want Fetched=0 Skipped=0 (not a per-item skip)", summary)
	}
}

// TestFetchMediaInline_FailedDownloadChargesActualBytes locks in the fix for
// Codex's P2 ("Charge only bytes consumed by failed downloads"): a per-item
// download failure whose callback ran (attemptedFn=true, an ordinary skip)
// may have already streamed some bytes before erroring — e.g. cappedBuffer
// aborting an oversized undeclared-size photo mid-stream. mediaDownloader
// reports that partial amount even on failure, and fetchMediaInline must
// charge exactly that against totalBytes — not the full perItemCap, and not
// zero — so the aggregate budget reflects real wire transfer without
// over-penalizing a failure that consumed little or nothing.
func TestFetchMediaInline_FailedDownloadChargesActualBytes(t *testing.T) {
	withBulkMediaByteCap(t, 150) // room for item 1's 90 partial bytes + item 2's 100, not both fully
	calls := 0
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		calls++
		// Simulate cappedBuffer having buffered 90 bytes before the item
		// aborted mid-stream — well under perItemCap (150) but nonzero.
		return make([]byte, 90), errors.New("boom"), true
	})
	raw1, decoded1 := newDownloadableMessage(1, 100)
	raw2, decoded2 := newDownloadableMessage(2, 100)
	rawMsgs := []*tg.Message{raw1, raw2}
	msgs := []telegram.Message{decoded1, decoded2}
	s := &Server{MediaDownloadMaxBytes: 1000} // per-file cap is not the binding constraint here
	summary, err := s.fetchMediaInline(context.Background(), 1, rawMsgs, msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Item 1: fits (remaining 150 >= 100), downloader called and fails after
	// streaming 90 bytes — charges 90, not the full 150 perItemCap. Item 2:
	// remaining is now 60 < its declared size 100, so it's skipped by the
	// size pre-check without ever reaching the downloader.
	if calls != 1 {
		t.Errorf("downloader called %d times, want 1 — item 2 must be rejected by the size pre-check, not attempted", calls)
	}
	want := FetchMediaSummary{Fetched: 0, Skipped: 2, Cap: BulkMediaFetchCap}
	if summary != want {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
}

// TestFetchMediaInline_ZeroByteFailureDoesNotStarveBudget is the direct
// regression test for the bug Codex flagged in the fix this replaces:
// charging the worst-case perItemCap (which, for the first item, equals the
// entire remaining aggregate budget) on ANY failure — including an instant,
// zero-byte one like a fast RPC error before any chunk arrived — would wrongly
// exhaust the whole budget after a single failure and starve every later
// item, contradicting fetchMediaInline's documented "per-item failures keep
// the loop going" contract.
func TestFetchMediaInline_ZeroByteFailureDoesNotStarveBudget(t *testing.T) {
	withBulkMediaByteCap(t, 1000) // one item's perItemCap would exhaust this if wrongly worst-case-charged
	calls := 0
	stubDownloader(t, func(context.Context, int64, telegram.MediaFileLocation, int64) ([]byte, error, bool) {
		calls++
		if calls == 1 {
			return nil, errors.New("immediate RPC error, zero bytes transferred"), true
		}
		return make([]byte, 100), nil, true
	})
	raw1, decoded1 := newDownloadableMessage(1, 100)
	raw2, decoded2 := newDownloadableMessage(2, 100)
	rawMsgs := []*tg.Message{raw1, raw2}
	msgs := []telegram.Message{decoded1, decoded2}
	s := &Server{MediaDownloadMaxBytes: 1000}
	summary, err := s.fetchMediaInline(context.Background(), 1, rawMsgs, msgs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Errorf("downloader called %d times, want 2 — a zero-byte failure must not consume the budget item 2 needs", calls)
	}
	want := FetchMediaSummary{Fetched: 1, Skipped: 1, Cap: BulkMediaFetchCap}
	if summary != want {
		t.Errorf("summary = %+v, want %+v", summary, want)
	}
}

// TestIsSystemicPoolErr_SessionRevokePersistFailed verifies
// isSystemicPoolErr recognizes telegram.ErrSessionRevokePersistFailed —
// added alongside the fix that deliberately keeps this marker out of
// sessionErrText's sentinels (see TestBorrow_RevokePersistFailureMarksSystemicNotSentinel
// in internal/telegram), so fetchMediaInline must check for it separately
// from sessionErrText to still abort the loop on this call-wide failure.
func TestIsSystemicPoolErr_SessionRevokePersistFailed(t *testing.T) {
	err := fmt.Errorf("revoke rejected session: %w: %w", telegram.ErrSessionRevokePersistFailed, errors.New("db closed"))
	if !isSystemicPoolErr(err) {
		t.Errorf("isSystemicPoolErr(%v) = false, want true", err)
	}
}
