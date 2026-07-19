package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// BulkMediaFetchCap is the maximum number of media items fetched inline per
// get_messages or get_unread_messages call when fetch_media=true. It guards
// against runaway context growth and unbounded in-memory download size when a
// history page is dense with large files.
const BulkMediaFetchCap = 5

// FetchMediaSummary is attached to messagesResult whenever fetch_media=true
// was requested (even when Fetched is 0), so callers can distinguish "nothing
// downloadable on this page" from "fetch_media wasn't set".
type FetchMediaSummary struct {
	Fetched int `json:"fetched"`
	Skipped int `json:"skipped"`
	Cap     int `json:"cap"`
}

// mediaDownloader abstracts the byte-fetch step of fetchMediaInline so unit
// tests can exercise the cap/skip/error bookkeeping without a live Telegram
// connection. Production code always calls through to
// (*Server).downloadMediaViaPool; tests that reassign this package variable
// must restore the original via t.Cleanup.
var mediaDownloader = func(s *Server, ctx context.Context, userID int64, loc telegram.MediaFileLocation, maxBytes int64) ([]byte, error) {
	return s.downloadMediaViaPool(ctx, userID, loc, maxBytes)
}

// downloadMediaViaPool borrows a pooled client and downloads loc's bytes,
// mirroring the pattern toolGetMedia uses for the two-step flow
// (s.borrowWithRetry + telegram.DownloadMedia).
func (s *Server) downloadMediaViaPool(ctx context.Context, userID int64, loc telegram.MediaFileLocation, maxBytes int64) ([]byte, error) {
	var buf []byte
	err := s.borrowWithRetry(ctx, "fetch_media", userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		var derr error
		buf, derr = telegram.DownloadMedia(ctx, c, loc, maxBytes)
		return derr
	})
	return buf, err
}

// isSystemicPoolErr reports whether err represents a call-wide Pool.Borrow
// failure — a revoked/expired/unauthorized session, no active session, or
// the pool at capacity — as opposed to a transient error scoped to one
// item's download. sessionErrText/telegram.ErrPoolFull are the same
// sentinels borrowErrResult uses to render the actionable reconnect message.
func isSystemicPoolErr(err error) bool {
	return sessionErrText(err) != "" || errors.Is(err, telegram.ErrPoolFull)
}

// fetchMediaInline attempts to download media bytes for each message in
// rawMsgs/msgs (parallel slices: same length, same order, one raw wire
// message per decoded Message), initiating at most BulkMediaFetchCap
// downloads. It mutates MediaData on each message it successfully
// downloads; items left un-fetched due to the cap, the size limit, a
// non-downloadable media type, protected content, or a per-item download
// error are left with MediaData == nil and counted in the returned
// summary's Skipped field (messages with no media at all are not counted —
// there was nothing to skip).
//
// Returns a non-nil error only for a systemic Pool.Borrow failure (see
// isSystemicPoolErr) encountered mid-loop — e.g. the session was revoked
// while paging through history. That aborts the loop immediately; the
// caller should treat it the same as the initial fetch's error (via
// borrowErrResult) rather than folding it into Skipped. All other per-item
// failures keep the loop going and are logged at DEBUG level.
func (s *Server) fetchMediaInline(ctx context.Context, userID int64, rawMsgs []*tg.Message, msgs []telegram.Message) (FetchMediaSummary, error) {
	summary := FetchMediaSummary{Cap: BulkMediaFetchCap}
	n := len(rawMsgs)
	if len(msgs) < n {
		n = len(msgs)
	}
	attempted := 0
	for i := 0; i < n; i++ {
		loc, err := telegram.ExtractMediaLocation(rawMsgs[i])
		if err != nil || loc == nil {
			if rawMsgs[i].Media != nil {
				// Non-downloadable type (web_page, contact, location, poll,
				// unsupported) or protected content (Noforwards): the page
				// had media here, it just isn't fetchable — count it.
				summary.Skipped++
			}
			// Plain messages with no media at all are not counted; there
			// was never anything to skip.
			continue
		}
		if info := msgs[i].MediaInfo; info != nil && info.Size > 0 && s.MediaDownloadMaxBytes > 0 && info.Size > s.MediaDownloadMaxBytes {
			summary.Skipped++
			continue
		}
		if attempted >= BulkMediaFetchCap {
			summary.Skipped++
			continue
		}
		attempted++
		data, dlErr := mediaDownloader(s, ctx, userID, *loc, s.MediaDownloadMaxBytes)
		if dlErr != nil {
			if isSystemicPoolErr(dlErr) {
				return summary, dlErr
			}
			summary.Skipped++
			slog.Debug("fetch_media: item download failed, skipping", "message_id", rawMsgs[i].ID, "err", dlErr)
			continue
		}
		encoded := base64.StdEncoding.EncodeToString(data)
		msgs[i].MediaData = &encoded
		summary.Fetched++
	}
	return summary, nil
}
