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

// BulkMediaByteCap bounds the total raw bytes fetchMediaInline may pull
// across ALL items in one bulk fetch call, independent of the per-file
// MEDIA_DOWNLOAD_MAX_BYTES setting. Without it, BulkMediaFetchCap successful
// downloads near the per-file default (20 MiB) could balloon a single
// response past 100 MiB raw — more once base64-encoded and duplicated into
// both the text and structured MCP response fields by jsonResult — and
// MEDIA_DOWNLOAD_MAX_BYTES=0 (documented as uncapped for a single get_media
// call) would remove the per-file half of that bound entirely. A package
// variable, not a const, so tests can shrink it instead of allocating
// megabytes of fixture data.
var BulkMediaByteCap int64 = telegram.DefaultMediaDownloadMaxBytes

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
// must restore the original via t.Cleanup. The third return value reports
// whether the download callback itself ran — false means Borrow failed in
// its own preflight/acquire/client-startup path (session check, pool
// capacity, connection setup) before ever reaching the callback, which
// fetchMediaInline treats as systemic regardless of the error's type.
var mediaDownloader = func(s *Server, ctx context.Context, userID int64, loc telegram.MediaFileLocation, maxBytes int64) ([]byte, error, bool) {
	return s.downloadMediaViaPool(ctx, userID, loc, maxBytes)
}

// downloadMediaViaPool borrows a pooled client and downloads loc's bytes,
// mirroring the pattern toolGetMedia uses for the two-step flow
// (s.borrowWithRetry + telegram.DownloadMedia). The bool return reports
// whether the download callback actually ran during the attempt that
// produced the returned error — see mediaDownloader. attempted is reset
// before every retry attempt (via borrowWithRetry's beforeAttempt hook) so a
// flood-wait retry whose first try called the callback but whose later
// Borrow call then fails in its own preflight/acquire path (never reaching
// the callback again) doesn't leave a stale true from the earlier attempt.
func (s *Server) downloadMediaViaPool(ctx context.Context, userID int64, loc telegram.MediaFileLocation, maxBytes int64) ([]byte, error, bool) {
	var buf []byte
	attempted := false
	err := s.borrowWithRetry(ctx, "fetch_media", userID, func(ctx context.Context, c *gotdtelegram.Client) error {
		attempted = true
		var derr error
		buf, derr = telegram.DownloadMedia(ctx, c, loc, maxBytes)
		return derr
	}, func() { attempted = false })
	return buf, err, attempted
}

// isSystemicPoolErr reports whether err represents a call-wide failure that
// should abort fetchMediaInline's loop rather than being folded into the
// per-item Skipped count: a revoked/expired/unauthorized session, no active
// session, the pool at capacity (sessionErrText/telegram.ErrPoolFull — the
// same sentinels borrowErrResult uses to render the actionable reconnect
// message), a session Telegram rejected whose DB revoke then failed to
// persist (telegram.ErrSessionRevokePersistFailed — call-wide like the
// others, but intentionally NOT one of sessionErrText's sentinels since we
// can't promise the "reconnect and you're set" recovery those imply), or the
// caller's context being canceled/deadline-exceeded (the client disconnected
// or the request timed out — continuing to attempt further downloads, or
// auditing the call as successful, would be wrong).
//
// This covers every *known* systemic error, but ClientPool.Borrow's own
// preflight (CheckSessionValid), acquire, and client-startup paths can also
// surface arbitrary unclassified errors (a transient database error, a
// generic connection failure) that match none of these sentinels. Callers
// should treat any error from a download that never reached the callback
// (see mediaDownloader's attempted return) as systemic too, regardless of
// whether isSystemicPoolErr recognizes it.
func isSystemicPoolErr(err error) bool {
	return sessionErrText(err) != "" ||
		errors.Is(err, telegram.ErrPoolFull) ||
		errors.Is(err, telegram.ErrSessionRevokePersistFailed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}

// fetchMediaInline attempts to download media bytes for each message in
// rawMsgs/msgs (parallel slices: same length, same order, one raw wire
// message per decoded Message), initiating at most BulkMediaFetchCap
// downloads and never pulling more than BulkMediaByteCap raw bytes in
// total across the whole call. It mutates MediaData on each message it
// successfully downloads; items left un-fetched due to either cap, the
// per-item size limit, a non-downloadable media type, protected content, or
// a per-item download error are left with MediaData == nil and counted in
// the returned summary's Skipped field (messages with no media at all are
// not counted — there was nothing to skip).
//
// Returns a non-nil error for a systemic failure (see isSystemicPoolErr) or
// for any error from a download whose callback never ran (Borrow failed in
// its own preflight/acquire/startup path with an error isSystemicPoolErr
// doesn't recognize) encountered mid-loop — e.g. the session was revoked
// while paging through history, the caller's context was canceled or hit
// its deadline, or a transient database error rejected the borrow before
// any bytes were requested. That aborts the loop immediately; the caller
// should treat it the same as the initial fetch's error (via
// borrowErrResult) rather than folding it into Skipped or auditing the call
// as successful. All other per-item failures keep the loop going and are
// logged at DEBUG level.
func (s *Server) fetchMediaInline(ctx context.Context, userID int64, rawMsgs []*tg.Message, msgs []telegram.Message) (FetchMediaSummary, error) {
	summary := FetchMediaSummary{Cap: BulkMediaFetchCap}
	n := len(rawMsgs)
	if len(msgs) < n {
		n = len(msgs)
	}
	attempted := 0
	var totalBytes int64
	for i := 0; i < n; i++ {
		loc, err := telegram.ExtractMediaLocation(rawMsgs[i])
		if err != nil || loc == nil {
			if msgs[i].MediaInfo != nil {
				// Non-downloadable type (web_page, contact, location, poll,
				// unsupported) or protected content (Noforwards): the page
				// had media here, it just isn't fetchable — count it.
				// rawMsgs[i].Media != nil is NOT the right test here: Telegram
				// sometimes sends an explicit MessageMediaEmpty constructor —
				// a non-nil Media value that DecodeMediaInfo (correctly)
				// treats as no media at all (MediaInfo == nil). Keying off
				// MediaInfo instead avoids over-counting those as skipped.
				summary.Skipped++
			}
			// Plain messages with no media at all are not counted; there
			// was never anything to skip.
			continue
		}
		if attempted >= BulkMediaFetchCap {
			summary.Skipped++
			continue
		}
		remaining := BulkMediaByteCap - totalBytes
		if remaining <= 0 {
			summary.Skipped++
			continue
		}
		// The effective per-item cap is the smaller of what remains of the
		// aggregate budget and the configured per-file limit (0 =
		// unbounded), so a page of several near-cap files — or files at all
		// when MEDIA_DOWNLOAD_MAX_BYTES=0 — can't multiply past
		// BulkMediaByteCap raw bytes for the whole call.
		perItemCap := remaining
		if s.MediaDownloadMaxBytes > 0 && s.MediaDownloadMaxBytes < perItemCap {
			perItemCap = s.MediaDownloadMaxBytes
		}
		// info.Size is 0 for photos (MTProto does not expose a declared byte size
		// for photos); they always proceed to the downloader, where cappedBuffer
		// enforces perItemCap mid-stream and an abort is counted as Skipped.
		if info := msgs[i].MediaInfo; info != nil && info.Size > 0 && info.Size > perItemCap {
			summary.Skipped++
			continue
		}
		attempted++
		data, dlErr, attemptedFn := mediaDownloader(s, ctx, userID, *loc, perItemCap)
		if dlErr != nil {
			if isSystemicPoolErr(dlErr) || !attemptedFn {
				return summary, dlErr
			}
			// A failed download whose callback ran may still have streamed
			// some bytes before erroring — e.g. cappedBuffer aborting an
			// oversized undeclared-size photo mid-stream. mediaDownloader
			// returns whatever was accumulated even on error (see
			// telegram.DownloadMedia), so charge that actual amount rather
			// than the full perItemCap: charging the worst case here would
			// let one instant, zero-byte per-item failure (a fast RPC error
			// before any chunk arrived) exhaust the entire remaining budget
			// and wrongly starve every later item, defeating the documented
			// "per-item failures keep the loop going" contract.
			totalBytes += int64(len(data))
			summary.Skipped++
			slog.Warn("fetch_media: item download failed, skipping", "message_id", rawMsgs[i].ID, "err", dlErr)
			continue
		}
		totalBytes += int64(len(data))
		encoded := base64.StdEncoding.EncodeToString(data)
		msgs[i].MediaData = &encoded
		summary.Fetched++
	}
	return summary, nil
}
