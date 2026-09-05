package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// prepareGetMediaResult is the success payload of prepare_get_media.
type prepareGetMediaResult struct {
	ConfirmationID string    `json:"confirmation_id"`
	PeerRedacted   string    `json:"peer_redacted"`
	MessageID      int       `json:"message_id"`
	MediaType      string    `json:"media_type"`
	MimeType       string    `json:"mime_type,omitempty"`
	FileName       string    `json:"file_name,omitempty"`
	Size           int64     `json:"size,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
}

// getMediaResult is the success payload of get_media.
type getMediaResult struct {
	MediaType string `json:"media_type"`
	MimeType  string `json:"mime_type,omitempty"`
	FileName  string `json:"file_name,omitempty"`
	Size      int64  `json:"size"`
	Data      string `json:"data"` // standard base64
}

// sendMediaFetchTimeout bounds a send_media file_url fetch, mirroring the
// 60s cap toolGetMedia uses for downloads.
const sendMediaFetchTimeout = 60 * time.Second

// maxCaptionLen mirrors Telegram's documented media-caption limit (1024
// characters — shorter than the 4096-character plain message-text limit
// send_message operates under). Applied defensively client-side, rather than
// relying on Telegram's own MEDIA_CAPTION_TOO_LONG error.
const maxCaptionLen = 1024

func (s *Server) toolPrepareGetMedia() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("prepare_get_media",
		mcplib.WithTitleAnnotation("Prepare a media download"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(true),
		mcplib.WithOutputSchema[prepareGetMediaResult](),
		mcplib.WithDescription(`Fetch a message's media metadata and return a confirmation_id for get_media.

The confirmation_id is valid for 10 minutes (single-shot). It binds the download to
the exact (peer, message_id) pair — passing different values to get_media will fail.

Inputs (required): peer, message_id.
Output: {confirmation_id, peer_redacted, message_id, media_type, mime_type, file_name, size, expires_at}.`),
		mcplib.WithString("peer",
			mcplib.Required(),
			mcplib.Description("Peer containing the message (@username or user/chat/channel id)."),
		),
		mcplib.WithNumber("message_id",
			mcplib.Required(),
			mcplib.Description("ID of the message whose media to prepare."),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "telegram:messages:read"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		args := req.GetArguments()
		peer := stringArg(args, "peer", "")
		messageID := intArg(args, "message_id", 0)
		if peer == "" || messageID == 0 {
			return mcplib.NewToolResultError("peer and message_id are required"), nil
		}
		if s.Hub != nil {
			mode, err := s.Store.GetAccountMode(ctx, id.UserID)
			if err == nil && mode == "local" {
				res, err2 := s.bridgeCall(ctx, id, "prepare_get_media", args)
				s.audit(ctx, id, "prepare_get_media", telegram.RedactPeer(peer), bridgeResultErr(res), startedAt, "local")
				return res, err2
			}
		}

		var ref *MediaDownloadRef
		var mediaInfo *telegram.MediaInfo
		err := s.borrowWithRetry(ctx, "prepare_get_media", id.UserID, func(ctx context.Context, c *gotdtelegram.Client) error {
			info, loc, err := telegram.PrepareMediaRef(ctx, c, peer, messageID, s.PeerCache, id.UserID)
			if err != nil {
				return err
			}
			mediaInfo = info
			ref = &MediaDownloadRef{
				Peer:      peer,
				MessageID: messageID,
				MediaType: info.MediaType,
				MimeType:  info.MimeType,
				FileName:  info.FileName,
				Size:      info.Size,
				Location:  *loc,
			}
			return nil
		})
		s.audit(ctx, id, "prepare_get_media", telegram.RedactPeer(peer), err, startedAt)
		if err != nil {
			if errors.Is(err, telegram.ErrPoolFull) {
				return mcplib.NewToolResultError("server at session capacity — try again later"), nil
			}
			return toolErr("prepare_get_media: %v", err), nil
		}

		conf, cerr := s.Confirms.Issue(id.UserID, "media", HashMediaPayload(peer, int64(messageID)))
		if cerr != nil {
			return toolErr("prepare_get_media: %v", cerr), nil
		}
		s.MediaStore.Set(conf.ID, ref)
		return jsonResult(prepareGetMediaResult{
			ConfirmationID: conf.ID,
			PeerRedacted:   telegram.RedactPeer(peer),
			MessageID:      messageID,
			MediaType:      mediaInfo.MediaType,
			MimeType:       mediaInfo.MimeType,
			FileName:       mediaInfo.FileName,
			Size:           mediaInfo.Size,
			ExpiresAt:      conf.ExpiresAt.UTC(),
		})
	}
	return tool, handler
}

func (s *Server) toolGetMedia() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("get_media",
		mcplib.WithTitleAnnotation("Download media from a Telegram message"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(true),
		mcplib.WithOutputSchema[getMediaResult](),
		mcplib.WithDescription(`Download media bytes for a Telegram message identified by (peer, message_id).

Requires a confirmation_id from prepare_get_media for the same (peer, message_id) pair.
The confirmation becomes in-flight on first use and is released when the download completes. Concurrent retries receive an 'in progress' response.

Returns the raw bytes encoded as standard base64 in the "data" field. Maximum download
size is controlled by MEDIA_DOWNLOAD_MAX_BYTES (default 20 MiB).

Inputs (required): peer, message_id, confirmation_id.
Output: {media_type, mime_type, file_name, size, data}.`),
		mcplib.WithString("peer",
			mcplib.Required(),
			mcplib.Description("Peer containing the message."),
		),
		mcplib.WithNumber("message_id",
			mcplib.Required(),
			mcplib.Description("ID of the message whose media to download."),
		),
		mcplib.WithString("confirmation_id",
			mcplib.Required(),
			mcplib.Description("Confirmation id from prepare_get_media."),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "telegram:messages:read"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		args := req.GetArguments()
		peer := stringArg(args, "peer", "")
		messageID := intArg(args, "message_id", 0)
		confID := stringArg(args, "confirmation_id", "")
		if peer == "" || messageID == 0 {
			return mcplib.NewToolResultError("peer and message_id are required"), nil
		}
		if confID == "" {
			return mcplib.NewToolResultError("confirmation_id required — call prepare_get_media first"), nil
		}
		if s.Hub != nil {
			mode, err := s.Store.GetAccountMode(ctx, id.UserID)
			if err == nil && mode == "local" {
				res, err2 := s.bridgeCall(ctx, id, "get_media", args)
				s.audit(ctx, id, "get_media", telegram.RedactPeer(peer), bridgeResultErr(res), startedAt, "local")
				return res, err2
			}
		}

		if _, cerr := s.Confirms.Claim(confID, id.UserID, HashMediaPayload(peer, int64(messageID))); cerr != nil {
			s.audit(ctx, id, "get_media", telegram.RedactPeer(peer), cerr, startedAt)
			if !errors.Is(cerr, ErrConfirmationInFlight) {
				// Claim already dropped (or never held) the ConfirmStore entry
				// for every other failure mode — drop the matching MediaStore
				// ref too so an expired or invalid probe doesn't leak it
				// indefinitely. Never touch it on ErrConfirmationInFlight: that
				// means a concurrent download legitimately owns this id.
				s.MediaStore.Delete(confID)
			}
			switch {
			case errors.Is(cerr, ErrConfirmationMismatch):
				return mcplib.NewToolResultError("confirmation_id was issued for a different (peer, message_id) — re-run prepare_get_media"), nil
			case errors.Is(cerr, ErrConfirmationWrongUser):
				return mcplib.NewToolResultError("confirmation_id belongs to another identity"), nil
			case errors.Is(cerr, ErrConfirmationInFlight):
				return mcplib.NewToolResultError("download already in progress for this confirmation_id — retry shortly"), nil
			default:
				return mcplib.NewToolResultError("confirmation_id not found, expired, or already used"), nil
			}
		}
		// Release the confirmation and media ref once we're done with them.
		// released tracks whether that already happened via the cancellation
		// branch below so the defer doesn't double-release; on every other
		// path (missing/oversized ref, real download error, success) the
		// defer's Finalize+Delete is what actually cleans up.
		released := false
		defer func() {
			if !released {
				s.Confirms.Finalize(confID)
				s.MediaStore.Delete(confID)
			}
		}()

		ref := s.MediaStore.Get(confID)
		if ref == nil {
			s.audit(ctx, id, "get_media", telegram.RedactPeer(peer), fmt.Errorf("media ref expired"), startedAt)
			return toolErr("media reference expired or missing — re-run prepare_get_media"), nil
		}

		if ref.Size > 0 && s.MediaDownloadMaxBytes > 0 && ref.Size > s.MediaDownloadMaxBytes {
			err := fmt.Errorf("file size %d bytes exceeds the %d-byte download cap", ref.Size, s.MediaDownloadMaxBytes)
			s.audit(ctx, id, "get_media", telegram.RedactPeer(peer), err, startedAt)
			return toolErr("file size %d bytes exceeds the %d-byte download cap", ref.Size, s.MediaDownloadMaxBytes), nil
		}

		var buf []byte
		downloadCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		dlErr := s.borrowWithRetry(downloadCtx, "get_media", id.UserID, func(ctx context.Context, c *gotdtelegram.Client) error {
			var err error
			buf, _, err = telegram.DownloadMedia(ctx, c, ref.Location, s.MediaDownloadMaxBytes)
			return err
		})
		s.audit(ctx, id, "get_media", telegram.RedactPeer(peer), dlErr, startedAt)
		if dlErr != nil {
			if errors.Is(dlErr, context.Canceled) || errors.Is(dlErr, context.DeadlineExceeded) {
				// The download was aborted by cancellation (client disconnect
				// or the caller's own transport-level timeout) or by our own
				// 60s cap — not a terminal failure of the operation itself.
				// Release the in-flight hold but keep the confirmation and
				// media ref alive so a retry with the same confirmation_id
				// can pick the download back up instead of being told
				// "not found".
				s.Confirms.Unclaim(confID)
				released = true
				return mcplib.NewToolResultError("download did not complete in time — retry with the same confirmation_id"), nil
			}
			if errors.Is(dlErr, telegram.ErrPoolFull) {
				return mcplib.NewToolResultError("server at session capacity — try again later"), nil
			}
			return toolErr("get_media: %v", dlErr), nil
		}
		return jsonResult(getMediaResult{
			MediaType: ref.MediaType,
			MimeType:  ref.MimeType,
			FileName:  ref.FileName,
			Size:      int64(len(buf)),
			Data:      base64.StdEncoding.EncodeToString(buf),
		})
	}
	return tool, handler
}

func (s *Server) toolSendMedia() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("send_media",
		mcplib.WithTitleAnnotation("Send Telegram Media"),
		// Annotations describe the worst-case real behavior, same rationale as
		// send_message: the server-side gate, not the annotation, is what keeps
		// tg.mctl.ai in dry-run by default.
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithOpenWorldHintAnnotation(true),
		mcplib.WithOutputSchema[telegram.SendMediaResult](),
		mcplib.WithDescription(`Send a photo, video, document, or animation (gif) to a Telegram peer, with an optional caption.

Draft-by-default: like send_message, media is sent for real only when the server send gate
is fully open (ALLOW_SEND=true, the telegram:messages:send scope, and per-account
send_enabled=true). Otherwise this returns a dry-run preview (sent=false) with a dry_reason —
nothing is fetched, decoded, or sent. The result's "sent" field tells you which happened.

Inputs (required):
  peer       — "@username", "user:<id>", "chat:<id>", or "channel:<id>".
  media_type — one of "photo", "video", "document", "animation". animation (gif) is sent as
               a distinct type from video and is never relabeled as a plain video.
  Exactly one of:
    file_url    — an HTTPS URL this server fetches and re-uploads. Must resolve to a public
                  address; loopback, link-local, and private-range addresses are refused.
    file_base64 — standard base64-encoded file bytes.
    file_path   — a local filesystem path (absolute or relative to the Local Bridge daemon's
                  working directory). Local Bridge accounts only — rejected with a validation
                  error for hosted accounts, before any filesystem access is attempted.

Inputs (optional):
  caption   — text attached to the media (truncated to Telegram's ~1024-char caption limit).
  file_name — REQUIRED when media_type="document" and file_base64 is the source; optional
              display name for file_url. Never required for file_path — it defaults to the
              path's basename when omitted.

Both the file_url fetch and the file_base64 decode are capped by MEDIA_UPLOAD_MAX_BYTES
(default 20 MiB) and are only ever performed on the real-send path — a draft or gate-denied
call never fetches a URL, decodes base64, or reads file_path.`),
		mcplib.WithString("peer",
			mcplib.Required(),
			mcplib.Description("Peer to send to."),
		),
		mcplib.WithString("media_type",
			mcplib.Required(),
			mcplib.Description(`One of "photo", "video", "document", "animation".`),
		),
		mcplib.WithString("file_url",
			mcplib.Description("HTTPS URL to fetch and send. Exactly one of file_url/file_base64/file_path is required."),
		),
		mcplib.WithString("file_base64",
			mcplib.Description("Standard base64-encoded file bytes. Exactly one of file_url/file_base64/file_path is required."),
		),
		mcplib.WithString("file_path",
			mcplib.Description("Local filesystem path (absolute or relative to the Local Bridge daemon's working directory). Local Bridge accounts only — rejected for hosted accounts. Exactly one of file_url/file_base64/file_path is required."),
		),
		mcplib.WithString("caption",
			mcplib.Description("Optional caption text for the media."),
		),
		mcplib.WithString("file_name",
			mcplib.Description(`Required when media_type="document" and file_base64 is used; optional display name otherwise. Defaults to the basename of file_path when file_path is the source and file_name is omitted.`),
		),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		// Checked eagerly, ahead of gate evaluation and any I/O — a deliberate
		// strengthening over send_message's pattern (which only checks the
		// scope deep inside evaluateSendGate). send_media has an extra
		// externally-triggerable I/O step (file_url) send_message doesn't, so a
		// caller lacking the scope must never reach it.
		if err := requireScope(id, "telegram:messages:send"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		args := req.GetArguments()
		peer := stringArg(args, "peer", "")
		mediaType := stringArg(args, "media_type", "")
		fileURL := stringArg(args, "file_url", "")
		fileB64 := stringArg(args, "file_base64", "")
		filePath := stringArg(args, "file_path", "")
		caption := truncate(stringArg(args, "caption", ""), maxCaptionLen)
		fileName := stringArg(args, "file_name", "")

		if peer == "" {
			return mcplib.NewToolResultError("peer is required"), nil
		}
		if !telegram.ValidMediaTypes[mediaType] {
			return mcplib.NewToolResultError(`media_type must be one of "photo", "video", "document", "animation"`), nil
		}
		sourceCount := 0
		for _, src := range []string{fileURL, fileB64, filePath} {
			if src != "" {
				sourceCount++
			}
		}
		if sourceCount != 1 {
			return mcplib.NewToolResultError("exactly one of file_url, file_base64, and file_path is required"), nil
		}
		if filePath != "" && fileName == "" {
			// Always derivable — write it back into args so the bridge-forwarded
			// copy (if any) carries the same derived name, avoiding a second
			// derivation on the daemon side.
			fileName = filepath.Base(filePath)
			args["file_name"] = fileName
		}
		if mediaType == "document" && fileB64 != "" && fileName == "" {
			return mcplib.NewToolResultError(`file_name is required when media_type is "document" and file_base64 is used`), nil
		}

		if filePath != "" {
			// file_path is only meaningful for a Local Bridge daemon, which has
			// direct access to the caller's own filesystem. The hosted server
			// must never resolve it against its own disk — reject before the
			// gate/draft branch runs and before any filesystem access, mirroring
			// the other fail-fast validation checks above.
			isLocalBridge := false
			if s.Hub != nil {
				if mode, err := s.Store.GetAccountMode(ctx, id.UserID); err == nil && mode == "local" {
					isLocalBridge = true
				}
			}
			if !isLocalBridge {
				return mcplib.NewToolResultError("file_path is only supported for Local Bridge accounts — use file_base64 or file_url, or connect Local Bridge"), nil
			}
		}

		peerRedacted := telegram.RedactPeer(peer)
		canSend, dryReason := evaluateSendGate(ctx, s.Store, id, s.AllowSend, s.DemoReviewerTGID)
		if canSend {
			if blocked, r := evaluateDirectSendLimiter(s.Limiter, id, peerRedacted); blocked {
				canSend = false
				dryReason = r
			}
		}
		if !canSend {
			// Draft-by-default: when the gate denies, return a successful
			// dry-run preview (not an error) without fetching file_url or
			// decoding file_base64 — a denied call must perform no meaningful
			// I/O. Resolving the byte source only happens in the real-send
			// branch below.
			s.audit(ctx, id, "send_media:draft", peerRedacted, nil, startedAt)
			result, _ := telegram.SendMedia(ctx, nil, peer, mediaType, nil, fileName, "", caption, false, dryReason, nil, 0)
			return jsonResult(result)
		}

		if s.Hub != nil {
			accountMode, modeErr := s.Store.GetAccountMode(ctx, id.UserID)
			if modeErr == nil && accountMode == "local" {
				// Gates passed server-side; signal the daemon to really send —
				// same mode-injection contract send_message relies on.
				args["mode"] = "send"
				res, err2 := s.bridgeCall(ctx, id, "send_media", args)
				s.audit(ctx, id, "send_media:via-bridge", peerRedacted, bridgeResultErr(res), startedAt, "local")
				return res, err2
			}
		}

		// Hosted mode, real send: this is the ONLY branch that fetches
		// file_url or decodes file_base64.
		data, mimeType, resolveErr := s.resolveSendMediaBytes(ctx, fileURL, fileB64)
		if resolveErr != nil {
			s.audit(ctx, id, "send_media:sent", peerRedacted, resolveErr, startedAt)
			return toolErr("send_media: %v", resolveErr), nil
		}

		var result *telegram.SendMediaResult
		err := s.borrowWithRetry(ctx, "send_media", id.UserID, func(ctx context.Context, c *gotdtelegram.Client) error {
			var inner error
			result, inner = telegram.SendMedia(ctx, c, peer, mediaType, data, fileName, mimeType, caption, true, "", s.PeerCache, id.UserID)
			return inner
		})
		s.audit(ctx, id, "send_media:sent", peerRedacted, err, startedAt)
		if err != nil {
			return borrowErrResult("send_media", err), nil
		}
		return jsonResult(result)
	}
	return tool, handler
}

// resolveSendMediaBytes decodes file_base64 or fetches file_url (SSRF-guarded),
// enforcing s.MediaUploadMaxBytes before returning. Exactly one of fileURL/
// fileB64 is non-empty — the caller has already validated that. Only ever
// called from send_media's real-send branch.
func (s *Server) resolveSendMediaBytes(ctx context.Context, fileURL, fileB64 string) ([]byte, string, error) {
	if fileB64 != "" {
		data, err := base64.StdEncoding.DecodeString(fileB64)
		if err != nil {
			return nil, "", fmt.Errorf("file_base64: invalid base64: %w", err)
		}
		if s.MediaUploadMaxBytes > 0 && int64(len(data)) > s.MediaUploadMaxBytes {
			return nil, "", fmt.Errorf("file_base64 decodes to %d bytes, exceeding the %d-byte upload cap", len(data), s.MediaUploadMaxBytes)
		}
		return data, http.DetectContentType(data[:min(512, len(data))]), nil
	}
	fetchCtx, cancel := context.WithTimeout(ctx, sendMediaFetchTimeout)
	defer cancel()
	data, mimeType, err := telegram.FetchGuardedURL(fetchCtx, fileURL, s.MediaUploadMaxBytes, sendMediaFetchTimeout)
	if err != nil {
		return nil, "", fmt.Errorf("file_url: %w", err)
	}
	return data, mimeType, nil
}
