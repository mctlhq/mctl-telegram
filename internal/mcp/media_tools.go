package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
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
The confirmation is single-shot and expires in 10 minutes.

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

		if _, cerr := s.Confirms.Consume(confID, id.UserID, HashMediaPayload(peer, int64(messageID))); cerr != nil {
			s.audit(ctx, id, "get_media", telegram.RedactPeer(peer), cerr, startedAt)
			switch {
			case errors.Is(cerr, ErrConfirmationMismatch):
				return mcplib.NewToolResultError("confirmation_id was issued for a different (peer, message_id) — re-run prepare_get_media"), nil
			case errors.Is(cerr, ErrConfirmationWrongUser):
				return mcplib.NewToolResultError("confirmation_id belongs to another identity"), nil
			default:
				return mcplib.NewToolResultError("confirmation_id not found, expired, or already used"), nil
			}
		}

		ref := s.MediaStore.Pop(confID)
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
			buf, err = telegram.DownloadMedia(ctx, c, ref.Location, s.MediaDownloadMaxBytes)
			return err
		})
		s.audit(ctx, id, "get_media", telegram.RedactPeer(peer), dlErr, startedAt)
		if dlErr != nil {
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
