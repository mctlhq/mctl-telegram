package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
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
			api := c.API()
			result, err := api.MessagesGetMessages(ctx, &tg.MessagesGetMessagesRequest{
				ID: []tg.InputMessageClass{&tg.InputMessageID{ID: messageID}},
			})
			if err != nil {
				return fmt.Errorf("MessagesGetMessages: %w", err)
			}
			var rawMsgs []tg.MessageClass
			switch v := result.(type) {
			case *tg.MessagesMessages:
				rawMsgs = v.Messages
			case *tg.MessagesMessagesSlice:
				rawMsgs = v.Messages
			case *tg.MessagesChannelMessages:
				rawMsgs = v.Messages
			}
			var msg *tg.Message
			for _, mc := range rawMsgs {
				if m, ok := mc.(*tg.Message); ok && m.ID == messageID {
					msg = m
					break
				}
			}
			if msg == nil {
				return fmt.Errorf("message %d not found", messageID)
			}
			mediaInfo = telegram.DecodeMediaInfo(msg.Media)
			if mediaInfo == nil {
				return fmt.Errorf("message %d has no downloadable media", messageID)
			}
			ref = &MediaDownloadRef{
				Peer:      peer,
				MessageID: messageID,
				MediaType: mediaInfo.MediaType,
				MimeType:  mediaInfo.MimeType,
				FileName:  mediaInfo.FileName,
				Size:      mediaInfo.Size,
			}
			// Populate location fields from the raw media.
			switch m := msg.Media.(type) {
			case *tg.MessageMediaDocument:
				if doc, ok := m.Document.(*tg.Document); ok {
					ref.IsDocument = true
					ref.DocID = doc.ID
					ref.AccessHash = doc.AccessHash
					ref.FileReference = doc.FileReference
				}
			case *tg.MessageMediaPhoto:
				if photo, ok := m.Photo.(*tg.Photo); ok {
					ref.IsDocument = false
					ref.PhotoID = photo.ID
					ref.AccessHash = photo.AccessHash
					ref.FileReference = photo.FileReference
					// Find the type code of the largest PhotoSize.
					bestArea := 0
					for _, sz := range photo.Sizes {
						if ps, ok := sz.(*tg.PhotoSize); ok {
							area := ps.W * ps.H
							if area > bestArea {
								bestArea = area
								ref.ThumbSize = ps.Type
							}
						}
					}
				}
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
			api := c.API()
			var loc tg.InputFileLocationClass
			if ref.IsDocument {
				loc = &tg.InputDocumentFileLocation{
					ID:            ref.DocID,
					AccessHash:    ref.AccessHash,
					FileReference: ref.FileReference,
					ThumbSize:     "",
				}
			} else {
				loc = &tg.InputPhotoFileLocation{
					ID:            ref.PhotoID,
					AccessHash:    ref.AccessHash,
					FileReference: ref.FileReference,
					ThumbSize:     ref.ThumbSize,
				}
			}
			offset := int64(0)
			const chunkSize = 512 * 1024 // 512 KB per Telegram API limit
			buf = nil
			for {
				res, err := api.UploadGetFile(ctx, &tg.UploadGetFileRequest{
					Location: loc,
					Offset:   offset,
					Limit:    chunkSize,
				})
				if err != nil {
					return fmt.Errorf("UploadGetFile: %w", err)
				}
				chunk, ok := res.(*tg.UploadFile)
				if !ok {
					return fmt.Errorf("unexpected UploadGetFile response type")
				}
				if len(chunk.Bytes) == 0 {
					break
				}
				buf = append(buf, chunk.Bytes...)
				offset += int64(len(chunk.Bytes))
				if s.MediaDownloadMaxBytes > 0 && int64(len(buf)) > s.MediaDownloadMaxBytes {
					return fmt.Errorf("download exceeded %d-byte cap mid-stream", s.MediaDownloadMaxBytes)
				}
			}
			return nil
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
