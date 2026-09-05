package telegram

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/uploader"
	"github.com/gotd/td/tg"
)

// DefaultMediaUploadMaxBytes is the fallback per-upload byte cap used when no
// explicit cap is configured (hosted: MEDIA_UPLOAD_MAX_BYTES; local bridge
// daemon: always this value, mirroring DefaultMediaDownloadMaxBytes).
const DefaultMediaUploadMaxBytes int64 = 20971520 // 20 MiB

// ValidMediaTypes are the send_media MCP tool's supported media_type values.
// animation is kept distinct from video (see buildInputMedia) so a gif sent
// through this tool is never relabeled as a plain video.
var ValidMediaTypes = map[string]bool{
	"photo":     true,
	"video":     true,
	"document":  true,
	"animation": true,
	"voice":     true,
}

// SendMediaResult mirrors SendResult's shape (sent, mode, peer, message_id,
// dry_reason, notice) plus the media-specific fields the send_media tool
// exposes.
type SendMediaResult struct {
	Sent      bool   `json:"sent"`
	Mode      string `json:"mode"` // "send" or "draft"
	Notice    string `json:"notice,omitempty"`
	PeerInput string `json:"peer"`
	MediaType string `json:"media_type"`
	MimeType  string `json:"mime_type,omitempty"`
	FileName  string `json:"file_name,omitempty"`
	Caption   string `json:"caption,omitempty"`
	MessageID int    `json:"message_id,omitempty"`
	DryReason string `json:"dry_reason,omitempty"`
}

// SendMedia either uploads data and sends it as a real media message
// (mode="send" and gate allows) or returns a dry-run preview (mode="draft" or
// gate denies), mirroring SendMessage's dry-run/real-send split.
//
// Gate is evaluated by the caller; this fn assumes the green light when
// realSend is true. When realSend is false, data may be nil/empty — the
// caller must not have fetched file_url or decoded file_base64 in that case,
// per send_media's draft-by-default contract.
//
// cache and userID enable peer resolution caching; pass nil and 0 to disable.
func SendMedia(ctx context.Context, c *telegram.Client, peer, mediaType string, data []byte, fileName, mimeType, caption string, realSend bool, dryReason string, cache *PeerCache, userID int64, durationSeconds int) (*SendMediaResult, error) {
	if peer == "" {
		return nil, fmt.Errorf("peer required")
	}
	if !ValidMediaTypes[mediaType] {
		return nil, fmt.Errorf("invalid media_type %q", mediaType)
	}
	if !realSend {
		return &SendMediaResult{
			Sent:      false,
			Mode:      "draft",
			Notice:    "Draft preview — this media was NOT sent.",
			PeerInput: peer,
			MediaType: mediaType,
			MimeType:  mimeType,
			FileName:  fileName,
			Caption:   caption,
			DryReason: dryReason,
		}, nil
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("media bytes required for a real send")
	}
	if mediaType == "voice" {
		if err := validateVoicePayload(data); err != nil {
			return nil, err
		}
		// Telegram's voice player expects audio/ogg regardless of what
		// DetectContentType guessed (often application/ogg or octet-stream).
		mimeType = "audio/ogg"
		if fileName == "" {
			fileName = defaultUploadName("voice")
		}
	}

	var randomID int64
	{
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		randomID = int64(binary.LittleEndian.Uint64(b[:]))
	}

	uploadName := fileName
	if uploadName == "" {
		uploadName = defaultUploadName(mediaType)
	}
	uploaded, err := uploader.NewUploader(c.API()).Upload(ctx, uploader.NewUpload(uploadName, bytes.NewReader(data), int64(len(data))))
	if err != nil {
		return nil, fmt.Errorf("upload: %w", err)
	}
	media, err := buildInputMedia(mediaType, uploaded, fileName, mimeType, durationSeconds)
	if err != nil {
		return nil, err
	}

	updates, err := sendWithPeerRetry(ctx, c, peer, cache, userID, func(inputPeer tg.InputPeerClass) (tg.UpdatesClass, error) {
		return c.API().MessagesSendMedia(ctx, &tg.MessagesSendMediaRequest{
			Peer:     inputPeer,
			Media:    media,
			Message:  caption,
			RandomID: randomID,
		})
	})
	if err != nil {
		return nil, err
	}
	messageID := extractMessageID(updates)
	// Media sends are echoed through the same user session as outgoing
	// messages. Mark the server-assigned id before returning so the agent
	// listener does not interpret that echo as a manual owner takeover.
	notifyAgentSent(userID, int64(messageID))
	return &SendMediaResult{
		Sent:      true,
		Mode:      "send",
		PeerInput: peer,
		MediaType: mediaType,
		MimeType:  mimeType,
		FileName:  fileName,
		Caption:   caption,
		MessageID: messageID,
	}, nil
}

// defaultUploadName returns a generic filename to hand to the uploader when
// the caller (e.g. a file_url fetch, or file_base64 without file_name for a
// photo/video/animation) supplied none. Telegram does not require a
// meaningful name for photo/video/animation; document sends always carry a
// real file_name (enforced by the caller before this point).
func defaultUploadName(mediaType string) string {
	switch mediaType {
	case "photo":
		return "photo.jpg"
	case "video":
		return "video.mp4"
	case "animation":
		return "animation.mp4"
	case "voice":
		return "voice.ogg"
	default:
		return "file"
	}
}

// buildInputMedia constructs the tg.InputMediaClass appropriate for
// mediaType from an already-uploaded file handle.
//
// Attribute order matters for media_type=="animation": DocumentAttributeAnimated
// must precede DocumentAttributeVideo in the Attributes slice.
// internal/telegram/messages.go's DecodeMediaInfo classifies a document by
// the FIRST attribute in the list that sets info.MediaType (video and
// animation attributes only fill an empty slot; whichever appears first
// wins) — so animation-then-video here is what keeps a message this function
// sends from being read back as "video" instead of "animation".
func buildInputMedia(mediaType string, uploaded tg.InputFileClass, fileName, mimeType string, durationSeconds int) (tg.InputMediaClass, error) {
	switch mediaType {
	case "photo":
		return &tg.InputMediaUploadedPhoto{File: uploaded}, nil
	case "video":
		return &tg.InputMediaUploadedDocument{
			File:       uploaded,
			MimeType:   mimeType,
			Attributes: videoAttributes(fileName),
		}, nil
	case "animation":
		attrs := []tg.DocumentAttributeClass{&tg.DocumentAttributeAnimated{}}
		attrs = append(attrs, videoAttributes(fileName)...)
		return &tg.InputMediaUploadedDocument{
			File:       uploaded,
			MimeType:   mimeType,
			Attributes: attrs,
		}, nil
	case "document":
		attrs := []tg.DocumentAttributeClass{}
		if fileName != "" {
			attrs = append(attrs, &tg.DocumentAttributeFilename{FileName: fileName})
		}
		return &tg.InputMediaUploadedDocument{
			File:       uploaded,
			MimeType:   mimeType,
			Attributes: attrs,
		}, nil
	case "voice":
		if mimeType == "" {
			mimeType = "audio/ogg"
		}
		attrs := []tg.DocumentAttributeClass{
			&tg.DocumentAttributeAudio{Voice: true, Duration: durationSeconds},
		}
		if fileName != "" {
			attrs = append(attrs, &tg.DocumentAttributeFilename{FileName: fileName})
		}
		return &tg.InputMediaUploadedDocument{
			File:       uploaded,
			MimeType:   mimeType,
			Attributes: attrs,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported media_type %q", mediaType)
	}
}

// validateVoicePayload requires OGG container bytes. Telegram's voice player
// expects OGG/Opus; transcoding is out of scope, so anything else is refused
// rather than uploaded as a file attachment that would not render as a
// waveform. The OggS magic is the authority — DetectContentType often
// reports application/octet-stream for short Opus pages.
func validateVoicePayload(data []byte) error {
	if len(data) < 4 || string(data[:4]) != "OggS" {
		return fmt.Errorf("voice messages require OGG/Opus bytes")
	}
	return nil
}

// videoAttributes builds the DocumentAttributeVideo (+ optional filename)
// attribute list shared by video and animation media. Duration/W/H are left
// at zero (unknown) — Telegram accepts this, it just won't show a scrubber
// thumbnail as richly for agent-generated files with no known dimensions.
func videoAttributes(fileName string) []tg.DocumentAttributeClass {
	attrs := []tg.DocumentAttributeClass{
		&tg.DocumentAttributeVideo{SupportsStreaming: true},
	}
	if fileName != "" {
		attrs = append(attrs, &tg.DocumentAttributeFilename{FileName: fileName})
	}
	return attrs
}
