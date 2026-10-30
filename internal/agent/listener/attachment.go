package listener

import (
	"strconv"
	"strings"
	"unicode"

	"github.com/gotd/td/tg"
)

// Attachment kinds recorded in an inbound event's meta (#948). The agent
// cannot open any of them; the kind only lets it acknowledge that something
// arrived instead of telling the sender nothing did.
const (
	AttachmentDocument  = "document"
	AttachmentPhoto     = "photo"
	AttachmentVideo     = "video"
	AttachmentAnimation = "animation"
	AttachmentVoice     = "voice"
	AttachmentAudio     = "audio"
	AttachmentVideoNote = "video_note"
	AttachmentSticker   = "sticker"
	AttachmentContact   = "contact"
	AttachmentLocation  = "location"
	AttachmentPoll      = "poll"
	AttachmentOther     = "other"
)

const (
	maxAttachmentFileNameRunes = 200
	maxAttachmentMimeRunes     = 100
	maxAttachmentEmojiRunes    = 16
)

// attachmentMetadata describes what was attached, never what it contains.
// Contacts and locations carry the kind only: a shared phone number or a
// position is personal data the agent has no use for.
type attachmentMetadata struct {
	Kind     string `json:"kind"`
	FileName string `json:"file_name,omitempty"`
	MimeType string `json:"mime_type,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Emoji    string `json:"emoji,omitempty"`
}

// attachmentOf maps a message's media to its metadata. nil means there is
// no attachment worth recording: no media, an empty or unsupported media
// placeholder, or a link preview, which only renders a URL already in the
// text.
func attachmentOf(media tg.MessageMediaClass) *attachmentMetadata {
	switch m := media.(type) {
	case nil, *tg.MessageMediaEmpty, *tg.MessageMediaUnsupported, *tg.MessageMediaWebPage:
		return nil
	case *tg.MessageMediaPhoto:
		return &attachmentMetadata{Kind: AttachmentPhoto}
	case *tg.MessageMediaDocument:
		return documentAttachment(m)
	case *tg.MessageMediaContact:
		return &attachmentMetadata{Kind: AttachmentContact}
	case *tg.MessageMediaGeo, *tg.MessageMediaGeoLive, *tg.MessageMediaVenue:
		return &attachmentMetadata{Kind: AttachmentLocation}
	case *tg.MessageMediaPoll:
		return &attachmentMetadata{Kind: AttachmentPoll}
	default:
		return &attachmentMetadata{Kind: AttachmentOther}
	}
}

func documentAttachment(m *tg.MessageMediaDocument) *attachmentMetadata {
	att := &attachmentMetadata{Kind: AttachmentDocument}
	switch {
	case m.Voice:
		att.Kind = AttachmentVoice
	case m.Round:
		att.Kind = AttachmentVideoNote
	case m.Video:
		att.Kind = AttachmentVideo
	}
	doc, ok := m.Document.(*tg.Document)
	if !ok {
		return att
	}
	att.MimeType = cleanAttachmentText(doc.MimeType, maxAttachmentMimeRunes)
	if doc.Size > 0 {
		att.Size = doc.Size
	}
	explicit := att.Kind != AttachmentDocument
	for _, a := range doc.Attributes {
		switch attr := a.(type) {
		case *tg.DocumentAttributeFilename:
			att.FileName = cleanAttachmentText(attr.FileName, maxAttachmentFileNameRunes)
		case *tg.DocumentAttributeSticker:
			att.Kind = AttachmentSticker
			att.Emoji = cleanAttachmentText(attr.Alt, maxAttachmentEmojiRunes)
			explicit = true
		case *tg.DocumentAttributeAudio:
			if !explicit {
				att.Kind = AttachmentAudio
				if attr.Voice {
					att.Kind = AttachmentVoice
				}
			}
		case *tg.DocumentAttributeVideo:
			if !explicit {
				att.Kind = AttachmentVideo
				if attr.RoundMessage {
					att.Kind = AttachmentVideoNote
				}
			}
		case *tg.DocumentAttributeAnimated:
			if !explicit {
				att.Kind = AttachmentAnimation
				explicit = true
			}
		}
	}
	if att.Kind == AttachmentSticker {
		// A sticker's file name is an internal asset name, not something
		// the sender wrote.
		att.FileName = ""
	}
	return att
}

// cleanAttachmentText drops control and format characters (a file name is
// sender-chosen and may try to break out of the line it is shown on) and
// caps the length.
func cleanAttachmentText(s string, maxRunes int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		if n == maxRunes {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// attachmentFingerprint is appended to the edit dedup hash so an edit that
// swaps the attached file without touching the caption is still a distinct
// event. Empty when there is no attachment, which keeps text-only edit ids
// unchanged.
func attachmentFingerprint(media tg.MessageMediaClass) string {
	att := attachmentOf(media)
	if att == nil {
		return ""
	}
	fp := "\x00" + att.Kind
	if m, ok := media.(*tg.MessageMediaDocument); ok {
		if doc, ok := m.Document.(*tg.Document); ok {
			fp += ":d" + strconv.FormatInt(doc.ID, 10)
		}
	}
	if m, ok := media.(*tg.MessageMediaPhoto); ok {
		if p, ok := m.Photo.(*tg.Photo); ok {
			fp += ":p" + strconv.FormatInt(p.ID, 10)
		}
	}
	return fp
}
