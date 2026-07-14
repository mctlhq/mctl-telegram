package telegram

import (
	"context"
	"fmt"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/downloader"
	"github.com/gotd/td/tg"
)

// DefaultMediaDownloadMaxBytes is the fallback per-download byte cap used when
// no explicit cap is configured (hosted: MEDIA_DOWNLOAD_MAX_BYTES; local
// bridge daemon: always this value).
const DefaultMediaDownloadMaxBytes int64 = 20971520 // 20 MiB

// MediaFileLocation identifies a downloadable Telegram file (document or
// photo) plus the access credentials Telegram requires to fetch it. The
// AccessHash and FileReference fields are secrets in the MTProto sense — they
// must never be returned to MCP clients, only held server-side between
// prepare_get_media and get_media.
type MediaFileLocation struct {
	IsDocument    bool
	DocID         int64
	PhotoID       int64
	AccessHash    int64
	FileReference []byte
	ThumbSize     string // photo only: type code of the size to download
}

func (l MediaFileLocation) inputLocation() tg.InputFileLocationClass {
	if l.IsDocument {
		return &tg.InputDocumentFileLocation{
			ID:            l.DocID,
			AccessHash:    l.AccessHash,
			FileReference: l.FileReference,
			ThumbSize:     "",
		}
	}
	return &tg.InputPhotoFileLocation{
		ID:            l.PhotoID,
		AccessHash:    l.AccessHash,
		FileReference: l.FileReference,
		ThumbSize:     l.ThumbSize,
	}
}

// PrepareMediaRef fetches message messageID from peer and extracts its media
// metadata and file location. Channel/supergroup peers are routed through
// channels.getMessages (messages.getMessages cannot see channel messages);
// everything else goes through messages.getMessages. Returns an error when
// the message does not exist or carries no downloadable media (web pages,
// contacts, locations, polls have MediaInfo but no file to fetch).
func PrepareMediaRef(ctx context.Context, c *telegram.Client, peerSpec string, messageID int, cache *PeerCache, userID int64) (*MediaInfo, *MediaFileLocation, error) {
	api := c.API()
	inputPeer, err := ResolvePeerCached(ctx, c, peerSpec, cache, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve peer: %w", err)
	}
	var result tg.MessagesMessagesClass
	if ch, ok := inputPeer.(*tg.InputPeerChannel); ok {
		result, err = api.ChannelsGetMessages(ctx, &tg.ChannelsGetMessagesRequest{
			Channel: &tg.InputChannel{ChannelID: ch.ChannelID, AccessHash: ch.AccessHash},
			ID:      []tg.InputMessageClass{&tg.InputMessageID{ID: messageID}},
		})
		if err != nil {
			return nil, nil, fmt.Errorf("ChannelsGetMessages: %w", err)
		}
	} else {
		result, err = api.MessagesGetMessages(ctx, []tg.InputMessageClass{&tg.InputMessageID{ID: messageID}})
		if err != nil {
			return nil, nil, fmt.Errorf("MessagesGetMessages: %w", err)
		}
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
		return nil, nil, fmt.Errorf("message %d not found", messageID)
	}
	info := DecodeMediaInfo(msg.Media)
	if info == nil {
		return nil, nil, fmt.Errorf("message %d has no downloadable media", messageID)
	}
	loc := &MediaFileLocation{}
	switch m := msg.Media.(type) {
	case *tg.MessageMediaDocument:
		if doc, ok := m.Document.(*tg.Document); ok {
			loc.IsDocument = true
			loc.DocID = doc.ID
			loc.AccessHash = doc.AccessHash
			loc.FileReference = doc.FileReference
		}
	case *tg.MessageMediaPhoto:
		if photo, ok := m.Photo.(*tg.Photo); ok {
			loc.PhotoID = photo.ID
			loc.AccessHash = photo.AccessHash
			loc.FileReference = photo.FileReference
			loc.ThumbSize = largestPhotoSizeType(photo.Sizes)
		}
	}
	if !loc.IsDocument && loc.PhotoID == 0 {
		return nil, nil, fmt.Errorf("message %d has media type %q, which is not downloadable", messageID, info.MediaType)
	}
	return info, loc, nil
}

// largestPhotoSizeType returns the type code of the largest downloadable
// photo size by pixel area. Both plain and progressive-JPEG size entries are
// candidates — modern servers often return ONLY photoSizeProgressive for the
// full-resolution rendition, so ignoring it would download a low-res
// thumbnail or nothing at all.
func largestPhotoSizeType(sizes []tg.PhotoSizeClass) string {
	best := ""
	bestArea := 0
	for _, sz := range sizes {
		var typ string
		var area int
		switch ps := sz.(type) {
		case *tg.PhotoSize:
			typ, area = ps.Type, ps.W*ps.H
		case *tg.PhotoSizeProgressive:
			typ, area = ps.Type, ps.W*ps.H
		default:
			continue
		}
		if area > bestArea {
			bestArea = area
			best = typ
		}
	}
	return best
}

// cappedBuffer accumulates downloaded bytes, failing the stream as soon as
// the cap is exceeded so oversized files abort mid-download instead of
// filling memory.
type cappedBuffer struct {
	buf []byte
	cap int64
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	if w.cap > 0 && int64(len(w.buf))+int64(len(p)) > w.cap {
		return 0, fmt.Errorf("download exceeded %d-byte cap mid-stream", w.cap)
	}
	w.buf = append(w.buf, p...)
	return len(p), nil
}

// DownloadMedia fetches the file identified by loc, enforcing maxBytes
// (0 = uncapped). It uses gotd's downloader rather than a manual
// upload.getFile loop: the library stops cleanly on the final short chunk
// (a manual loop keeps requesting past EOF and trips OFFSET_INVALID on files
// whose size is not 4KB-aligned) and follows upload.fileCdnRedirect for
// CDN-served popular media, which a bare *tg.UploadFile type assertion would
// reject.
func DownloadMedia(ctx context.Context, c *telegram.Client, loc MediaFileLocation, maxBytes int64) ([]byte, error) {
	w := &cappedBuffer{cap: maxBytes}
	d := downloader.NewDownloader().WithAllowCDN(true)
	if _, err := d.Download(c.API(), loc.inputLocation()).Stream(ctx, w); err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	return w.buf, nil
}
