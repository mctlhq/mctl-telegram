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
	// A bare "channel:<id>"/"user:<id>" spec resolves to a zero AccessHash
	// when the shared PeerCache is absent (Local Bridge daemon passes nil) or
	// cold — Telegram rejects such peers with CHANNEL_INVALID/PEER_ID_INVALID.
	// Recover the hash by scanning the dialog list, same source
	// GetMessages/seedPeerCache use.
	if peerNeedsAccessHash(inputPeer) {
		fromDialogs, derr := findPeerInDialogs(ctx, api, peerSpec)
		if derr != nil {
			return nil, nil, fmt.Errorf("peer %q carries no access hash and was not found in the dialog list; "+
				"call list_dialogs and use an id exactly as returned there: %w", peerSpec, derr)
		}
		inputPeer = fromDialogs
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
	// messages.getMessages looks up by GLOBAL message ID with no peer scoping
	// (unlike channels.getMessages) — without this check the confirmation
	// record could label media from a completely different chat with the
	// requested peer.
	if !messageBelongsToPeer(msg, inputPeer) {
		return nil, nil, fmt.Errorf("message %d does not belong to peer %q", messageID, peerSpec)
	}
	// Content protection: the chat owner marked this content non-savable
	// (Telegram clients disable saving/forwarding). Refuse to mint a
	// download ref rather than silently bypassing the restriction. Checked
	// via ExtractMediaLocation, ahead of the "no downloadable media" check
	// below, to preserve the exact original error-precedence order.
	loc, err := ExtractMediaLocation(msg)
	if err != nil {
		return nil, nil, err
	}
	info := DecodeMediaInfo(msg.Media)
	if info == nil {
		return nil, nil, fmt.Errorf("message %d has no downloadable media", messageID)
	}
	if loc == nil {
		return nil, nil, fmt.Errorf("message %d has media type %q, which is not downloadable", messageID, info.MediaType)
	}
	return info, loc, nil
}

// ExtractMediaLocation extracts the file location from an already-fetched
// tg.Message without making an additional Telegram API call. It mirrors the
// location-extraction logic PrepareMediaRef used to run inline before this
// helper was factored out; PrepareMediaRef now calls this function instead of
// duplicating the switch, so both call sites share one behavior.
//
// Returns (nil, nil) when the message carries no media, or media of a type
// that has no file to download (web_page, contact, location, poll,
// unsupported) — this is not an error, callers that want to skip such
// messages silently can treat a nil location as "nothing to fetch".
//
// Returns a non-nil error when the message is protected content (Noforwards
// set): the chat owner disabled saving/forwarding, so no location is minted
// even though the media itself may otherwise be downloadable.
func ExtractMediaLocation(msg *tg.Message) (*MediaFileLocation, error) {
	if msg == nil {
		return nil, nil
	}
	if msg.Noforwards {
		return nil, fmt.Errorf("message %d is protected content (owner disabled saving/forwarding)", msg.ID)
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
		return nil, nil
	}
	return loc, nil
}

// messageBelongsToPeer reports whether msg's owning dialog matches the
// InputPeer the caller asked about. Channel messages arrive pre-scoped via
// channels.getMessages, so a channel input always passes; user/chat inputs
// are compared against the message's PeerID.
func messageBelongsToPeer(msg *tg.Message, input tg.InputPeerClass) bool {
	switch in := input.(type) {
	case *tg.InputPeerChannel:
		return true
	case *tg.InputPeerUser:
		p, ok := msg.PeerID.(*tg.PeerUser)
		return ok && p.UserID == in.UserID
	case *tg.InputPeerChat:
		p, ok := msg.PeerID.(*tg.PeerChat)
		return ok && p.ChatID == in.ChatID
	default:
		return false
	}
}

// peerNeedsAccessHash reports whether the resolved InputPeer is missing the
// access hash Telegram requires for messages.*/channels.* calls. Basic
// groups (InputPeerChat) never carry one.
func peerNeedsAccessHash(p tg.InputPeerClass) bool {
	switch v := p.(type) {
	case *tg.InputPeerChannel:
		return v.AccessHash == 0
	case *tg.InputPeerUser:
		return v.AccessHash == 0
	default:
		return false
	}
}

// findPeerInDialogs locates peerSpec in the dialog list and returns a
// hash-bearing InputPeer for it — the same recovery GetMessages performs via
// its dialog scan, for callers that run without a seeded PeerCache (the
// Local Bridge daemon).
func findPeerInDialogs(ctx context.Context, api *tg.Client, peerSpec string) (tg.InputPeerClass, error) {
	dlgRes, err := api.MessagesGetDialogs(ctx, &tg.MessagesGetDialogsRequest{
		Limit:      200,
		OffsetPeer: &tg.InputPeerEmpty{},
	})
	if err != nil {
		return nil, fmt.Errorf("MessagesGetDialogs: %w", err)
	}
	users, chats, dialogs := decodeDialogsResult(dlgRes)
	for _, dc := range dialogs {
		d, ok := dc.(*tg.Dialog)
		if !ok {
			continue
		}
		hint := dialogFromPeer(d, users, chats)
		if hint == nil {
			continue
		}
		if hint.ID != peerSpec && !matchUsername(hint.Username, peerSpec) {
			continue
		}
		if input := inputPeerFromPeer(d.Peer, users, chats); input != nil {
			return input, nil
		}
	}
	return nil, fmt.Errorf("peer %q not in the dialog list", peerSpec)
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
//
// On error the returned slice is whatever cappedBuffer had accumulated
// before the failure (possibly empty, e.g. an immediate RPC error before any
// chunk arrived) rather than always nil — callers that bound an aggregate
// transfer budget across multiple downloads (fetchMediaInline) need the
// actual bytes consumed, not just success/failure, to charge a failed
// attempt accurately.
func DownloadMedia(ctx context.Context, c *telegram.Client, loc MediaFileLocation, maxBytes int64) ([]byte, error) {
	w := &cappedBuffer{cap: maxBytes}
	d := downloader.NewDownloader().WithAllowCDN(true)
	if _, err := d.Download(c.API(), loc.inputLocation()).Stream(ctx, w); err != nil {
		return w.buf, fmt.Errorf("download: %w", err)
	}
	return w.buf, nil
}
