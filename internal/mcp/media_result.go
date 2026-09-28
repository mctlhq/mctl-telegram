package mcp

import (
	"encoding/json"
	"fmt"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// mediaTextInlineCapDefault is the total base64 length (in bytes) below which
// a media-bearing result keeps the legacy dual-encoded shape: the same base64
// in both the text content block and structuredContent. This is the value
// internal/config.Config.MediaTextInlineCapBytes defaults to
// (MEDIA_TEXT_INLINE_CAP_BYTES); it is named here so the default is
// documented next to the code that enforces it, per issue #705.
const mediaTextInlineCapDefault int64 = 1 << 20

// mediaTextOmitted reports whether a media-bearing result whose total base64
// length is mediaBytes should have its media fields replaced by a placeholder
// in the text content block. s.MediaTextInlineCapBytes == 0 means "always
// inline" (the pre-issue-705 behavior, and the zero value every existing
// *Server not explicitly configured with a cap gets) — never omitted,
// regardless of mediaBytes. This is also the escape hatch documented for
// MEDIA_TEXT_INLINE_CAP_BYTES=0.
func (s *Server) mediaTextOmitted(mediaBytes int64) bool {
	return s.MediaTextInlineCapBytes > 0 && mediaBytes > s.MediaTextInlineCapBytes
}

// mediaJSONResult returns v (a messagesResult or getMediaResult carrying
// base64 media) as a *mcplib.CallToolResult the way jsonResult does, except
// that when mediaBytes exceeds the server's inline cap it builds the text
// content block from textView — a copy of v with every base64 media field
// replaced by a short placeholder — instead of marshalling v itself. That
// keeps the media bytes reachable from exactly one place during response
// marshalling: structuredContent, serialized once by mcp-go.
//
// At or below the cap (or when the cap is 0, meaning "always inline"), this
// delegates to jsonResult(v) and is byte-for-byte identical to the pre-#705
// behavior, including json.MarshalIndent formatting — jsonResult itself is
// untouched, along with its ~90 other call sites.
//
// textView is called only on the omitted path, so the common below-cap path
// never builds the placeholder copy. The view carries no media bytes, so it
// is indented like jsonResult's output: the text block keeps one format on
// both sides of the cap.
func (s *Server) mediaJSONResult(v any, mediaBytes int64, textView func() any) (*mcplib.CallToolResult, error) {
	if !s.mediaTextOmitted(mediaBytes) {
		return jsonResult(v)
	}
	b, err := json.MarshalIndent(textView(), "", "  ")
	if err != nil {
		return mcplib.NewToolResultError("encode: " + err.Error()), nil
	}
	res := mcplib.NewToolResultText(string(b))
	res.StructuredContent = v
	return res, nil
}

// sumMediaDataBytes totals the base64 length of every message's MediaData
// without copying any of the underlying bytes — just len(*m.MediaData) per
// message — so computing mediaBytes for mediaJSONResult costs nothing
// proportional to the media itself.
func sumMediaDataBytes(msgs []telegram.Message) int64 {
	var n int64
	for i := range msgs {
		if msgs[i].MediaData != nil {
			n += int64(len(*msgs[i].MediaData))
		}
	}
	return n
}

// mediaOmittedPlaceholder is the text substituted for an omitted base64
// field. n is the number of base64 bytes omitted (from the source field's
// length, not the raw decoded size).
func mediaOmittedPlaceholder(n int, path string) string {
	return fmt.Sprintf("<omitted: %d base64 bytes; read %s or call prepare_get_media/get_media>", n, path)
}

// messagesTextView copies result and replaces every non-nil Messages[i].MediaData
// with a short placeholder naming the omitted byte count and where to find the
// bytes instead. It allocates nothing proportional to the media bytes: the
// copied []telegram.Message shares every other field (including Text) by
// value/pointer the way wrapMessages' own copy does, and MediaData is
// replaced with a small placeholder string, never read from the original.
func messagesTextView(result messagesResult) messagesResult {
	view := result
	if len(result.Messages) == 0 {
		return view
	}
	view.Messages = make([]telegram.Message, len(result.Messages))
	copy(view.Messages, result.Messages)
	for i := range view.Messages {
		if md := view.Messages[i].MediaData; md != nil {
			placeholder := mediaOmittedPlaceholder(len(*md), fmt.Sprintf("structuredContent.messages[%d].media_data", i))
			view.Messages[i].MediaData = &placeholder
		}
	}
	return view
}

// getMediaTextView copies result and replaces a non-empty Data with a short
// placeholder naming the omitted byte count and where to find the bytes
// instead.
func getMediaTextView(result getMediaResult) getMediaResult {
	view := result
	if view.Data != "" {
		view.Data = mediaOmittedPlaceholder(len(result.Data), "structuredContent.data")
	}
	return view
}
