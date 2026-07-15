// Package bridge defines the wire protocol for the Local Bridge mode
// (M4). In Local Bridge mode the MTProto session lives on the user's
// machine inside a local daemon; tg.mctl.ai becomes a relay that forwards
// MCP tool-call envelopes from Claude.ai down to the daemon and shuttles
// responses back. The daemon never gives the server its session bytes;
// the server never has to decrypt MTProto plaintext for these users.
//
// This package contains:
//   - Envelope: the JSON shape exchanged over the websocket connection.
//   - Hub:      the server-side router (one daemon connection per user).
//
// The websocket implementation itself (gorilla, nhooyr, or stdlib once
// it lands) is deferred — see DESIGN.md alongside this file for the
// remaining work and trade-offs.
package bridge

import (
	"encoding/json"
	"time"
)

// EnvelopeType discriminates the four kinds of frame the daemon and the
// relay exchange.
type EnvelopeType string

const (
	// TypeCall is server → daemon: please execute this MCP tool with these arguments.
	TypeCall EnvelopeType = "call"
	// TypeResponse is daemon → server: here is the result of call <ID>.
	TypeResponse EnvelopeType = "response"
	// TypeError is daemon → server: call <ID> failed; do not retry automatically.
	TypeError EnvelopeType = "error"
	// TypePing is bidirectional: liveness check. The other side must
	// answer with TypePong inside DeadlinePingPong.
	TypePing EnvelopeType = "ping"
	// TypePong is the answer to TypePing.
	TypePong EnvelopeType = "pong"
)

// DeadlinePingPong is how long each side waits for a pong before
// considering the peer dead and dropping the connection.
const DeadlinePingPong = 30 * time.Second

// DeadlineCall is the max time the relay waits for a daemon's response
// before timing out an in-flight tool call.
const DeadlineCall = 30 * time.Second

// DeadlineMediaCall is the per-call deadline for get_media: the daemon
// streams up to MaxMediaFrameBytes from Telegram over the user's own
// connection, and 30 s does not cover a 20 MiB file on a typical
// residential link (~5 Mbps ≈ 32 s for the download alone).
const DeadlineMediaCall = 180 * time.Second

// MaxMediaFrameBytes bounds a single websocket frame between daemon and
// relay. coder/websocket defaults to a 32 KiB read limit, which rejects any
// non-trivial get_media response (20 MiB of media ≈ 27 MiB of base64 JSON).
// 32 MiB leaves headroom over the base64-encoded MEDIA_DOWNLOAD_MAX_BYTES
// default plus envelope overhead.
const MaxMediaFrameBytes = 32 << 20

// DeadlineFor returns the response deadline for a tool call routed over the
// bridge. get_media is the only long-running call; everything else keeps the
// tight default so a stuck daemon is detected quickly.
func DeadlineFor(tool string) time.Duration {
	if tool == "get_media" {
		return DeadlineMediaCall
	}
	return DeadlineCall
}

// Envelope is the JSON frame written to and read from the websocket.
// Fields are split by type:
//
//	TypeCall:     ID, Tool, Args
//	TypeResponse: ID, Result
//	TypeError:    ID, Error
//	TypePing/Pong: no payload (ID may be set for round-trip latency)
//
// Result and Args are kept as json.RawMessage so the relay does not
// need to know each tool's schema; it forwards opaquely. This also
// means the daemon could in the future expose tools that the relay
// has never heard of, with no relay deploy required.
type Envelope struct {
	Type   EnvelopeType    `json:"type"`
	ID     string          `json:"id,omitempty"`
	Tool   string          `json:"tool,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// EncodeCall builds a TypeCall envelope. id should be a fresh UUID-ish
// string the relay can match against the eventual response.
func EncodeCall(id, tool string, args json.RawMessage) Envelope {
	return Envelope{Type: TypeCall, ID: id, Tool: tool, Args: args}
}

// EncodeResponse builds a TypeResponse envelope.
func EncodeResponse(id string, result json.RawMessage) Envelope {
	return Envelope{Type: TypeResponse, ID: id, Result: result}
}

// EncodeError builds a TypeError envelope. Error strings cross the wire
// verbatim; daemons MUST NOT include sensitive data (session bytes,
// phone numbers, etc) in this field.
func EncodeError(id, msg string) Envelope {
	return Envelope{Type: TypeError, ID: id, Error: msg}
}
