// Package events publishes reference-only mctl.events/v1 envelopes for
// incoming Telegram messages to platform Valkey Streams (mctlhq/.github#87).
//
// An event is a signal, not a copy: the envelope names the account, chat and
// message, and the consumer (a Claude Code session) hydrates the text through
// this service's own MCP tools under its own authorization. The message body
// never leaves the database, where it is sealed per user.
package events

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// SpecVersion is the envelope contract, canonical schema in
// mctlhq/.github events/schemas/event-envelope.v1.schema.json.
const SpecVersion = "mctl.events/v1"

// Source identifies this producer in every envelope.
const Source = "mctl-telegram"

// DefaultStream is the Valkey stream this producer's ACL user may XADD to.
const DefaultStream = "mctl:events:telegram"

// Envelope mirrors the closed v1 schema. Subject values are strings only.
type Envelope struct {
	SpecVersion   string            `json:"specversion"`
	ID            string            `json:"id"`
	Type          string            `json:"type"`
	Source        string            `json:"source"`
	OccurredAt    string            `json:"occurred_at"`
	CorrelationID string            `json:"correlation_id"`
	Subject       map[string]string `json:"subject"`
}

// eventTypes maps the listener's event kinds onto envelope types. Kinds that
// are not listed (owner_outgoing, saved_command) are control-plane signals for
// the communication agent and are not published.
var eventTypes = map[string]string{
	db.EventKindPrivateMessage: "telegram.message.created",
	db.EventKindMessageEdit:    "telegram.message.edited",
}

// Publishable reports whether an incoming event kind produces an envelope.
func Publishable(kind string) bool {
	_, ok := eventTypes[kind]
	return ok
}

// BuildEnvelope derives the envelope for an incoming event. It reads only
// identifiers from ev -- never ev.Body or ev.Meta -- so no message content can
// reach the transport. The id is derived from the listener's deterministic
// event_id, so a redelivered Telegram update yields the same envelope id and
// the consumer deduplicates it.
func BuildEnvelope(ev db.IncomingEvent, occurredAt time.Time) (Envelope, error) {
	typ, ok := eventTypes[ev.Kind]
	if !ok {
		return Envelope{}, fmt.Errorf("event kind %q is not published", ev.Kind)
	}
	if ev.EventID == "" || ev.ChatTGID == 0 || ev.MessageID <= 0 {
		return Envelope{}, fmt.Errorf("event %q lacks identifiers", ev.EventID)
	}
	account, ok := telegramAccountID(ev.EventID)
	if !ok {
		return Envelope{}, fmt.Errorf("event %q does not name a Telegram account", ev.EventID)
	}
	id := "telegram:" + ev.EventID
	return Envelope{
		SpecVersion:   SpecVersion,
		ID:            id,
		Type:          typ,
		Source:        Source,
		OccurredAt:    occurredAt.UTC().Format(time.RFC3339),
		CorrelationID: id,
		Subject: map[string]string{
			"kind":       "telegram.message",
			"account_id": account,
			"chat_id":    strconv.FormatInt(ev.ChatTGID, 10),
			"message_id": strconv.FormatInt(ev.MessageID, 10),
			// The peer string the MCP get_messages tool accepts for this chat.
			"peer": "user:" + strconv.FormatInt(ev.ChatTGID, 10),
		},
	}, nil
}

// telegramAccountID returns the Telegram account id from a listener event id
// (evt:v1:<account>:<chat>:<message>[...]). The subject is a cross-service
// reference, so it carries the Telegram identity other services know, not this
// database's users.id.
//
// The whole id is checked, edit suffix included, so every envelope id meets the
// mctl.events/v1 identifier pattern and length that consumers enforce.
func telegramAccountID(eventID string) (string, bool) {
	m := listenerEventID.FindStringSubmatch(eventID)
	if m == nil || len("telegram:"+eventID) > maxIdentifierLen {
		return "", false
	}
	if n, err := strconv.ParseInt(m[1], 10, 64); err != nil || n <= 0 {
		return "", false
	}
	return m[1], true
}

// listenerEventID is the listener's event id format (see
// listener.eventIDForMessage): evt:v1:<account>:<chat>:<message>, plus
// :e<edit unix time>:<12 hex digits> for an edit.
var listenerEventID = regexp.MustCompile(`^evt:v1:([0-9]+):-?[0-9]+:[0-9]+(?::e[0-9]+:[0-9a-f]{12})?$`)

// maxIdentifierLen is the mctl.events/v1 limit on id and correlation_id.
const maxIdentifierLen = 256

// Marshal renders the envelope as compact JSON with a stable key order.
func (e Envelope) Marshal() (string, error) {
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	if len(b) > 4096 {
		return "", fmt.Errorf("envelope %s exceeds 4096 bytes", e.ID)
	}
	return string(b), nil
}
