// Package bot is the login bot's inbound update receiver (issue-619).
//
// Transport only. It gets updates from Telegram, makes each one durable exactly
// once, and hands it to a small handler registry. It deliberately implements no
// command semantics: /subscribe and /settings belong to the #438 split,
// delivery results to #439, and clarification callbacks to #571. Nothing here
// sends a message, and the digest sender and the MCP tools are untouched.
//
// Transport choice: long-poll getUpdates, not a webhook. The service runs with
// strategy: Recreate at replicaCount 1 with no HPA, so every rollout has a
// window with no pod at all. A webhook would get a 502 in that window and
// Telegram gives up on a failing webhook after an undocumented number of
// attempts; getUpdates keeps the updates queued on Telegram's side for 24h and
// delivers them when the new pod polls. The same Recreate/replicas=1 shape is
// what makes long-poll's single-consumer requirement safe -- two pods never
// overlap, so getUpdates cannot 409. See the design comment on issue-619.
package bot

import (
	"database/sql"
	"encoding/json"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Update is the subset of a Telegram Update this receiver reads.
//
// It is deliberately tiny. Message text, callback payloads, phone numbers,
// contacts and media are NOT decoded into any field, so they cannot be logged,
// stored or passed to a handler by accident -- the safest way to keep content
// out of logs is to never hold it. Handlers that later need content must widen
// this struct explicitly, in a change that has to argue for itself.
type Update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *Message       `json:"message"`
	CallbackQuery *CallbackQuery `json:"callback_query"`
}

// Message carries routing facts only -- no text field, by construction.
type Message struct {
	Chat Chat `json:"chat"`
}

// CallbackQuery carries the query id and originating chat. The `data` payload
// is NOT decoded: routing for callbacks is by the chat and the registered
// handler, and the payload is attacker-influenced content that #571 will define
// a format for when it needs one.
type CallbackQuery struct {
	ID      string   `json:"id"`
	Message *Message `json:"message"`
}

// Chat is the chat a routable update arrived in.
type Chat struct {
	ID int64 `json:"id"`
}

// Kind classifies an update for the registry, and mirrors the db.Kind*
// constants stored on the row.
func (u Update) Kind() string {
	switch {
	case u.CallbackQuery != nil:
		return db.KindCallbackQuery
	case u.Message != nil:
		return db.KindMessage
	default:
		return db.KindUnsupported
	}
}

// ChatID returns the chat an update belongs to, if it has one. An update with
// no chat (an unsupported kind, or a callback query with no originating
// message) yields an invalid NullInt64 rather than a zero chat id, so "chat 0"
// and "no chat" stay distinguishable in the row and in the handler.
func (u Update) ChatID() sql.NullInt64 {
	switch {
	case u.CallbackQuery != nil && u.CallbackQuery.Message != nil:
		return sql.NullInt64{Int64: u.CallbackQuery.Message.Chat.ID, Valid: true}
	case u.Message != nil:
		return sql.NullInt64{Int64: u.Message.Chat.ID, Valid: true}
	default:
		return sql.NullInt64{}
	}
}

// getUpdatesResponse is the Bot API envelope for getUpdates.
type getUpdatesResponse struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	ErrorCode   int             `json:"error_code"`
	Result      json.RawMessage `json:"result"`
}
