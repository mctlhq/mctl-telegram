package pa

import (
	"encoding/json"
	"strconv"
)

// Kind is the kind of a verified update. Only two exist: allowed_updates is
// message and callback_query (threat model T4).
type Kind string

const (
	KindMessage       Kind = "message"
	KindCallbackQuery Kind = "callback_query"
)

// Outcome labels for every way an update can leave the ingress. They are
// counter labels only; no update content is ever logged.
const (
	OutcomeAccepted     = "accepted"
	OutcomeDuplicate    = "duplicate"
	DropMalformed       = "malformed"
	DropUnsupportedKind = "unsupported_kind"
	DropBusiness        = "business"
	DropNotPrivate      = "not_private"
	DropChatMismatch    = "chat_from_mismatch"
	DropSenderChat      = "sender_chat"
	DropViaBot          = "via_bot"
	DropNoSender        = "no_sender"
	DropBotSender       = "bot_sender"
	DropInlineCallback  = "inline_callback"
)

// maxCallbackData is Telegram's documented limit on callback_data (1-64
// bytes). Anything longer did not come from a keyboard this bot built.
const maxCallbackData = 64

// Principal is the Telegram user a run acts for. Its only constructor is the
// ingress filter (invariant I2): it is never built from tool arguments, model
// output, a worker request field, a URL parameter or a cookie. The zero value
// is "no principal" and is refused everywhere.
type Principal struct{ telegramID int64 }

// TelegramID returns the principal's Telegram user id.
func (p Principal) TelegramID() int64 { return p.telegramID }

// IsZero reports whether p is the zero, invalid principal.
func (p Principal) IsZero() bool { return p.telegramID <= 0 }

// VerifiedUpdate is an update that passed the T4 filter. Its fields are
// unexported so that no package other than this one can fabricate one: every
// VerifiedUpdate outside tests came from Filter.
//
// It deliberately carries no message text. Text is decoded together with its
// provenance mark (threat model T5) in the conversation-state slice, so that
// unmarked content never exists in memory as a plain string.
type VerifiedUpdate struct {
	updateID     int64
	kind         Kind
	principal    Principal
	messageID    int64
	callbackID   string
	callbackData string
}

func (u VerifiedUpdate) UpdateID() int64      { return u.updateID }
func (u VerifiedUpdate) Kind() Kind           { return u.kind }
func (u VerifiedUpdate) Principal() Principal { return u.principal }

// MessageID is the message_id of a message update, or of the message a
// callback button was attached to.
func (u VerifiedUpdate) MessageID() int64 { return u.messageID }

// CallbackID is the callback_query id (needed to answer it); empty for a
// message update.
func (u VerifiedUpdate) CallbackID() string { return u.callbackID }

// CallbackData is the opaque callback_data. It is attacker-influenced input:
// a later slice resolves it as a random id under (Principal, id), never as a
// reference that names its own owner (T4, cross-user isolation).
func (u VerifiedUpdate) CallbackData() string { return u.callbackData }

type tgUser struct {
	ID    int64 `json:"id"`
	IsBot bool  `json:"is_bot"`
}

type tgChat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

// messageRejectKeys are message fields whose mere presence drops the update,
// even with a null value. sender_chat: sent on behalf of a chat, so from.id
// is not the author. via_bot: content composed by another bot.
// business_connection_id / sender_business_bot: Telegram Business would
// deliver third parties' private messages to the bot.
var messageRejectKeys = []struct{ key, outcome string }{
	{"business_connection_id", DropBusiness},
	{"sender_business_bot", DropBusiness},
	{"sender_chat", DropSenderChat},
	{"via_bot", DropViaBot},
}

// Filter applies the T4 update filter to one raw webhook body. It returns the
// verified update and OutcomeAccepted, or a zero VerifiedUpdate and the drop
// outcome. It fails closed: anything it does not positively recognise as a
// private-chat message or callback from a human principal is dropped.
func Filter(body []byte) (VerifiedUpdate, string) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil || top == nil {
		return VerifiedUpdate{}, DropMalformed
	}
	rawID, ok := top["update_id"]
	if !ok {
		return VerifiedUpdate{}, DropMalformed
	}
	updateID, err := strconv.ParseInt(string(rawID), 10, 64)
	if err != nil || updateID < 0 {
		return VerifiedUpdate{}, DropMalformed
	}

	// Exactly one payload key, and it must be message or callback_query.
	// Every other kind -- edited_message, channel_post, business_message,
	// business_connection, inline_query, my_chat_member, ... -- is dropped
	// even if allowed_updates should have stopped Telegram sending it.
	var payloadKey string
	for k := range top {
		if k == "update_id" {
			continue
		}
		if payloadKey != "" {
			return VerifiedUpdate{}, DropUnsupportedKind
		}
		payloadKey = k
	}
	switch payloadKey {
	case "message":
		return filterMessage(updateID, top["message"])
	case "callback_query":
		return filterCallback(updateID, top["callback_query"])
	case "business_connection", "business_message", "edited_business_message", "deleted_business_messages":
		return VerifiedUpdate{}, DropBusiness
	default:
		return VerifiedUpdate{}, DropUnsupportedKind
	}
}

func filterMessage(updateID int64, raw json.RawMessage) (VerifiedUpdate, string) {
	fields, ok := decodeObject(raw)
	if !ok {
		return VerifiedUpdate{}, DropMalformed
	}
	if outcome := rejectMessageKeys(fields); outcome != "" {
		return VerifiedUpdate{}, outcome
	}
	principal, messageID, outcome := privateSender(fields, fields)
	if outcome != "" {
		return VerifiedUpdate{}, outcome
	}
	return VerifiedUpdate{
		updateID:  updateID,
		kind:      KindMessage,
		principal: principal,
		messageID: messageID,
	}, OutcomeAccepted
}

func filterCallback(updateID int64, raw json.RawMessage) (VerifiedUpdate, string) {
	fields, ok := decodeObject(raw)
	if !ok {
		return VerifiedUpdate{}, DropMalformed
	}
	// A button on an inline-mode message lives in someone else's chat; the
	// PA only answers buttons it put in the principal's own private chat.
	if _, present := fields["inline_message_id"]; present {
		return VerifiedUpdate{}, DropInlineCallback
	}
	var id string
	if err := json.Unmarshal(fields["id"], &id); err != nil || id == "" {
		return VerifiedUpdate{}, DropMalformed
	}
	var data string
	if rawData, present := fields["data"]; present {
		if err := json.Unmarshal(rawData, &data); err != nil || len(data) > maxCallbackData {
			return VerifiedUpdate{}, DropMalformed
		}
	}
	msgRaw, present := fields["message"]
	if !present {
		return VerifiedUpdate{}, DropInlineCallback
	}
	msg, ok := decodeObject(msgRaw)
	if !ok {
		return VerifiedUpdate{}, DropMalformed
	}
	// The button's message gets the same field checks as a message update:
	// a button on a business, sender_chat or via_bot message is not one this
	// bot put in the principal's own chat.
	if outcome := rejectMessageKeys(msg); outcome != "" {
		return VerifiedUpdate{}, outcome
	}
	// The sender is the callback's from (who pressed the button); the chat is
	// the one the button's message is in. Both must be the same private chat.
	principal, messageID, outcome := privateSender(fields, msg)
	if outcome != "" {
		return VerifiedUpdate{}, outcome
	}
	return VerifiedUpdate{
		updateID:     updateID,
		kind:         KindCallbackQuery,
		principal:    principal,
		messageID:    messageID,
		callbackID:   id,
		callbackData: data,
	}, OutcomeAccepted
}

// privateSender extracts the principal from fromObj["from"] and checks it
// against msgObj["chat"]: a human sender in a private chat whose id is the
// sender's own id. msgObj also supplies message_id.
func privateSender(fromObj, msgObj map[string]json.RawMessage) (Principal, int64, string) {
	rawFrom, present := fromObj["from"]
	if !present || isNull(rawFrom) {
		return Principal{}, 0, DropNoSender
	}
	var from tgUser
	if err := json.Unmarshal(rawFrom, &from); err != nil {
		return Principal{}, 0, DropMalformed
	}
	if from.ID <= 0 {
		return Principal{}, 0, DropNoSender
	}
	if from.IsBot {
		return Principal{}, 0, DropBotSender
	}
	rawChat, present := msgObj["chat"]
	if !present || isNull(rawChat) {
		return Principal{}, 0, DropMalformed
	}
	var chat tgChat
	if err := json.Unmarshal(rawChat, &chat); err != nil {
		return Principal{}, 0, DropMalformed
	}
	if chat.Type != "private" {
		return Principal{}, 0, DropNotPrivate
	}
	if chat.ID != from.ID {
		return Principal{}, 0, DropChatMismatch
	}
	var messageID int64
	if rawMID, ok := msgObj["message_id"]; ok {
		if err := json.Unmarshal(rawMID, &messageID); err != nil {
			return Principal{}, 0, DropMalformed
		}
	}
	return Principal{telegramID: from.ID}, messageID, ""
}

// rejectMessageKeys returns the drop outcome of the first messageRejectKeys
// field present in a message object, or "".
func rejectMessageKeys(msg map[string]json.RawMessage) string {
	for _, r := range messageRejectKeys {
		if _, present := msg[r.key]; present {
			return r.outcome
		}
	}
	return ""
}

func decodeObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

func isNull(raw json.RawMessage) bool { return string(raw) == "null" }
