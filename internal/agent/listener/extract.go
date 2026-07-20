// Package listener turns live Telegram updates for an agent-enabled account
// into durable incoming_events + queued agent_jobs. It attaches to the client
// pool via the AgentRuntime interface: HandlerFor builds a gotd update
// dispatcher wrapped in updates.Manager (gap recovery), RunFor runs the
// manager, and each mapped update is persisted with a deterministic event_id
// so gotd redelivery stays exactly-once at the DB.
package listener

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Extracted is the pure result of mapping one raw update: the event to persist
// plus a routing hint the listener acts on after the DB write.
type Extracted struct {
	Event db.IncomingEvent
	// SavedCommandText is non-empty when the update is the owner's own
	// outgoing /mctl command in Saved Messages. Ordinary Saved Messages notes
	// are never retained by the agent listener.
	SavedCommandText string
}

// eventIDForMessage builds the deterministic dedup key for a message-bearing
// update. Edits include both Telegram's second-resolution edit timestamp and a
// short content hash: two distinct edits within one second remain distinct,
// while redelivery of the same edit still deduplicates.
func eventIDForMessage(accountTGID, chatID, messageID int64, editDate int, body string) string {
	base := "evt:v1:" + strconv.FormatInt(accountTGID, 10) + ":" +
		strconv.FormatInt(chatID, 10) + ":" + strconv.FormatInt(messageID, 10)
	if editDate > 0 {
		sum := sha256.Sum256([]byte(body))
		base += ":e" + strconv.Itoa(editDate) + ":" + fmt.Sprintf("%x", sum[:6])
	}
	return base
}

func isMCTLCommand(text string) bool {
	fields := strings.Fields(text)
	return len(fields) > 0 && strings.EqualFold(fields[0], "/mctl")
}

// ExtractMessage maps one *tg.Message (from a new or edit update) to an
// IncomingEvent for the given account. ok=false means the message is not
// agent-relevant (non-user peer, empty inbound/service message, a bot sender,
// etc.). Owner outgoing messages are kept even without text: a photo, sticker,
// voice note, or other media-only reply is still a human takeover signal.
func ExtractMessage(accountUserID, selfTGID int64, msg *tg.Message, ents tg.Entities, isEdit bool) (Extracted, bool) {
	if msg == nil {
		return Extracted{}, false
	}
	text := strings.TrimSpace(msg.Message)

	// Owner's own outgoing message.
	if msg.Out {
		peerUser, ok := msg.PeerID.(*tg.PeerUser)
		if !ok {
			return Extracted{}, false
		}
		if peerUser.UserID == selfTGID {
			// Saved Messages is private scratch space. Retain only explicit /mctl
			// control commands; ordinary personal notes must never enter agent
			// retention or reach the command router.
			if !isMCTLCommand(text) {
				return Extracted{}, false
			}
			ev := db.IncomingEvent{
				EventID:    eventIDForMessage(selfTGID, selfTGID, int64(msg.ID), editDate(msg, isEdit), msg.Message),
				UserID:     accountUserID,
				Kind:       db.EventKindSavedCommand,
				ChatTGID:   selfTGID,
				SenderTGID: selfTGID,
				MessageID:  int64(msg.ID),
				Body:       msg.Message,
			}
			return Extracted{Event: ev, SavedCommandText: msg.Message}, true
		}
		// Do not require text here: any visible owner intervention in a private
		// chat (including media without caption) must stop autonomous replies.
		ev := db.IncomingEvent{
			EventID:    eventIDForMessage(selfTGID, peerUser.UserID, int64(msg.ID), editDate(msg, isEdit), msg.Message),
			UserID:     accountUserID,
			Kind:       db.EventKindOwnerOutgoing,
			ChatTGID:   peerUser.UserID,
			SenderTGID: selfTGID,
			MessageID:  int64(msg.ID),
			Body:       msg.Message,
		}
		return Extracted{Event: ev}, true
	}

	if text == "" {
		return Extracted{}, false
	}
	peerUser, ok := msg.PeerID.(*tg.PeerUser)
	if !ok {
		return Extracted{}, false
	}
	senderID := peerUser.UserID
	if from, ok := msg.FromID.(*tg.PeerUser); ok {
		senderID = from.UserID
	}
	if u, ok := ents.Users[senderID]; ok && u.Bot {
		return Extracted{}, false
	}

	kind := db.EventKindPrivateMessage
	if isEdit {
		kind = db.EventKindMessageEdit
	}
	ev := db.IncomingEvent{
		EventID:    eventIDForMessage(selfTGID, peerUser.UserID, int64(msg.ID), editDate(msg, isEdit), msg.Message),
		UserID:     accountUserID,
		Kind:       kind,
		ChatTGID:   peerUser.UserID,
		SenderTGID: senderID,
		MessageID:  int64(msg.ID),
		Body:       msg.Message,
		Meta:       senderMeta(ents.Users[senderID]),
	}
	return Extracted{Event: ev}, true
}

func editDate(msg *tg.Message, isEdit bool) int {
	if !isEdit {
		return 0
	}
	if d, ok := msg.GetEditDate(); ok && d > 0 {
		return d
	}
	return msg.Date
}

type senderMetadata struct {
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	IsContact   bool   `json:"is_contact,omitempty"`
	IsBot       bool   `json:"is_bot,omitempty"`
}

// senderMeta builds strict JSON. strconv.Quote is intentionally not used:
// it may emit Go-only escapes such as \xNN that json.Unmarshal rejects.
func senderMeta(u *tg.User) string {
	if u == nil {
		return "{}"
	}
	b, err := json.Marshal(senderMetadata{
		Username:    u.Username,
		DisplayName: strings.TrimSpace(u.FirstName + " " + u.LastName),
		IsContact:   u.Contact,
		IsBot:       u.Bot,
	})
	if err != nil {
		return "{}"
	}
	return string(b)
}

// senderIdentityFromMeta decodes the fields used to seed a conversation.
// Malformed metadata is ignored rather than blocking ingestion.
func senderIdentityFromMeta(meta string) (username, displayName string) {
	if meta == "" || meta == "{}" {
		return "", ""
	}
	var m senderMetadata
	if err := json.Unmarshal([]byte(meta), &m); err != nil {
		return "", ""
	}
	return m.Username, m.DisplayName
}
