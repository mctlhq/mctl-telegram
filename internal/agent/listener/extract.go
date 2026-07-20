// Package listener turns live Telegram updates for an agent-enabled account
// into durable incoming_events + queued agent_jobs. It attaches to the client
// pool via the AgentRuntime interface: HandlerFor builds a gotd update
// dispatcher wrapped in updates.Manager (gap recovery), RunFor runs the
// manager, and each mapped update is persisted with a deterministic event_id
// so gotd redelivery stays exactly-once at the DB.
package listener

import (
	"encoding/json"
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
	// outgoing message in Saved Messages — the raw text for the /mctl command
	// parser. The event is still persisted (kind saved_command) for audit.
	SavedCommandText string
}

// eventIDForMessage builds the deterministic dedup key for a message-bearing
// update. edit>0 appends the edit timestamp so a later edit of the same
// message yields a distinct event while a redelivery of the same edit dedups.
func eventIDForMessage(accountTGID, chatID, messageID int64, editDate int) string {
	base := "evt:v1:" + strconv.FormatInt(accountTGID, 10) + ":" +
		strconv.FormatInt(chatID, 10) + ":" + strconv.FormatInt(messageID, 10)
	if editDate > 0 {
		base += ":e" + strconv.Itoa(editDate)
	}
	return base
}

// ExtractMessage maps one *tg.Message (from a new or edit update) to an
// IncomingEvent for the given account. ok=false means the message is not
// agent-relevant (non-user peer, empty service message, a bot sender, …) and
// must be skipped. selfTGID is the account's own Telegram id; accountUserID is
// the internal users.id that owns the row.
//
// Pure and side-effect free so the full routing matrix is table-testable
// against hand-built tg structs, matching send_test.go / seedpeer_test.go.
func ExtractMessage(accountUserID, selfTGID int64, msg *tg.Message, ents tg.Entities, isEdit bool) (Extracted, bool) {
	if msg == nil || strings.TrimSpace(msg.Message) == "" {
		return Extracted{}, false
	}

	// Owner's own outgoing message.
	if msg.Out {
		peerUser, ok := msg.PeerID.(*tg.PeerUser)
		if !ok {
			return Extracted{}, false
		}
		if peerUser.UserID == selfTGID {
			ev := db.IncomingEvent{
				EventID:    eventIDForMessage(selfTGID, selfTGID, int64(msg.ID), editDate(msg, isEdit)),
				UserID:     accountUserID,
				Kind:       db.EventKindSavedCommand,
				ChatTGID:   selfTGID,
				SenderTGID: selfTGID,
				MessageID:  int64(msg.ID),
				Body:       msg.Message,
			}
			return Extracted{Event: ev, SavedCommandText: msg.Message}, true
		}
		ev := db.IncomingEvent{
			EventID:    eventIDForMessage(selfTGID, peerUser.UserID, int64(msg.ID), editDate(msg, isEdit)),
			UserID:     accountUserID,
			Kind:       db.EventKindOwnerOutgoing,
			ChatTGID:   peerUser.UserID,
			SenderTGID: selfTGID,
			MessageID:  int64(msg.ID),
			Body:       msg.Message,
		}
		return Extracted{Event: ev}, true
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
		EventID:    eventIDForMessage(selfTGID, peerUser.UserID, int64(msg.ID), editDate(msg, isEdit)),
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
