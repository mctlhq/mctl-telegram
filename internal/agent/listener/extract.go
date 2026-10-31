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
	"time"

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
	// SenderAccessHash is the sender's MTProto access_hash, captured from
	// the update's entity data (ents.Users), when this is an inbound private
	// message or edit. 0 when unknown or unusable — see the guard in
	// ExtractMessage. The listener persists it onto the conversation row
	// (Store.SetConversationPeerAccessHash) so the executor can build a
	// working InputPeerUser later: messages.* RPCs reject a zero-access-hash
	// peer with PEER_ID_INVALID.
	SenderAccessHash int64
	// SentAt is when Telegram says the owner sent this message (msg.Date),
	// set only for EventKindOwnerOutgoing. An edit keeps the original send
	// time, so editing an old message is not fresh engagement (#953). Zero
	// when Telegram gave no date.
	SentAt time.Time
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
// agent-relevant (non-user peer, inbound message with neither text nor an
// attachment, a bot sender, a sender or recipient in the owner's contacts,
// etc.). Owner outgoing messages are kept even without text: a photo, sticker,
// voice note, or other media-only reply is still a human takeover signal.
func ExtractMessage(accountUserID, selfTGID int64, msg *tg.Message, ents tg.Entities, isEdit bool) (Extracted, bool) {
	if msg == nil {
		return Extracted{}, false
	}
	text := strings.TrimSpace(msg.Message)

	// Saved Messages dialog: classify by peer identity, not msg.Out.
	// classifySavedCommand's own doc comment already documents that Out is
	// not reliable for this one peer on the messages.getHistory path; live
	// evidence 2026-08-01 (mctl-telegram#354) showed the SAME unreliability
	// on the live push too -- two consecutive genuine owner /mctl approve
	// sends, and even this account's own SendMessage echo of its own draft
	// notification moments earlier, all arrived with Out=false. Gating on
	// Out here (as an earlier version of this function did) silently
	// misfiled them as ordinary inbound private messages from "sender
	// self", which the fallback poller's own event_id-based dedup can then
	// never recover from -- the command is lost permanently, not delayed.
	// classifySavedCommand's forwarded/saved-peer/from-id checks are what
	// actually gate this peer (nothing but the owner can author a message
	// that lands in their own primary Saved Messages dialog), so this is no
	// less safe than the Out-gated version, only less fragile.
	if isSelfPeer(msg.PeerID, selfTGID) {
		return classifySavedCommand(accountUserID, selfTGID, msg, text, isEdit)
	}

	// Owner's own outgoing message to some other peer.
	if msg.Out {
		peerUser, ok := msg.PeerID.(*tg.PeerUser)
		if !ok {
			return Extracted{}, false
		}
		// An edit Telegram makes on its own (edit_hide: a link preview
		// filling in, a live-location refresh) is not the owner's hand.
		// The listener no longer treats any outgoing edit as an agent echo
		// (#993), so without this a preview appearing on an agent reply
		// would take the conversation over.
		if media, _ := msg.GetMedia(); isEdit && hiddenEdit(msg, media) {
			return Extracted{}, false
		}
		// The owner writing to a contact is private correspondence the agent
		// never handles (inbound from contacts is skipped below), so it is
		// not recorded either.
		if u, ok := ents.Users[peerUser.UserID]; ok && u.Contact {
			return Extracted{}, false
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
		var sentAt time.Time
		if msg.Date > 0 {
			sentAt = time.Unix(int64(msg.Date), 0).UTC()
		}
		return Extracted{Event: ev, SentAt: sentAt}, true
	}

	// Media counts as content (#948): a file, photo or voice note with no
	// caption is still a message the sender expects someone to see.
	media, _ := msg.GetMedia()
	attachment := attachmentOf(media)
	if isEdit && hiddenEdit(msg, media) {
		return Extracted{}, false
	}
	if text == "" && attachment == nil {
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
	senderUser, hasSenderUser := ents.Users[senderID]
	if hasSenderUser && senderUser.Bot {
		return Extracted{}, false
	}
	// A sender in the owner's contacts is someone the owner already knows,
	// not a cold contact the agent is for: their messages are never stored or
	// shown to the model. Telegram sets contact on the user entity. When the
	// update carries no entity for the sender, the status is unknown and the
	// message is processed as before.
	if hasSenderUser && senderUser.Contact {
		return Extracted{}, false
	}

	kind := db.EventKindPrivateMessage
	if isEdit {
		kind = db.EventKindMessageEdit
	}
	ev := db.IncomingEvent{
		EventID: eventIDForMessage(selfTGID, peerUser.UserID, int64(msg.ID), editDate(msg, isEdit),
			msg.Message+attachmentFingerprint(media)),
		UserID:     accountUserID,
		Kind:       kind,
		ChatTGID:   peerUser.UserID,
		SenderTGID: senderID,
		MessageID:  int64(msg.ID),
		Body:       msg.Message,
		Meta:       messageMeta(senderUser, attachment),
	}
	return Extracted{Event: ev, SenderAccessHash: senderAccessHash(senderUser, hasSenderUser)}, true
}

// hiddenEdit reports an edit Telegram made without the sender editing
// anything: edit_hide marks updates the client must not show as "edited",
// and every position refresh of a live location arrives that way. Turning
// those into message_edit events would deny the conversation's pending
// drafts and queue a job on each refresh (#948 review).
func hiddenEdit(msg *tg.Message, media tg.MessageMediaClass) bool {
	if msg.EditHide {
		return true
	}
	_, live := media.(*tg.MessageMediaGeoLive)
	return live
}

func isSelfPeer(peer tg.PeerClass, selfTGID int64) bool {
	user, ok := peer.(*tg.PeerUser)
	return ok && user.UserID == selfTGID
}

// classifySavedCommand applies the shared owner-authored-command rules for a
// message already known to be in the primary Saved Messages dialog (PeerID
// == selfTGID). Deliberately does not look at msg.Out: Out is unreliable for
// this one peer on BOTH callers -- messages.getHistory against
// Peer: InputPeerSelf (the history poller, pollSavedHistory) was observed
// (live, 2026-07-26) setting Out == false on a message the same account had
// just sent to itself, and the live push path (ExtractMessage's
// UpdateNewMessage handling) was observed doing the exact same thing (live,
// 2026-08-01, mctl-telegram#354) -- including for this account's own
// SendMessage echo of its own draft notification moments earlier, not just
// another-session sends. Gating on dialog membership plus the
// forwarded/saved-peer/from-id checks below is correct either way: nothing
// but the owner can ever author a message that lands in their own primary
// Saved Messages dialog.
func classifySavedCommand(accountUserID, selfTGID int64, msg *tg.Message, text string, isEdit bool) (Extracted, bool) {
	// A command must be authored directly by the owner in their primary
	// Saved Messages dialog. Forwarded messages and messages surfaced
	// from another saved peer/topic are content, not control input.
	if _, forwarded := msg.GetFwdFrom(); forwarded {
		return Extracted{}, false
	}
	if savedPeer, set := msg.GetSavedPeerID(); set && !isSelfPeer(savedPeer, selfTGID) {
		return Extracted{}, false
	}
	if from, set := msg.GetFromID(); set && !isSelfPeer(from, selfTGID) {
		return Extracted{}, false
	}
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

// ExtractSavedHistoryMessage classifies one message fetched via
// messages.getHistory against Peer: InputPeerSelf (see pollSavedHistory).
// Every item the real API returns for that peer is, by construction, in the
// owner's own Saved Messages dialog, so this does not need msg.Out the way
// ExtractMessage does for a live update (see classifySavedCommand's doc
// comment for why that flag cannot be trusted here) -- but it still checks
// PeerID itself rather than trusting the caller, both as defense in depth
// and because callers other than the real production RPC (tests, a future
// caller with a different fetch) are not guaranteed the same invariant.
func ExtractSavedHistoryMessage(accountUserID, selfTGID int64, msg *tg.Message) (Extracted, bool) {
	if msg == nil {
		return Extracted{}, false
	}
	peerUser, ok := msg.PeerID.(*tg.PeerUser)
	if !ok || peerUser.UserID != selfTGID {
		return Extracted{}, false
	}
	return classifySavedCommand(accountUserID, selfTGID, msg, strings.TrimSpace(msg.Message), false)
}

// senderAccessHash extracts a usable access_hash from the sender's entity,
// or 0 if there is none. Matches internal/telegram/messages.go's
// seedPeerCache guard: a "min" user's access_hash
// (https://core.telegram.org/api/min) is valid only for limited contexts
// (e.g. profile photos), never for messages.* RPCs, which still return
// PEER_ID_INVALID for one — so a min user's hash is treated the same as no
// hash at all, rather than persisted and later trusted.
func senderAccessHash(u *tg.User, ok bool) int64 {
	if !ok || u == nil || u.Min {
		return 0
	}
	return u.AccessHash
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
	Username    string              `json:"username,omitempty"`
	DisplayName string              `json:"display_name,omitempty"`
	IsContact   bool                `json:"is_contact,omitempty"`
	IsBot       bool                `json:"is_bot,omitempty"`
	Attachment  *attachmentMetadata `json:"attachment,omitempty"`
}

// senderMeta builds strict JSON. strconv.Quote is intentionally not used:
// it may emit Go-only escapes such as \xNN that json.Unmarshal rejects.
func senderMeta(u *tg.User) string {
	return messageMeta(u, nil)
}

// messageMeta is senderMeta plus what the message carried besides its text
// (#948). The worker's get_event returns it verbatim, which is how the agent
// learns that a file arrived.
func messageMeta(u *tg.User, attachment *attachmentMetadata) string {
	m := senderMetadata{Attachment: attachment}
	if u != nil {
		m.Username = u.Username
		m.DisplayName = strings.TrimSpace(u.FirstName + " " + u.LastName)
		m.IsContact = u.Contact
		m.IsBot = u.Bot
	}
	if m == (senderMetadata{}) {
		return "{}"
	}
	b, err := json.Marshal(m)
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
