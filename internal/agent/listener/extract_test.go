package listener

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

const (
	selfTG   = int64(100)
	ownerUID = int64(7)
	recruit  = int64(555)
)

func ents(users ...*tg.User) tg.Entities {
	m := make(map[int64]*tg.User, len(users))
	for _, u := range users {
		m[u.ID] = u
	}
	return tg.Entities{Users: m}
}

func TestExtractMessage_IncomingPrivate(t *testing.T) {
	msg := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Здравствуйте"}
	got, ok := ExtractMessage(ownerUID, selfTG, msg, ents(&tg.User{ID: recruit, Username: "anna_hr", FirstName: "Anna"}), false)
	if !ok || got.Event.Kind != db.EventKindPrivateMessage || got.Event.EventID != "evt:v1:100:555:42" {
		t.Fatalf("event = %#v, ok=%v", got.Event, ok)
	}
	username, display := senderIdentityFromMeta(got.Event.Meta)
	if username != "anna_hr" || display != "Anna" {
		t.Fatalf("identity = %q/%q", username, display)
	}
}

func TestExtractMessage_EditGetsDistinctEventID(t *testing.T) {
	base := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "v1", Date: 1000}
	fresh, _ := ExtractMessage(ownerUID, selfTG, base, ents(), false)
	edited := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "v2", Date: 1000}
	edited.SetEditDate(2000)
	got, ok := ExtractMessage(ownerUID, selfTG, edited, ents(), true)
	if !ok || got.Event.Kind != db.EventKindMessageEdit || got.Event.EventID == fresh.Event.EventID {
		t.Fatalf("edit = %#v, ok=%v", got.Event, ok)
	}
	if !strings.HasPrefix(got.Event.EventID, "evt:v1:100:555:42:e2000:") {
		t.Fatalf("edit event id = %q", got.Event.EventID)
	}
}

func TestExtractMessage_TwoEditsInSameSecondStayDistinct(t *testing.T) {
	first := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "first edit", Date: 1000}
	first.SetEditDate(2000)
	second := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "second edit", Date: 1000}
	second.SetEditDate(2000)
	a, _ := ExtractMessage(ownerUID, selfTG, first, ents(), true)
	b, _ := ExtractMessage(ownerUID, selfTG, second, ents(), true)
	if a.Event.EventID == b.Event.EventID {
		t.Fatalf("same-second edits collided: %q", a.Event.EventID)
	}
	redelivery, _ := ExtractMessage(ownerUID, selfTG, first, ents(), true)
	if redelivery.Event.EventID != a.Event.EventID {
		t.Fatalf("same edit redelivery changed id: %q vs %q", redelivery.Event.EventID, a.Event.EventID)
	}
}

func TestExtractMessage_SavedCommandAndOwnerTakeover(t *testing.T) {
	saved := &tg.Message{ID: 9, Out: true, PeerID: &tg.PeerUser{UserID: selfTG}, Message: "/mctl status"}
	got, ok := ExtractMessage(ownerUID, selfTG, saved, ents(), false)
	if !ok || got.Event.Kind != db.EventKindSavedCommand || got.SavedCommandText != saved.Message {
		t.Fatalf("saved = %#v, ok=%v", got, ok)
	}
	upper := &tg.Message{ID: 10, Out: true, PeerID: &tg.PeerUser{UserID: selfTG}, Message: "  /MCTL pause  "}
	if got, ok := ExtractMessage(ownerUID, selfTG, upper, ents(), false); !ok || got.Event.Kind != db.EventKindSavedCommand {
		t.Fatalf("case-insensitive command = %#v, ok=%v", got, ok)
	}
	ordinary := &tg.Message{ID: 11, Out: true, PeerID: &tg.PeerUser{UserID: selfTG}, Message: "passport number and private note"}
	if _, ok := ExtractMessage(ownerUID, selfTG, ordinary, ents(), false); ok {
		t.Fatal("ordinary Saved Messages note must not be retained")
	}
	out := &tg.Message{ID: 12, Out: true, PeerID: &tg.PeerUser{UserID: recruit}, Message: "I'll take it"}
	got, ok = ExtractMessage(ownerUID, selfTG, out, ents(), false)
	if !ok || got.Event.Kind != db.EventKindOwnerOutgoing || got.SavedCommandText != "" {
		t.Fatalf("owner outgoing = %#v, ok=%v", got, ok)
	}
}

func TestExtractMessage_RejectsIndirectSavedCommands(t *testing.T) {
	forwarded := &tg.Message{
		ID: 20, Out: true, PeerID: &tg.PeerUser{UserID: selfTG},
		Message: "/mctl approve FORWARDED",
	}
	forwarded.SetFwdFrom(tg.MessageFwdHeader{Date: 1})

	otherSavedPeer := &tg.Message{
		ID: 21, Out: true, PeerID: &tg.PeerUser{UserID: selfTG},
		Message: "/mctl approve OTHERPEER",
	}
	otherSavedPeer.SetSavedPeerID(&tg.PeerUser{UserID: recruit})

	otherAuthor := &tg.Message{
		ID: 22, Out: true, PeerID: &tg.PeerUser{UserID: selfTG},
		Message: "/mctl approve OTHERAUTHOR",
	}
	otherAuthor.SetFromID(&tg.PeerUser{UserID: recruit})

	for _, msg := range []*tg.Message{forwarded, otherSavedPeer, otherAuthor} {
		if _, ok := ExtractMessage(ownerUID, selfTG, msg, ents(), false); ok {
			t.Fatalf("indirect Saved Messages command accepted: id=%d", msg.ID)
		}
	}

	directWithSavedPeer := &tg.Message{
		ID: 23, Out: true, PeerID: &tg.PeerUser{UserID: selfTG},
		Message: "/mctl status",
	}
	directWithSavedPeer.SetSavedPeerID(&tg.PeerUser{UserID: selfTG})
	directWithSavedPeer.SetFromID(&tg.PeerUser{UserID: selfTG})
	if _, ok := ExtractMessage(ownerUID, selfTG, directWithSavedPeer, ents(), false); !ok {
		t.Fatal("direct owner-authored command with self saved_peer_id was rejected")
	}
}

func TestExtractMessage_MediaOnlyOwnerMessageIsTakeover(t *testing.T) {
	out := &tg.Message{ID: 13, Out: true, PeerID: &tg.PeerUser{UserID: recruit}, Message: ""}
	got, ok := ExtractMessage(ownerUID, selfTG, out, ents(), false)
	if !ok || got.Event.Kind != db.EventKindOwnerOutgoing || got.Event.Body != "" {
		t.Fatalf("media-only takeover = %#v, ok=%v", got, ok)
	}
	self := &tg.Message{ID: 14, Out: true, PeerID: &tg.PeerUser{UserID: selfTG}, Message: ""}
	if _, ok := ExtractMessage(ownerUID, selfTG, self, ents(), false); ok {
		t.Fatal("blank Saved Messages item should not become a command")
	}
}

func TestExtractMessage_SkipsUnsupportedMessages(t *testing.T) {
	cases := []*tg.Message{
		{ID: 1, PeerID: &tg.PeerUser{UserID: recruit}},
		{ID: 1, PeerID: &tg.PeerUser{UserID: recruit}, Message: "   "},
		{ID: 1, PeerID: &tg.PeerChat{ChatID: 9}, Message: "hi"},
		{ID: 1, PeerID: &tg.PeerChannel{ChannelID: 9}, Message: "hi"},
		{ID: 1, Out: true, PeerID: &tg.PeerChat{ChatID: 9}, Message: "hi"},
	}
	for _, msg := range cases {
		if _, ok := ExtractMessage(ownerUID, selfTG, msg, ents(), false); ok {
			t.Fatalf("message should be skipped: %#v", msg)
		}
	}
	bot := &tg.Message{ID: 1, PeerID: &tg.PeerUser{UserID: recruit}, Message: "hi"}
	if _, ok := ExtractMessage(ownerUID, selfTG, bot, ents(&tg.User{ID: recruit, Bot: true}), false); ok {
		t.Fatal("bot message should be skipped")
	}
}

// TestExtractMessage_CapturesSenderAccessHash guards against the P1 found
// in round-4 review: the executor's send path needs a real access_hash to
// build a working InputPeerUser, and the only place that hash is ever
// available is the entity data on the peer's own incoming messages.
func TestExtractMessage_CapturesSenderAccessHash(t *testing.T) {
	msg := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "hi"}
	got, ok := ExtractMessage(ownerUID, selfTG, msg, ents(&tg.User{ID: recruit, AccessHash: 123456789}), false)
	if !ok {
		t.Fatal("expected ok")
	}
	if got.SenderAccessHash != 123456789 {
		t.Fatalf("SenderAccessHash = %d, want 123456789", got.SenderAccessHash)
	}
}

// TestExtractMessage_MinUserAccessHashIsIgnored guards against trusting a
// Telegram "min" user's access_hash — valid only for limited contexts (e.g.
// profile photos), not for messages.* RPCs, which would still return
// PEER_ID_INVALID for one. Persisting it would look like a fix while
// silently reintroducing the same failure.
func TestExtractMessage_MinUserAccessHashIsIgnored(t *testing.T) {
	u := &tg.User{ID: recruit, AccessHash: 123456789}
	u.SetMin(true)
	msg := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "hi"}
	got, ok := ExtractMessage(ownerUID, selfTG, msg, ents(u), false)
	if !ok {
		t.Fatal("expected ok")
	}
	if got.SenderAccessHash != 0 {
		t.Fatalf("SenderAccessHash = %d, want 0 (min user hash must be ignored)", got.SenderAccessHash)
	}
}

func TestExtractMessage_SenderFromFromID(t *testing.T) {
	msg := &tg.Message{ID: 5, PeerID: &tg.PeerUser{UserID: recruit}, FromID: &tg.PeerUser{UserID: 999}, Message: "hi"}
	got, ok := ExtractMessage(ownerUID, selfTG, msg, ents(), false)
	if !ok || got.Event.SenderTGID != 999 || got.Event.ChatTGID != recruit {
		t.Fatalf("sender/chat = %d/%d, ok=%v", got.Event.SenderTGID, got.Event.ChatTGID, ok)
	}
}

func TestSenderMeta_IsStrictJSON(t *testing.T) {
	meta := senderMeta(&tg.User{ID: 1, Username: "ann\a", FirstName: "A\v", LastName: "B", Contact: true})
	var decoded senderMetadata
	if err := json.Unmarshal([]byte(meta), &decoded); err != nil {
		t.Fatalf("invalid JSON %q: %v", meta, err)
	}
	if decoded.Username != "ann\a" || decoded.DisplayName != "A\v B" || !decoded.IsContact {
		t.Fatalf("decoded = %#v", decoded)
	}
}

func TestSenderIdentityFromMeta_MalformedIsSafe(t *testing.T) {
	username, display := senderIdentityFromMeta(`{"username":`)
	if username != "" || display != "" {
		t.Fatalf("malformed meta returned %q/%q", username, display)
	}
}
