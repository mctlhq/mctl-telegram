package listener

import (
	"encoding/json"
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
	if !ok || got.Event.Kind != db.EventKindMessageEdit || got.Event.EventID == fresh.Event.EventID || got.Event.EventID != "evt:v1:100:555:42:e2000" {
		t.Fatalf("edit = %#v, ok=%v", got.Event, ok)
	}
}

func TestExtractMessage_SavedCommandAndOwnerTakeover(t *testing.T) {
	saved := &tg.Message{ID: 9, Out: true, PeerID: &tg.PeerUser{UserID: selfTG}, Message: "/mctl status"}
	got, ok := ExtractMessage(ownerUID, selfTG, saved, ents(), false)
	if !ok || got.Event.Kind != db.EventKindSavedCommand || got.SavedCommandText != saved.Message {
		t.Fatalf("saved = %#v, ok=%v", got, ok)
	}
	out := &tg.Message{ID: 11, Out: true, PeerID: &tg.PeerUser{UserID: recruit}, Message: "I'll take it"}
	got, ok = ExtractMessage(ownerUID, selfTG, out, ents(), false)
	if !ok || got.Event.Kind != db.EventKindOwnerOutgoing || got.SavedCommandText != "" {
		t.Fatalf("owner outgoing = %#v, ok=%v", got, ok)
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
