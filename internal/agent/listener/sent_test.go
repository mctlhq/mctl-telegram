package listener

import (
	"context"
	"testing"

	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func TestOnMessage_ProgrammaticSendEchoDoesNotTriggerTakeover(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	if _, err := store.EnsureConversation(ctx, acct.userID, recruit, "anna_hr", "Anna"); err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}

	l.MarkSent(acct.userID, 777)
	echo := &tg.Message{
		ID:      777,
		Out:     true,
		PeerID:  &tg.PeerUser{UserID: recruit},
		Message: "agent-generated reply",
	}
	if err := l.onMessage(ctx, acct, ents(), echo, false); err != nil {
		t.Fatalf("programmatic echo: %v", err)
	}

	conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if conv.State != db.ConversationActive {
		t.Fatalf("programmatic echo changed state to %q", conv.State)
	}
	var events int
	if err := store.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM incoming_events WHERE user_id=$1 AND message_id=$2`,
		acct.userID, 777,
	).Scan(&events); err != nil {
		t.Fatalf("count echo events: %v", err)
	}
	if events != 0 {
		t.Fatalf("programmatic echo persisted %d event(s)", events)
	}
}

func TestOnMessage_ProgrammaticSendMarkerSurvivesListenerRestart(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	if _, err := store.EnsureConversation(ctx, acct.userID, recruit, "anna_hr", "Anna"); err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}

	l.MarkSent(acct.userID, 779)
	restarted := New(store, l.Queue, nil, nil)
	echo := &tg.Message{
		ID:      779,
		Out:     true,
		PeerID:  &tg.PeerUser{UserID: recruit},
		Message: "agent-generated reply after restart",
	}
	if err := restarted.onMessage(ctx, acct, ents(), echo, false); err != nil {
		t.Fatalf("programmatic echo after restart: %v", err)
	}

	conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if conv.State != db.ConversationActive {
		t.Fatalf("programmatic echo after restart changed state to %q", conv.State)
	}
}

func TestOnMessage_UnmarkedOwnerOutgoingStillTriggersTakeover(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	if _, err := store.EnsureConversation(ctx, acct.userID, recruit, "anna_hr", "Anna"); err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}

	human := &tg.Message{
		ID:      778,
		Out:     true,
		PeerID:  &tg.PeerUser{UserID: recruit},
		Message: "I'll handle this personally",
	}
	if err := l.onMessage(ctx, acct, ents(), human, false); err != nil {
		t.Fatalf("human outgoing: %v", err)
	}

	conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if conv.State != db.ConversationTakenOver {
		t.Fatalf("human outgoing left state at %q", conv.State)
	}
}

// #993: a send through the listener's own session gets no echo, so its marker
// is still live when the owner edits that agent reply by hand. The edit is an
// owner intervention and must take the conversation over.
func TestOnMessage_OwnerEditOfAgentSendTriggersTakeover(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	if _, err := store.EnsureConversation(ctx, acct.userID, recruit, "carol_hr", "Carol"); err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}

	l.MarkSent(acct.userID, 780)
	edit := &tg.Message{
		ID:       780,
		Out:      true,
		PeerID:   &tg.PeerUser{UserID: recruit},
		Message:  "agent reply, corrected by the owner",
		EditDate: 1_700_000_000,
	}
	if err := l.onMessage(ctx, acct, ents(), edit, true); err != nil {
		t.Fatalf("owner edit: %v", err)
	}

	conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if conv.State != db.ConversationTakenOver {
		t.Fatalf("owner edit of an agent send left state at %q", conv.State)
	}
}

// A hidden edit Telegram makes itself on an agent reply (edit_hide, e.g. a
// link preview filling in) is not an owner intervention and must not take
// the conversation over.
func TestOnMessage_HiddenEditOfAgentSendDoesNotTakeOver(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	if _, err := store.EnsureConversation(ctx, acct.userID, recruit, "carol_hr", "Carol"); err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}

	l.MarkSent(acct.userID, 781)
	hidden := &tg.Message{
		ID:       781,
		Out:      true,
		EditHide: true,
		PeerID:   &tg.PeerUser{UserID: recruit},
		Message:  "agent reply with a link preview",
		Date:     1_700_000_000,
	}
	if err := l.onMessage(ctx, acct, ents(), hidden, true); err != nil {
		t.Fatalf("hidden edit: %v", err)
	}

	conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if conv.State != db.ConversationActive {
		t.Fatalf("hidden edit of an agent send changed state to %q", conv.State)
	}
}

// #993, as seen live: with no echo of the send, the owner's edit reached the
// listener through gap recovery as the agent's message itself, delivered as
// new (isEdit false) with an edit date and no separate edit update. The
// marker must not swallow it.
func TestOnMessage_EditedAgentSendDeliveredAsNewTriggersTakeover(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	if _, err := store.EnsureConversation(ctx, acct.userID, recruit, "carol_hr", "Carol"); err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}

	l.MarkSent(acct.userID, 782)
	recovered := &tg.Message{
		ID:       782,
		Out:      true,
		PeerID:   &tg.PeerUser{UserID: recruit},
		Message:  "agent reply, corrected by the owner",
		Date:     1_700_000_000,
		EditDate: 1_700_000_060,
	}
	if err := l.onMessage(ctx, acct, ents(), recovered, false); err != nil {
		t.Fatalf("recovered edit: %v", err)
	}

	conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if conv.State != db.ConversationTakenOver {
		t.Fatalf("edited agent send delivered as new left state at %q", conv.State)
	}
}

// The same delivery with edit_hide is Telegram's own change (a link preview
// filling in) and is still swallowed as the send echo.
func TestOnMessage_HiddenEditedAgentSendDeliveredAsNewIsEcho(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	if _, err := store.EnsureConversation(ctx, acct.userID, recruit, "carol_hr", "Carol"); err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}

	l.MarkSent(acct.userID, 783)
	recovered := &tg.Message{
		ID:       783,
		Out:      true,
		EditHide: true,
		PeerID:   &tg.PeerUser{UserID: recruit},
		Message:  "agent reply with a link preview",
		Date:     1_700_000_000,
		EditDate: 1_700_000_060,
	}
	if err := l.onMessage(ctx, acct, ents(), recovered, false); err != nil {
		t.Fatalf("hidden recovered edit: %v", err)
	}

	conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if conv.State != db.ConversationActive {
		t.Fatalf("hidden edit delivered as new changed state to %q", conv.State)
	}
}
