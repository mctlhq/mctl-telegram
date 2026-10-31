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
