package listener

import (
	"context"
	"testing"
	"time"

	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// seedUnconfirmedSend leaves an agent reply executing with body reserved and
// no sent marker: the state a send whose RPC answer was lost is in (#1029).
func seedUnconfirmedSend(t *testing.T, store *db.Store, uid int64, body string) int64 {
	t.Helper()
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, recruit, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	id, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply,
		Payload: body, PolicyDecision: db.PolicyRequireApproval, Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatalf("insert action: %v", err)
	}
	action, err := store.GetAgentAction(ctx, uid, id)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if ok, err := store.ReserveAgentActionSend(ctx, *action, 919191, body, 0, 0, time.Time{}, false); err != nil || !ok {
		t.Fatalf("reserve: ok=%v err=%v", ok, err)
	}
	if _, ok, err := store.NoteAgentActionSendAttempt(ctx, uid, id); err != nil || !ok {
		t.Fatalf("note attempt: ok=%v err=%v", ok, err)
	}
	return id
}

func conversationState(t *testing.T, store *db.Store, uid int64) string {
	t.Helper()
	conv, err := store.GetConversationByPeer(context.Background(), uid, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	return conv.State
}

// TestOnMessage_EchoOfUnconfirmedAgentSendIsNotTakeover: the echo of an
// agent send whose result was lost carries no marker, but its text is the
// reserved send body, so it is the agent's message, not the owner's.
func TestOnMessage_EchoOfUnconfirmedAgentSendIsNotTakeover(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	id := seedUnconfirmedSend(t, store, acct.userID, "Thanks, Bob. - AI assistant")

	echo := &tg.Message{ID: 880, Out: true, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Thanks, Bob. - AI assistant"}
	if err := l.onMessage(ctx, acct, ents(), echo, false); err != nil {
		t.Fatalf("echo: %v", err)
	}
	if got := conversationState(t, store, acct.userID); got != db.ConversationActive {
		t.Fatalf("echo of an unconfirmed agent send changed state to %q", got)
	}
	action, err := store.GetAgentAction(ctx, acct.userID, id)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionExecuting {
		t.Fatalf("status = %q, want still executing (recovery completes it)", action.Status)
	}
	if action.ExecutedTGMessageID != 880 {
		t.Fatalf("noted id = %d, want 880", action.ExecutedTGMessageID)
	}
}

// TestOnMessage_EditedCopyOfUnconfirmedAgentSendIsTakeover keeps #993: an
// agent message delivered as new with an edit date was edited by the owner,
// so it is the owner's hand even when it starts from the agent's text.
func TestOnMessage_EditedCopyOfUnconfirmedAgentSendIsTakeover(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	seedUnconfirmedSend(t, store, acct.userID, "Thanks, Bob. - AI assistant")

	edited := &tg.Message{ID: 881, Out: true, PeerID: &tg.PeerUser{UserID: recruit},
		Message: "Thanks, Bob. - AI assistant", EditDate: int(time.Now().Unix())}
	if err := l.onMessage(ctx, acct, ents(), edited, false); err != nil {
		t.Fatalf("edited copy: %v", err)
	}
	if got := conversationState(t, store, acct.userID); got != db.ConversationTakenOver {
		t.Fatalf("owner-edited agent message left state at %q, want taken over", got)
	}
}

// TestOnMessage_OwnerTextBesideUnconfirmedSendIsTakeover: an unconfirmed
// send in the chat does not make every outgoing message the agent's.
func TestOnMessage_OwnerTextBesideUnconfirmedSendIsTakeover(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	seedUnconfirmedSend(t, store, acct.userID, "Thanks, Bob. - AI assistant")

	human := &tg.Message{ID: 882, Out: true, PeerID: &tg.PeerUser{UserID: recruit}, Message: "I'll take it from here"}
	if err := l.onMessage(ctx, acct, ents(), human, false); err != nil {
		t.Fatalf("owner message: %v", err)
	}
	if got := conversationState(t, store, acct.userID); got != db.ConversationTakenOver {
		t.Fatalf("owner message left state at %q, want taken over", got)
	}
}
