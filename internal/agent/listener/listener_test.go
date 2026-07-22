package listener

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/gotd/td/tg"

	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	cryptopkg "github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func newListenerTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, fmt.Sprintf("file:listener_%d?mode=memory&cache=shared", time.Now().UnixNano()), 0, 0)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate db: %v", err)
	}
	crypt, err := cryptopkg.New(nil)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	return db.NewStore(conn, crypt)
}

func newTestListener(t *testing.T, router CommandRouter) (*Listener, *db.Store, *account) {
	t.Helper()
	store := newListenerTestStore(t)
	uid, err := store.EnsureUser(context.Background(), "listener-owner", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	return New(store, queue.New(store, "listener-test", nil), router, nil), store, &account{userID: uid, tgID: selfTG}
}

func TestOnMessage_PersistsEventJobAndConversationIdentity(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	msg := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Hello"}
	entities := ents(&tg.User{ID: recruit, Username: "anna_hr", FirstName: "Anna", LastName: "Recruiter"})

	if err := l.onMessage(ctx, acct, entities, msg, false); err != nil {
		t.Fatalf("onMessage: %v", err)
	}
	if err := l.onMessage(ctx, acct, entities, msg, false); err != nil {
		t.Fatalf("duplicate onMessage: %v", err)
	}

	var events, jobs int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM incoming_events WHERE event_id=$1`, "evt:v1:100:555:42").Scan(&events); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM agent_jobs WHERE event_id=$1`, "evt:v1:100:555:42").Scan(&jobs); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if events != 1 || jobs != 1 {
		t.Fatalf("events/jobs = %d/%d, want 1/1", events, jobs)
	}

	var username, display string
	var lastIncoming any
	if err := store.DB.QueryRowContext(ctx,
		`SELECT peer_username, peer_display_name, last_incoming_at FROM conversations WHERE user_id=$1 AND peer_tg_id=$2`,
		acct.userID, recruit,
	).Scan(&username, &display, &lastIncoming); err != nil {
		t.Fatalf("conversation: %v", err)
	}
	if username != "anna_hr" || display != "Anna Recruiter" || lastIncoming == nil {
		t.Fatalf("identity/touch = %q/%q/%v", username, display, lastIncoming)
	}
}

func installFailingJobTrigger(t *testing.T, store *db.Store) {
	t.Helper()
	if _, err := store.DB.ExecContext(context.Background(), `
		CREATE TRIGGER fail_agent_job_insert
		BEFORE INSERT ON agent_jobs
		BEGIN
			SELECT RAISE(ABORT, 'forced job failure');
		END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
}

func TestPersist_IngestRollsBackEventWhenJobInsertFails(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	installFailingJobTrigger(t, store)

	ex := Extracted{Event: db.IncomingEvent{
		EventID: "evt:v1:100:555:99", UserID: acct.userID,
		Kind: db.EventKindPrivateMessage, ChatTGID: recruit,
		SenderTGID: recruit, MessageID: 99, Body: "atomic please",
		Meta: `{"username":"anna_hr","display_name":"Anna"}`,
	}}
	if err := l.persist(ctx, acct, ex); err == nil {
		t.Fatal("persist succeeded despite forced job failure")
	}
	var events, jobs int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM incoming_events WHERE event_id=$1`, ex.Event.EventID).Scan(&events); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM agent_jobs WHERE event_id=$1`, ex.Event.EventID).Scan(&jobs); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if events != 0 || jobs != 0 {
		t.Fatalf("partial ingestion left events/jobs = %d/%d", events, jobs)
	}
}

func TestOnMessage_PropagatesPersistenceFailure(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	installFailingJobTrigger(t, store)
	msg := &tg.Message{ID: 77, PeerID: &tg.PeerUser{UserID: recruit}, Message: "retry me"}
	if err := l.onMessage(ctx, acct, ents(), msg, false); err == nil {
		t.Fatal("onMessage swallowed persistence failure")
	}
}

func TestPersist_OwnerOutgoingTakesOverConversation(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	if _, err := store.EnsureConversation(ctx, acct.userID, recruit, "anna_hr", "Anna"); err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	ex := Extracted{Event: db.IncomingEvent{
		EventID: "evt:v1:100:555:100", UserID: acct.userID,
		Kind: db.EventKindOwnerOutgoing, ChatTGID: recruit,
		SenderTGID: acct.tgID, MessageID: 100, Body: "I'll handle this",
	}}
	if err := l.persist(ctx, acct, ex); err != nil {
		t.Fatalf("persist owner outgoing: %v", err)
	}
	conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if conv.State != db.ConversationTakenOver {
		t.Fatalf("state = %q", conv.State)
	}
	if err := l.persist(ctx, acct, ex); err != nil {
		t.Fatalf("duplicate owner event: %v", err)
	}
}

type recordingRouter struct {
	calls int
	text  string
	err   error
}

func (r *recordingRouter) HandleSavedText(_ context.Context, _ int64, text string) error {
	r.calls++
	r.text = text
	return r.err
}

func savedCommand(acct *account, eventID string) Extracted {
	return Extracted{Event: db.IncomingEvent{
		EventID: eventID, UserID: acct.userID,
		Kind: db.EventKindSavedCommand, ChatTGID: acct.tgID,
		SenderTGID: acct.tgID, MessageID: 101, Body: "/mctl status",
	}, SavedCommandText: "/mctl status"}
}

func TestPersist_SavedCommandRoutesOnceAndNilRouterIsSafe(t *testing.T) {
	ctx := context.Background()
	router := &recordingRouter{}
	l, _, acct := newTestListener(t, router)
	ex := savedCommand(acct, "evt:v1:100:100:101")
	if err := l.persist(ctx, acct, ex); err != nil {
		t.Fatalf("persist saved command: %v", err)
	}
	if err := l.persist(ctx, acct, ex); err != nil {
		t.Fatalf("persist duplicate: %v", err)
	}
	if router.calls != 1 || router.text != "/mctl status" {
		t.Fatalf("router calls/text = %d/%q", router.calls, router.text)
	}

	nilListener, _, nilAcct := newTestListener(t, nil)
	if err := nilListener.persist(ctx, nilAcct, savedCommand(nilAcct, "evt:v1:100:100:102")); err != nil {
		t.Fatalf("nil router: %v", err)
	}
}

func TestPersist_SavedCommandRouterFailureIsRetriedWithoutAuditDedup(t *testing.T) {
	ctx := context.Background()
	router := &recordingRouter{err: errors.New("control plane unavailable")}
	l, store, acct := newTestListener(t, router)
	ex := savedCommand(acct, "evt:v1:100:100:103")

	if err := l.persist(ctx, acct, ex); err == nil {
		t.Fatal("router failure was swallowed")
	}
	var events int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM incoming_events WHERE event_id=$1`, ex.Event.EventID).Scan(&events); err != nil {
		t.Fatalf("count failed command events: %v", err)
	}
	if events != 0 {
		t.Fatalf("failed command was audit-deduped before routing: events=%d", events)
	}

	router.err = nil
	if err := l.persist(ctx, acct, ex); err != nil {
		t.Fatalf("retry command: %v", err)
	}
	if err := l.persist(ctx, acct, ex); err != nil {
		t.Fatalf("duplicate command: %v", err)
	}
	if router.calls != 2 {
		t.Fatalf("router calls = %d, want failure + one retry", router.calls)
	}
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM incoming_events WHERE event_id=$1`, ex.Event.EventID).Scan(&events); err != nil {
		t.Fatalf("count successful command events: %v", err)
	}
	if events != 1 {
		t.Fatalf("successful command audit rows = %d, want 1", events)
	}
}

// TestPersist_MessageEditDeniesPendingAction is A-PR7's crash-recovery
// spec's "edit invalidates the draft" requirement: a pending_approval (or
// proposed/approved) action for a conversation must be denied when the
// sender edits the message the draft was built from, so a stale draft
// answering pre-edit text can never go out unchanged.
func TestPersist_MessageEditDeniesPendingAction(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)

	original := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Original text", Date: 1000}
	entities := ents(&tg.User{ID: recruit, Username: "anna_hr", FirstName: "Anna", LastName: "Recruiter"})
	if err := l.onMessage(ctx, acct, entities, original, false); err != nil {
		t.Fatalf("onMessage original: %v", err)
	}

	conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: acct.userID, ActionType: db.ActionTypeReply,
		Payload: "Draft answering the original text", PolicyDecision: db.PolicyRequireApproval,
		Status: db.ActionPendingApproval, ApprovalCode: "EDIT01",
	})
	if err != nil {
		t.Fatalf("seed pending action: %v", err)
	}

	edited := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Edited text", Date: 1000}
	edited.SetEditDate(2000)
	if err := l.onMessage(ctx, acct, entities, edited, true); err != nil {
		t.Fatalf("onMessage edit: %v", err)
	}

	action, err := store.GetAgentAction(ctx, acct.userID, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionDenied {
		t.Fatalf("action status = %q, want denied after the source message was edited", action.Status)
	}

	// The edit itself still enqueues its own job under a distinct event id,
	// so a fresh proposal can be produced from the current text.
	var jobCount int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM agent_jobs WHERE conversation_id=$1`, conv.ID).Scan(&jobCount); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if jobCount != 2 {
		t.Fatalf("job count = %d, want 2 (original + edit)", jobCount)
	}
}

// TestPersist_MessageEditLeavesExecutingActionAlone confirms an action
// already `executing` (a send may be in flight) is NOT denied by an edit
// racing it — DenyPendingActionsForConversation deliberately excludes that
// status, see its doc comment.
func TestPersist_MessageEditLeavesExecutingActionAlone(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)

	original := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Original text", Date: 1000}
	entities := ents(&tg.User{ID: recruit, Username: "anna_hr", FirstName: "Anna", LastName: "Recruiter"})
	if err := l.onMessage(ctx, acct, entities, original, false); err != nil {
		t.Fatalf("onMessage original: %v", err)
	}
	conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: acct.userID, ActionType: db.ActionTypeReply,
		Payload: "Draft mid-send", PolicyDecision: db.PolicyAllow, Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatalf("seed action: %v", err)
	}
	if ok, err := store.BeginExecutingAgentAction(ctx, acct.userID, actionID, 999); err != nil || !ok {
		t.Fatalf("begin executing: ok=%v err=%v", ok, err)
	}

	edited := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Edited text", Date: 1000}
	edited.SetEditDate(2000)
	if err := l.onMessage(ctx, acct, entities, edited, true); err != nil {
		t.Fatalf("onMessage edit: %v", err)
	}

	action, err := store.GetAgentAction(ctx, acct.userID, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionExecuting {
		t.Fatalf("action status = %q, want still executing (in-flight sends are not recalled)", action.Status)
	}
}
