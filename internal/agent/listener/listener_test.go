package listener

import (
	"context"
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

	l.onMessage(ctx, acct, entities, msg, false)
	l.onMessage(ctx, acct, entities, msg, false)

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

func TestPersist_IngestRollsBackEventWhenJobInsertFails(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	if _, err := store.DB.ExecContext(ctx, `
		CREATE TRIGGER fail_agent_job_insert
		BEFORE INSERT ON agent_jobs
		BEGIN
			SELECT RAISE(ABORT, 'forced job failure');
		END`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

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
}

type recordingRouter struct {
	calls int
	text  string
}

func (r *recordingRouter) HandleSavedText(_ context.Context, _ int64, text string) error {
	r.calls++
	r.text = text
	return nil
}

func TestPersist_SavedCommandRoutesOnceAndNilRouterIsSafe(t *testing.T) {
	ctx := context.Background()
	router := &recordingRouter{}
	l, _, acct := newTestListener(t, router)
	ex := Extracted{Event: db.IncomingEvent{
		EventID: "evt:v1:100:100:101", UserID: acct.userID,
		Kind: db.EventKindSavedCommand, ChatTGID: acct.tgID,
		SenderTGID: acct.tgID, MessageID: 101, Body: "/mctl status",
	}, SavedCommandText: "/mctl status"}
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
	nilEvent := ex
	nilEvent.Event.EventID = "evt:v1:100:100:102"
	nilEvent.Event.UserID = nilAcct.userID
	if err := nilListener.persist(ctx, nilAcct, nilEvent); err != nil {
		t.Fatalf("nil router: %v", err)
	}
}
