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

func claimAttemptForJob(t *testing.T, store *db.Store, userID, jobID int64) int {
	t.Helper()
	for tries := 0; tries < 50; tries++ {
		jobs, err := store.ClaimAgentJobs(context.Background(), "listener-test", userID, 50)
		if err != nil {
			t.Fatalf("claim jobs: %v", err)
		}
		if len(jobs) == 0 {
			t.Fatalf("job %d was not claimable", jobID)
		}
		for _, job := range jobs {
			if job.ID == jobID {
				return job.Attempts
			}
			// ClaimAgentJobs deliberately serializes one conversation. Finish
			// older jobs as ignored so a test that targets a later source
			// message models the real ordering rather than bypassing fencing.
			if err := store.CompleteAgentJob(context.Background(), job.ID, job.Attempts, db.JobIgnored, "test advanced to later message"); err != nil {
				t.Fatalf("finish earlier job %d: %v", job.ID, err)
			}
		}
	}
	t.Fatalf("job %d was not reached after advancing earlier jobs", jobID)
	return 0
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

func TestOnMessage_SenderAllowlistFiltersBeforePersistence(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	if !l.SetAccountProfile(acct.userID, acct.tgID, "999, 777") {
		t.Fatal("set account profile")
	}
	filtered, ok := l.get(acct.userID)
	if !ok {
		t.Fatal("listener account missing")
	}
	msg := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Hello"}
	entities := ents(&tg.User{ID: recruit, Username: "anna_hr", FirstName: "Anna"})

	if err := l.onMessage(ctx, filtered, entities, msg, false); err != nil {
		t.Fatalf("filtered onMessage: %v", err)
	}
	var events, jobs, conversations int
	for table, dest := range map[string]*int{
		"incoming_events": &events,
		"agent_jobs":      &jobs,
		"conversations":   &conversations,
	} {
		if err := store.DB.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(dest); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
	}
	if events != 0 || jobs != 0 || conversations != 0 {
		t.Fatalf("filtered sender persisted events/jobs/conversations = %d/%d/%d", events, jobs, conversations)
	}

	// Reconciliation refreshes the allowlist on the existing manager without
	// requiring a disconnect. The same peer becomes eligible immediately.
	if !l.SetAccountProfile(acct.userID, acct.tgID, "555") {
		t.Fatal("refresh account profile")
	}
	if err := l.onMessage(ctx, filtered, entities, msg, false); err != nil {
		t.Fatalf("allowed onMessage: %v", err)
	}
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM agent_jobs`).Scan(&jobs); err != nil {
		t.Fatalf("count allowed jobs: %v", err)
	}
	if jobs != 1 {
		t.Fatalf("allowed sender jobs = %d, want 1", jobs)
	}
}

func TestParseSenderAllowlist_EmptyAllowsAllAndInvalidFailsClosed(t *testing.T) {
	l := New(nil, nil, nil, nil)
	empty := &account{senderAllowlist: parseSenderAllowlist("  ")}
	if !l.senderAllowed(empty, 555) {
		t.Fatal("empty allowlist must preserve allow-all compatibility")
	}
	invalid := &account{senderAllowlist: parseSenderAllowlist("not-an-id,-1")}
	if l.senderAllowed(invalid, 555) {
		t.Fatal("configured but invalid allowlist must fail closed")
	}
}

// TestOnMessage_PersistsPeerAccessHash guards against the P1 found in
// round-4 review: without this, the executor's send path always built a
// zero-access-hash InputPeerUser and every reply failed with
// PEER_ID_INVALID. An incoming message's entity data is the only place this
// hash is ever available, so the listener must capture and persist it onto
// the conversation row.
func TestOnMessage_PersistsPeerAccessHash(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	msg := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Hello"}
	entities := ents(&tg.User{ID: recruit, Username: "anna_hr", FirstName: "Anna", AccessHash: 555111333})

	if err := l.onMessage(ctx, acct, entities, msg, false); err != nil {
		t.Fatalf("onMessage: %v", err)
	}

	conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if conv.PeerAccessHash != 555111333 {
		t.Fatalf("PeerAccessHash = %d, want 555111333", conv.PeerAccessHash)
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

// TestPersist_OwnerOutgoingDeniesPendingActions covers a Codex finding on
// #307: the automatically-detected takeover path (the owner just replying
// directly, with no /mctl command) set the conversation to taken_over but,
// unlike the explicit /mctl takeover command's handler, never denied
// pending actions — leaving a race where executor.send could read the
// conversation before this transition and still win its approved→executing
// CAS afterward, sending the agent's reply on top of the owner's own
// message. An approved action for the conversation must now be denied the
// same way the explicit command already does.
func TestPersist_OwnerOutgoingDeniesPendingActions(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	conv, err := store.EnsureConversation(ctx, acct.userID, recruit, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: acct.userID, ActionType: db.ActionTypeReply,
		Payload: "Sure, let's schedule a call.", PolicyDecision: db.PolicyAllow,
		Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatalf("seed approved action: %v", err)
	}

	ex := Extracted{Event: db.IncomingEvent{
		EventID: "evt:v1:100:555:100", UserID: acct.userID,
		Kind: db.EventKindOwnerOutgoing, ChatTGID: recruit,
		SenderTGID: acct.tgID, MessageID: 100, Body: "I'll handle this",
	}}
	if err := l.persist(ctx, acct, ex); err != nil {
		t.Fatalf("persist owner outgoing: %v", err)
	}

	action, err := store.GetAgentAction(ctx, acct.userID, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionDenied {
		t.Fatalf("status = %q, want denied (automatic takeover must deny pending actions like /mctl takeover does)", action.Status)
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
	var sourceJobID int64
	if err := store.DB.QueryRowContext(ctx,
		`SELECT id FROM agent_jobs WHERE event_id=$1`, eventIDForMessage(acct.tgID, recruit, 42, 0, original.Message),
	).Scan(&sourceJobID); err != nil {
		t.Fatalf("get source job: %v", err)
	}
	sourceAttempt := claimAttemptForJob(t, store, acct.userID, sourceJobID)
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		JobID: sourceJobID, Attempt: sourceAttempt,
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

func TestPersist_MessageEditKeepsDraftFromLaterMessage(t *testing.T) {
	ctx := context.Background()
	l, store, acct := newTestListener(t, nil)
	entities := ents(&tg.User{ID: recruit, Username: "anna_hr", FirstName: "Anna"})

	older := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Older text", Date: 1000}
	later := &tg.Message{ID: 43, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Current question", Date: 1001}
	if err := l.onMessage(ctx, acct, entities, older, false); err != nil {
		t.Fatalf("onMessage older: %v", err)
	}
	if err := l.onMessage(ctx, acct, entities, later, false); err != nil {
		t.Fatalf("onMessage later: %v", err)
	}
	conv, err := store.GetConversationByPeer(ctx, acct.userID, recruit)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	var laterJobID int64
	if err := store.DB.QueryRowContext(ctx,
		`SELECT id FROM agent_jobs WHERE event_id=$1`, eventIDForMessage(acct.tgID, recruit, 43, 0, later.Message),
	).Scan(&laterJobID); err != nil {
		t.Fatalf("get later source job: %v", err)
	}
	laterAttempt := claimAttemptForJob(t, store, acct.userID, laterJobID)
	laterActionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		JobID: laterJobID, Attempt: laterAttempt,
		ConversationID: conv.ID, UserID: acct.userID,
		ActionType: db.ActionTypeReply, Payload: "Answer to current question",
		PolicyDecision: db.PolicyRequireApproval, Status: db.ActionPendingApproval,
		ApprovalCode: "LATER1",
	})
	if err != nil {
		t.Fatalf("seed later action: %v", err)
	}

	editedOlder := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Edited older text", Date: 1000}
	editedOlder.SetEditDate(2000)
	if err := l.onMessage(ctx, acct, entities, editedOlder, true); err != nil {
		t.Fatalf("edit older message: %v", err)
	}

	action, err := store.GetAgentAction(ctx, acct.userID, laterActionID)
	if err != nil {
		t.Fatalf("get later action: %v", err)
	}
	if action.Status != db.ActionPendingApproval {
		t.Fatalf("later action status=%q, want pending_approval", action.Status)
	}
}

// TestPersist_RedeliveredEditDoesNotDenyTheFreshProposalItCreated guards
// against a Codex finding on #307: gotd delivers updates at least once, so
// the SAME edit can arrive again later (a reconnect/gap-recovery replay).
// Queue.Ingest already treats that redelivery as a no-op via its unique
// event_id constraint, but the deny call had no such dedup of its own — a
// redelivered edit would re-deny whatever fresh, correctly-edited proposal
// the FIRST delivery's job already produced, while the redelivered Ingest
// creates nothing to replace it. Simulated here by delivering the identical
// edited message twice, seeding a fresh proposal in between (standing in
// for what the first delivery's job would have produced).
func TestPersist_RedeliveredEditDoesNotDenyTheFreshProposalItCreated(t *testing.T) {
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

	edited := &tg.Message{ID: 42, PeerID: &tg.PeerUser{UserID: recruit}, Message: "Edited text", Date: 1000}
	edited.SetEditDate(2000)
	if err := l.onMessage(ctx, acct, entities, edited, true); err != nil {
		t.Fatalf("onMessage edit (first delivery): %v", err)
	}

	// Stands in for the fresh, correctly-edited proposal the edit's own job
	// would go on to produce.
	var editedJobID int64
	if err := store.DB.QueryRowContext(ctx,
		`SELECT id FROM agent_jobs WHERE event_id=$1`, eventIDForMessage(acct.tgID, recruit, 42, 2000, edited.Message),
	).Scan(&editedJobID); err != nil {
		t.Fatalf("get edited source job: %v", err)
	}
	editedAttempt := claimAttemptForJob(t, store, acct.userID, editedJobID)
	freshActionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		JobID: editedJobID, Attempt: editedAttempt,
		ConversationID: conv.ID, UserID: acct.userID, ActionType: db.ActionTypeReply,
		Payload: "Draft answering the EDITED text", PolicyDecision: db.PolicyRequireApproval,
		Status: db.ActionPendingApproval, ApprovalCode: "EDIT02",
	})
	if err != nil {
		t.Fatalf("seed fresh proposal: %v", err)
	}

	// Redelivery: the identical edited message, same ID/text/edit-date —
	// gotd would produce the exact same event_id for this.
	if err := l.onMessage(ctx, acct, entities, edited, true); err != nil {
		t.Fatalf("onMessage edit (redelivery): %v", err)
	}

	action, err := store.GetAgentAction(ctx, acct.userID, freshActionID)
	if err != nil {
		t.Fatalf("get fresh action: %v", err)
	}
	if action.Status != db.ActionPendingApproval {
		t.Fatalf("fresh proposal status = %q, want still pending_approval — a redelivered edit must not deny the response it already produced", action.Status)
	}

	var jobCount int
	if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM agent_jobs WHERE conversation_id=$1`, conv.ID).Scan(&jobCount); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if jobCount != 2 {
		t.Fatalf("job count = %d, want 2 (original + edit) — the redelivery must not enqueue a third job", jobCount)
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
	var sourceJobID int64
	if err := store.DB.QueryRowContext(ctx,
		`SELECT id FROM agent_jobs WHERE event_id=$1`, eventIDForMessage(acct.tgID, recruit, 42, 0, original.Message),
	).Scan(&sourceJobID); err != nil {
		t.Fatalf("get source job: %v", err)
	}
	sourceAttempt := claimAttemptForJob(t, store, acct.userID, sourceJobID)
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		JobID: sourceJobID, Attempt: sourceAttempt,
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
