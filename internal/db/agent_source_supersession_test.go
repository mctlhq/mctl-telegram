package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// supersessionFixture is one owner with a conversation with Alice (555), on
// either dialect.
type supersessionFixture struct {
	s      *Store
	uid    int64
	convID int64
}

const aliceChat int64 = 555

func newSupersessionFixture(t *testing.T, s *Store, uid int64) *supersessionFixture {
	t.Helper()
	conv, err := s.EnsureConversation(context.Background(), uid, aliceChat, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	return &supersessionFixture{s: s, uid: uid, convID: conv.ID}
}

func (f *supersessionFixture) eventID(msg int64, suffix string) string {
	return fmt.Sprintf("evt:v1:1:%d:%d%s", aliceChat, msg, suffix)
}

// ingest records an incoming DM (or an edit of one when suffix is non-empty)
// and its pending job, the way the listener does.
func (f *supersessionFixture) ingest(t *testing.T, msg int64, suffix string) string {
	t.Helper()
	kind := EventKindPrivateMessage
	if suffix != "" {
		kind = EventKindMessageEdit
	}
	id := f.eventID(msg, suffix)
	if _, ok, err := f.s.InsertEventEnqueueJobAndTouch(context.Background(), IncomingEvent{
		EventID: id, UserID: f.uid, Kind: kind, ChatTGID: aliceChat, SenderTGID: aliceChat,
		MessageID: msg, Body: "Hello from Alice",
	}, f.convID); err != nil || !ok {
		t.Fatalf("ingest %s: ok=%v err=%v", id, ok, err)
	}
	return id
}

// claim claims the oldest pending job of the conversation.
func (f *supersessionFixture) claim(t *testing.T) AgentJob {
	t.Helper()
	jobs, err := f.s.ClaimAgentJobs(context.Background(), "r", f.uid, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: %d jobs, err=%v", len(jobs), err)
	}
	return jobs[0]
}

func (f *supersessionFixture) jobID(t *testing.T, eventID string) int64 {
	t.Helper()
	var id int64
	if err := f.s.DB.QueryRow(`SELECT id FROM agent_jobs WHERE event_id = $1`, eventID).Scan(&id); err != nil {
		t.Fatalf("job for %s: %v", eventID, err)
	}
	return id
}

// coalesce attaches the member job to head the way ClaimAgentJobs does when
// turn coalescing folds a burst into one turn.
func (f *supersessionFixture) coalesce(t *testing.T, head, member int64) {
	t.Helper()
	if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET status = $1, coalesced_into = $2 WHERE id = $3`,
		JobCoalesced, head, member); err != nil {
		t.Fatalf("coalesce: %v", err)
	}
}

func (f *supersessionFixture) action(t *testing.T, job AgentJob, decision, status string) AgentAction {
	t.Helper()
	a := AgentAction{
		JobID: job.ID, Attempt: job.Attempts, ConversationID: f.convID, UserID: f.uid,
		ActionType: ActionTypeReply, Payload: "Thanks, Alice!", PolicyDecision: decision, Status: status,
	}
	if status == ActionPendingApproval {
		a.ApprovalCode = fmt.Sprintf("C%d", time.Now().UnixNano()%1_000_000)
	}
	id, err := f.s.InsertAgentAction(context.Background(), a)
	if err != nil {
		t.Fatalf("insert action: %v", err)
	}
	a.ID = id
	return a
}

func (f *supersessionFixture) actionRow(t *testing.T, id int64) (status, reasons string) {
	t.Helper()
	if err := f.s.DB.QueryRow(`SELECT status, policy_reasons FROM agent_actions WHERE id = $1`, id).Scan(&status, &reasons); err != nil {
		t.Fatalf("action %d: %v", id, err)
	}
	return status, reasons
}

func (f *supersessionFixture) superseded(t *testing.T, jobID int64) string {
	t.Helper()
	kind, err := f.s.JobSourceSuperseded(context.Background(), f.uid, jobID)
	if err != nil {
		t.Fatalf("JobSourceSuperseded: %v", err)
	}
	return kind
}

func (f *supersessionFixture) reserve(action AgentAction) (bool, error) {
	return f.s.ReserveAgentActionSend(context.Background(), action, action.ID+7000, "Thanks, Alice!",
		50, 10, time.Now().UTC().Add(-time.Minute), action.PolicyDecision == PolicyAllow)
}

func (f *supersessionFixture) recordDelete(t *testing.T, msg int64) MessageDeleteResult {
	t.Helper()
	res, err := f.s.RecordMessageDelete(context.Background(), f.uid, 1, msg)
	if err != nil {
		t.Fatalf("RecordMessageDelete(%d): %v", msg, err)
	}
	return res
}

// supersessionCases runs every case against a fresh store and owner from
// setup.
func supersessionCases(t *testing.T, setup func(t *testing.T) (*Store, int64)) {
	cases := []struct {
		name string
		run  func(t *testing.T, f *supersessionFixture)
	}{
		{"edit before propose supersedes the job", assertEditBeforePropose},
		{"delete outranks edit and the edit job stays current", assertDeleteOutranksEdit},
		{"edit between propose and send fails the reservation", assertEditBeforeReserve},
		{"delete fails the reservation of an owner-approved draft", assertDeleteBeforeReserveApproved},
		{"delete after reservation leaves the send alone", assertDeleteAfterReserve},
		{"edited coalesced member denies the head's draft", assertCoalescedMemberEdit},
		{"deleted coalesced member supersedes and denies the head", assertCoalescedMemberDelete},
		{"redelivered delete is a no-op", assertRedeliveredDelete},
		{"pending job for a deleted message is ignored", assertPendingJobIgnored},
		{"delete of an unknown message is a no-op", assertUnknownDelete},
		{"job-less action is never superseded", assertJoblessNotSuperseded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, uid := setup(t)
			tc.run(t, newSupersessionFixture(t, s, uid))
		})
	}
}

func TestSourceSupersession_SQLite(t *testing.T) {
	supersessionCases(t, func(t *testing.T) (*Store, int64) {
		s := newTestStoreCrypted(t)
		return s, seedAgentUser(t, s, "owner")
	})
}

func TestSourceSupersession_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	supersessionCases(t, func(t *testing.T) (*Store, int64) {
		uid := seedAgentUser(t, s, fmt.Sprintf("sup_%d", time.Now().UnixNano()))
		t.Cleanup(func() {
			for _, q := range []string{
				`DELETE FROM agent_actions WHERE user_id = $1`,
				`DELETE FROM agent_job_attempts WHERE job_id IN (SELECT id FROM agent_jobs WHERE user_id = $1)`,
				`DELETE FROM agent_jobs WHERE user_id = $1`,
				`DELETE FROM incoming_events WHERE user_id = $1`,
				`DELETE FROM conversations WHERE user_id = $1`,
				`DELETE FROM users WHERE id = $1`,
			} {
				_, _ = s.DB.Exec(q, uid)
			}
		})
		return s, uid
	})
}

func assertEditBeforePropose(t *testing.T, f *supersessionFixture) {
	f.ingest(t, 10, "")
	job := f.claim(t)
	if got := f.superseded(t, job.ID); got != "" {
		t.Fatalf("fresh job superseded: %q", got)
	}
	f.ingest(t, 10, ":e100:aa")
	if got := f.superseded(t, job.ID); got != SourceEdited {
		t.Fatalf("after edit: %q, want %q", got, SourceEdited)
	}
}

func assertDeleteOutranksEdit(t *testing.T, f *supersessionFixture) {
	f.ingest(t, 10, "")
	job := f.claim(t)
	editEvent := f.ingest(t, 10, ":e100:aa")
	editJob := f.jobID(t, editEvent)
	if got := f.superseded(t, editJob); got != "" {
		t.Fatalf("edit job superseded by its own event: %q", got)
	}
	f.recordDelete(t, 10)
	if got := f.superseded(t, job.ID); got != SourceDeleted {
		t.Fatalf("original job: %q, want %q", got, SourceDeleted)
	}
	if got := f.superseded(t, editJob); got != SourceDeleted {
		t.Fatalf("edit job after delete: %q, want %q", got, SourceDeleted)
	}
}

func assertEditBeforeReserve(t *testing.T, f *supersessionFixture) {
	f.ingest(t, 10, "")
	job := f.claim(t)
	a := f.action(t, job, PolicyAllow, ActionApproved)
	f.ingest(t, 10, ":e100:aa")
	ok, err := f.reserve(a)
	var se *SourceSupersededError
	if ok || !errors.As(err, &se) || se.Kind != SourceEdited || !errors.Is(err, ErrAgentSourceSuperseded) {
		t.Fatalf("reserve: ok=%v err=%v, want SourceSupersededError(edited)", ok, err)
	}
	if st, _ := f.actionRow(t, a.ID); st != ActionApproved {
		t.Fatalf("failed reservation moved the action to %s", st)
	}
	var turns int
	if err := f.s.DB.QueryRow(`SELECT autonomous_turns FROM conversations WHERE id = $1`, f.convID).Scan(&turns); err != nil {
		t.Fatal(err)
	}
	if turns != 0 {
		t.Fatalf("failed reservation consumed a turn: %d", turns)
	}
}

func assertDeleteBeforeReserveApproved(t *testing.T, f *supersessionFixture) {
	f.ingest(t, 10, "")
	job := f.claim(t)
	a := f.action(t, job, PolicyRequireApproval, ActionPendingApproval)
	if ok, err := f.s.UpdateAgentActionStatus(context.Background(), f.uid, a.ID, ActionPendingApproval, ActionApproved); err != nil || !ok {
		t.Fatalf("approve: ok=%v err=%v", ok, err)
	}
	// An event-only delete record, as if it raced the owner's approval: the
	// reservation itself must refuse.
	if _, err := f.s.DB.Exec(`INSERT INTO incoming_events
		(event_id, user_id, kind, chat_tg_id, sender_tg_id, message_id, meta)
		VALUES($1,$2,$3,$4,$4,$5,'{}')`,
		f.eventID(10, ":d"), f.uid, EventKindMessageDelete, aliceChat, int64(10)); err != nil {
		t.Fatal(err)
	}
	ok, err := f.reserve(a)
	var se *SourceSupersededError
	if ok || !errors.As(err, &se) || se.Kind != SourceDeleted {
		t.Fatalf("reserve: ok=%v err=%v, want SourceSupersededError(deleted)", ok, err)
	}
	if ok, err := f.s.DenyAgentActionWithReason(context.Background(), f.uid, a.ID, ActionApproved, SourceSupersededReason(se.Kind)); err != nil || !ok {
		t.Fatalf("deny: ok=%v err=%v", ok, err)
	}
	if st, reasons := f.actionRow(t, a.ID); st != ActionDenied || reasons != ReasonSourceDeleted {
		t.Fatalf("action = %s %q, want denied %q", st, reasons, ReasonSourceDeleted)
	}
	reason, at, ok, err := f.s.LastWithdrawnDraft(context.Background(), f.uid, f.convID)
	if err != nil || !ok || reason != ReasonSourceDeleted || at.IsZero() {
		t.Fatalf("LastWithdrawnDraft = %q %v ok=%v err=%v", reason, at, ok, err)
	}
}

func assertDeleteAfterReserve(t *testing.T, f *supersessionFixture) {
	f.ingest(t, 10, "")
	job := f.claim(t)
	a := f.action(t, job, PolicyAllow, ActionApproved)
	if ok, err := f.reserve(a); err != nil || !ok {
		t.Fatalf("reserve: ok=%v err=%v", ok, err)
	}
	res := f.recordDelete(t, 10)
	if res.Recorded != 1 || res.DeniedActions != 0 {
		t.Fatalf("delete result = %+v, want recorded and nothing denied", res)
	}
	if st, _ := f.actionRow(t, a.ID); st != ActionExecuting {
		t.Fatalf("executing action moved to %s by a later delete", st)
	}
}

func assertCoalescedMemberEdit(t *testing.T, f *supersessionFixture) {
	f.ingest(t, 10, "")
	memberEvent := f.ingest(t, 11, "")
	head := f.claim(t)
	f.coalesce(t, head.ID, f.jobID(t, memberEvent))
	a := f.action(t, head, PolicyRequireApproval, ActionPendingApproval)

	n, err := f.s.DenyPendingActionsForSourceMessage(context.Background(), f.uid, f.convID, 11, ReasonSourceEdited)
	if err != nil || n != 1 {
		t.Fatalf("deny for edited member: n=%d err=%v, want 1", n, err)
	}
	if st, reasons := f.actionRow(t, a.ID); st != ActionDenied || reasons != ReasonSourceEdited {
		t.Fatalf("head action = %s %q", st, reasons)
	}
	f.ingest(t, 11, ":e100:aa")
	if got := f.superseded(t, head.ID); got != SourceEdited {
		t.Fatalf("head after member edit: %q, want %q", got, SourceEdited)
	}
}

func assertCoalescedMemberDelete(t *testing.T, f *supersessionFixture) {
	f.ingest(t, 10, "")
	memberEvent := f.ingest(t, 11, "")
	head := f.claim(t)
	f.coalesce(t, head.ID, f.jobID(t, memberEvent))
	a := f.action(t, head, PolicyAllow, ActionApproved)

	res := f.recordDelete(t, 11)
	if res.Recorded != 1 || res.DeniedActions != 1 {
		t.Fatalf("delete result = %+v, want 1 recorded, 1 denied", res)
	}
	if st, reasons := f.actionRow(t, a.ID); st != ActionDenied || reasons != ReasonSourceDeleted {
		t.Fatalf("head action = %s %q", st, reasons)
	}
	if got := f.superseded(t, head.ID); got != SourceDeleted {
		t.Fatalf("head after member delete: %q", got)
	}
}

func assertRedeliveredDelete(t *testing.T, f *supersessionFixture) {
	f.ingest(t, 10, "")
	job := f.claim(t)
	if res := f.recordDelete(t, 10); res.Recorded != 1 {
		t.Fatalf("first delete = %+v", res)
	}
	// A fresh draft after the first delete (it would itself be denied at
	// propose time; inserted directly here) must not be touched by the
	// redelivery: the redelivery changes nothing at all.
	a := f.action(t, job, PolicyAllow, ActionApproved)
	if res := f.recordDelete(t, 10); res != (MessageDeleteResult{}) {
		t.Fatalf("redelivered delete = %+v, want no-op", res)
	}
	if st, _ := f.actionRow(t, a.ID); st != ActionApproved {
		t.Fatalf("redelivery touched an action: %s", st)
	}
	var n int
	if err := f.s.DB.QueryRow(`SELECT COUNT(*) FROM incoming_events WHERE user_id = $1 AND kind = $2`,
		f.uid, EventKindMessageDelete).Scan(&n); err != nil || n != 1 {
		t.Fatalf("delete events = %d err=%v, want 1", n, err)
	}
}

func assertPendingJobIgnored(t *testing.T, f *supersessionFixture) {
	deleted := f.ingest(t, 10, "")
	kept := f.ingest(t, 11, "")
	res := f.recordDelete(t, 10)
	if res.Recorded != 1 || res.IgnoredJobs != 1 {
		t.Fatalf("delete result = %+v, want 1 recorded, 1 ignored", res)
	}
	var st, note string
	if err := f.s.DB.QueryRow(`SELECT status, last_error FROM agent_jobs WHERE event_id = $1`, deleted).Scan(&st, &note); err != nil {
		t.Fatal(err)
	}
	if st != JobIgnored || note != ReasonSourceDeleted {
		t.Fatalf("deleted message's job = %s %q", st, note)
	}
	if err := f.s.DB.QueryRow(`SELECT status FROM agent_jobs WHERE event_id = $1`, kept).Scan(&st); err != nil {
		t.Fatal(err)
	}
	if st != JobPending {
		t.Fatalf("other message's job = %s, want pending", st)
	}
	if got := f.claim(t); got.EventID != kept {
		t.Fatalf("claimed %s, want %s", got.EventID, kept)
	}
}

func assertUnknownDelete(t *testing.T, f *supersessionFixture) {
	f.ingest(t, 10, "")
	if _, _, ok, err := f.s.LastWithdrawnDraft(context.Background(), f.uid, f.convID); err != nil || ok {
		t.Fatalf("LastWithdrawnDraft on a clean conversation: ok=%v err=%v", ok, err)
	}
	if res := f.recordDelete(t, 99); res != (MessageDeleteResult{}) {
		t.Fatalf("unknown delete = %+v, want no-op", res)
	}
}

func assertJoblessNotSuperseded(t *testing.T, f *supersessionFixture) {
	if got := f.superseded(t, 0); got != "" {
		t.Fatalf("job 0 superseded: %q", got)
	}
}
