package db

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAgentJobBackoff_Schedule(t *testing.T) {
	cases := []struct {
		attempts int
		want     time.Duration
	}{
		{0, 30 * time.Second}, // clamped to 1
		{1, 30 * time.Second},
		{2, time.Minute},
		{3, 2 * time.Minute},
		{4, 4 * time.Minute},
		{5, 8 * time.Minute},
		{6, 16 * time.Minute},
		{7, 30 * time.Minute}, // capped
		{20, 30 * time.Minute},
	}
	for _, c := range cases {
		if got := AgentJobBackoff(c.attempts); got != c.want {
			t.Errorf("AgentJobBackoff(%d) = %v, want %v", c.attempts, got, c.want)
		}
	}
}

// seedJob inserts an event + job pair and returns the job id.
func seedJob(t *testing.T, s *Store, uid int64, eventID string) int64 {
	t.Helper()
	ctx := context.Background()
	if _, _, err := s.InsertIncomingEvent(ctx, IncomingEvent{
		EventID: eventID, UserID: uid, Kind: EventKindPrivateMessage,
		ChatTGID: 1, SenderTGID: 1, MessageID: 1,
	}); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	id, enqueued, err := s.EnqueueAgentJob(ctx, eventID, uid, 0)
	if err != nil || !enqueued {
		t.Fatalf("enqueue: id=%d enqueued=%v err=%v", id, enqueued, err)
	}
	return id
}

func TestEnqueueAgentJob_IdempotentByEvent(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	seedJob(t, s, uid, "evt:v1:1:1:1")

	id, enqueued, err := s.EnqueueAgentJob(ctx, "evt:v1:1:1:1", uid, 0)
	if err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	if enqueued || id != 0 {
		t.Fatalf("re-enqueue: id=%d enqueued=%v, want 0/false", id, enqueued)
	}
}

func TestClaimAgentJobs_ClaimsDueInOrderAndOpensAttempt(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	j1 := seedJob(t, s, uid, "evt:v1:1:1:1")
	j2 := seedJob(t, s, uid, "evt:v1:1:1:2")
	// A job scheduled for the future must not be claimable.
	j3 := seedJob(t, s, uid, "evt:v1:1:1:3")
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_jobs SET next_run_at = $1 WHERE id = $2`,
		time.Now().UTC().Add(time.Hour), j3,
	); err != nil {
		t.Fatalf("defer j3: %v", err)
	}

	jobs, err := s.ClaimAgentJobs(ctx, "replica-a", uid, 5)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(jobs) != 2 || jobs[0].ID != j1 || jobs[1].ID != j2 {
		t.Fatalf("claimed %+v, want [%d %d]", jobs, j1, j2)
	}
	for _, j := range jobs {
		if j.Status != JobProcessing || j.Attempts != 1 || j.ClaimedBy != "replica-a" {
			t.Fatalf("claimed job = %+v", j)
		}
	}

	// Second claim must find nothing (all due jobs already processing).
	jobs, err = s.ClaimAgentJobs(ctx, "replica-b", uid, 5)
	if err != nil {
		t.Fatalf("claim 2: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("second claim got %+v, want none", jobs)
	}

	// Each claim opened an attempt row.
	var n int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM agent_job_attempts WHERE finished_at IS NULL`,
	).Scan(&n); err != nil {
		t.Fatalf("count attempts: %v", err)
	}
	if n != 2 {
		t.Fatalf("open attempts = %d, want 2", n)
	}
}

func TestCompleteAgentJob_CASFromProcessing(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	jid := seedJob(t, s, uid, "evt:v1:1:1:1")

	// Completing a pending (unclaimed) job must fail the CAS.
	if err := s.CompleteAgentJob(ctx, jid, 1, JobCompleted, ""); err != ErrAgentJobNotFound {
		t.Fatalf("complete unclaimed err = %v, want ErrAgentJobNotFound", err)
	}
	if _, err := s.ClaimAgentJobs(ctx, "r", uid, 1); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if err := s.CompleteAgentJob(ctx, jid, 1, "sideways", ""); err == nil {
		t.Fatal("invalid terminal status accepted")
	}
	if err := s.CompleteAgentJob(ctx, jid, 1, JobCompleted, "done"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	got, err := s.GetAgentJob(ctx, uid, jid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != JobCompleted {
		t.Fatalf("status = %q", got.Status)
	}
	// Attempt row closed.
	var open int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM agent_job_attempts WHERE job_id = $1 AND finished_at IS NULL`, jid,
	).Scan(&open); err != nil {
		t.Fatalf("count: %v", err)
	}
	if open != 0 {
		t.Fatalf("open attempts = %d, want 0", open)
	}
}

func TestRetryAgentJob_BackoffThenDeadLetter(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	jid := seedJob(t, s, uid, "evt:v1:1:1:1")
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_jobs SET max_attempts = 2 WHERE id = $1`, jid,
	); err != nil {
		t.Fatalf("set max_attempts: %v", err)
	}

	// Attempt 1: claim + retry → pending with future next_run_at.
	if _, err := s.ClaimAgentJobs(ctx, "r", uid, 1); err != nil {
		t.Fatalf("claim 1: %v", err)
	}
	status, err := s.RetryAgentJob(ctx, jid, 1, "model timeout")
	if err != nil {
		t.Fatalf("retry 1: %v", err)
	}
	if status != JobPending {
		t.Fatalf("retry 1 status = %q, want pending", status)
	}
	got, _ := s.GetAgentJob(ctx, uid, jid)
	if !got.NextRunAt.After(time.Now().UTC().Add(20 * time.Second)) {
		t.Fatalf("next_run_at %v not backed off", got.NextRunAt)
	}
	if got.LastError != "model timeout" {
		t.Fatalf("last_error = %q", got.LastError)
	}

	// Make it due again, claim (attempts=2=max), retry → dead_letter.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_jobs SET next_run_at = $1 WHERE id = $2`, time.Now().UTC().Add(-time.Second), jid,
	); err != nil {
		t.Fatalf("re-arm: %v", err)
	}
	if _, err := s.ClaimAgentJobs(ctx, "r", uid, 1); err != nil {
		t.Fatalf("claim 2: %v", err)
	}
	status, err = s.RetryAgentJob(ctx, jid, 2, "model timeout again")
	if err != nil {
		t.Fatalf("retry 2: %v", err)
	}
	if status != JobDeadLetter {
		t.Fatalf("retry 2 status = %q, want dead_letter", status)
	}

	// Retrying a non-processing job loses the CAS.
	if _, err := s.RetryAgentJob(ctx, jid, 2, "x"); err != ErrAgentJobNotFound {
		t.Fatalf("retry dead job err = %v, want ErrAgentJobNotFound", err)
	}
}

func TestRetryAgentJob_LostRaceReturnsNotFound(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	jid := seedJob(t, s, uid, "evt:v1:1:1:1")
	if _, err := s.ClaimAgentJobs(ctx, "r", uid, 1); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// Simulate another transaction (the stale-claim sweeper) moving the row
	// out of processing between the retry's SELECT and its UPDATE.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_jobs SET status = $1 WHERE id = $2`, JobPending, jid,
	); err != nil {
		t.Fatalf("external requeue: %v", err)
	}
	if _, err := s.RetryAgentJob(ctx, jid, 1, "boom"); err != ErrAgentJobNotFound {
		t.Fatalf("lost-race retry err = %v, want ErrAgentJobNotFound", err)
	}
	// No spurious attempt row should have been committed.
	var attempts int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM agent_job_attempts WHERE job_id = $1 AND status = $2`,
		jid, JobFailed,
	).Scan(&attempts); err != nil {
		t.Fatalf("count attempts: %v", err)
	}
	if attempts != 0 {
		t.Fatalf("failed-attempt rows = %d, want 0 (rolled back)", attempts)
	}
}

func TestStaleClaimCannotCompleteReclaimedJob(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	jid := seedJob(t, s, uid, "evt:v1:1:1:1")

	// Worker A claims (attempts=1), then stalls past the visibility timeout.
	first, err := s.ClaimAgentJobs(ctx, "worker-a", uid, 1)
	if err != nil || len(first) != 1 {
		t.Fatalf("claim a: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_jobs SET claimed_at = $1 WHERE id = $2`,
		time.Now().UTC().Add(-10*time.Minute), jid,
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if _, _, err := s.RequeueStaleAgentJobs(ctx, 5*time.Minute); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	// Worker B re-claims (attempts=2).
	second, err := s.ClaimAgentJobs(ctx, "worker-b", uid, 1)
	if err != nil || len(second) != 1 {
		t.Fatalf("claim b: %v", err)
	}
	if second[0].Attempts != 2 {
		t.Fatalf("second claim attempts = %d, want 2", second[0].Attempts)
	}

	// Worker A finally finishes: its claim identity (attempt 1) is stale, so it
	// must NOT overwrite worker B's in-flight claim.
	if err := s.CompleteAgentJob(ctx, jid, first[0].Attempts, JobCompleted, "late"); err != ErrAgentJobNotFound {
		t.Fatalf("stale complete err = %v, want ErrAgentJobNotFound", err)
	}
	if _, err := s.RetryAgentJob(ctx, jid, first[0].Attempts, "late"); err != ErrAgentJobNotFound {
		t.Fatalf("stale retry err = %v, want ErrAgentJobNotFound", err)
	}
	got, _ := s.GetAgentJob(ctx, uid, jid)
	if got.Status != JobProcessing {
		t.Fatalf("job status = %q, want processing (still owned by worker B)", got.Status)
	}
	// Worker B's own claim identity still works.
	if err := s.CompleteAgentJob(ctx, jid, second[0].Attempts, JobCompleted, "done"); err != nil {
		t.Fatalf("current claim complete: %v", err)
	}
}

func TestRequeueStaleAgentJobs_ClosesOpenAttempt(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	jid := seedJob(t, s, uid, "evt:v1:1:1:1")
	if _, err := s.ClaimAgentJobs(ctx, "r", uid, 1); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_jobs SET claimed_at = $1 WHERE id = $2`,
		time.Now().UTC().Add(-10*time.Minute), jid,
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if _, _, err := s.RequeueStaleAgentJobs(ctx, 5*time.Minute); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	// The abandoned claim's attempt row must be closed, not left open forever.
	var open int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM agent_job_attempts WHERE job_id = $1 AND finished_at IS NULL`, jid,
	).Scan(&open); err != nil {
		t.Fatalf("count open: %v", err)
	}
	if open != 0 {
		t.Fatalf("open attempts after requeue = %d, want 0", open)
	}
}

func TestInsertEventAndEnqueueJob_Atomic(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	conv, err := s.EnsureConversation(ctx, uid, 555, "anna", "Anna")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	ev := IncomingEvent{
		EventID: "evt:v1:1:555:1", UserID: uid, Kind: EventKindPrivateMessage,
		ChatTGID: 555, SenderTGID: 555, MessageID: 1, Body: "hi",
	}
	jobID, enqueued, err := s.InsertEventAndEnqueueJob(ctx, ev, conv.ID)
	if err != nil || !enqueued || jobID == 0 {
		t.Fatalf("ingest: job=%d enqueued=%v err=%v", jobID, enqueued, err)
	}
	// Event and job both exist.
	if _, err := s.GetIncomingEvent(ctx, uid, ev.EventID); err != nil {
		t.Fatalf("event missing: %v", err)
	}
	if _, err := s.GetAgentJob(ctx, uid, jobID); err != nil {
		t.Fatalf("job missing: %v", err)
	}
	// Redelivery is a no-op.
	if _, enqueued, err := s.InsertEventAndEnqueueJob(ctx, ev, conv.ID); err != nil || enqueued {
		t.Fatalf("redelivery: enqueued=%v err=%v, want false/nil", enqueued, err)
	}
	// A foreign conversation is rejected.
	other := seedAgentUser(t, s, "other")
	ev2 := ev
	ev2.EventID = "evt:v1:1:555:2"
	ev2.UserID = other
	if _, _, err := s.InsertEventAndEnqueueJob(ctx, ev2, conv.ID); err != ErrConversationNotFound {
		t.Fatalf("foreign conversation err = %v, want ErrConversationNotFound", err)
	}
}

func TestEnqueueAgentJob_RejectsForeignConversation(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	owner := seedAgentUser(t, s, "owner")
	other := seedAgentUser(t, s, "other")
	conv, err := s.EnsureConversation(ctx, owner, 555, "anna", "Anna")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, _, err := s.InsertIncomingEvent(ctx, IncomingEvent{
		EventID: "evt:x", UserID: other, Kind: EventKindPrivateMessage,
		ChatTGID: 1, SenderTGID: 1, MessageID: 1,
	}); err != nil {
		t.Fatalf("event: %v", err)
	}
	if _, _, err := s.EnqueueAgentJob(ctx, "evt:x", other, conv.ID); err != ErrConversationNotFound {
		t.Fatalf("foreign conversation err = %v, want ErrConversationNotFound", err)
	}
}

func TestClaimAgentJobs_SerializesPerConversation(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	conv, err := s.EnsureConversation(ctx, uid, 555, "anna", "Anna")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	seedEvent := func(eventID string) {
		t.Helper()
		if _, _, err := s.InsertIncomingEvent(ctx, IncomingEvent{
			EventID: eventID, UserID: uid, Kind: EventKindPrivateMessage,
			ChatTGID: 555, SenderTGID: 555, MessageID: 1,
		}); err != nil {
			t.Fatalf("event %s: %v", eventID, err)
		}
	}
	enqueue := func(eventID string, convID int64) int64 {
		t.Helper()
		seedEvent(eventID)
		id, enqueued, err := s.EnqueueAgentJob(ctx, eventID, uid, convID)
		if err != nil || !enqueued {
			t.Fatalf("enqueue %s: id=%d enqueued=%v err=%v", eventID, id, enqueued, err)
		}
		return id
	}
	first := enqueue("evt:conv:1", conv.ID)
	second := enqueue("evt:conv:2", conv.ID)
	loose := enqueue("evt:free:1", 0) // no conversation — unconstrained

	// Only the conversation's OLDEST job plus the unassociated one may be
	// claimed; message 2 must wait for message 1 even though it is due.
	jobs, err := s.ClaimAgentJobs(ctx, "r1", uid, 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(jobs) != 2 || jobs[0].ID != first || jobs[1].ID != loose {
		t.Fatalf("claimed %+v, want [%d %d]", jobs, first, loose)
	}
	// While message 1 is processing the conversation stays blocked.
	if jobs, err = s.ClaimAgentJobs(ctx, "r2", uid, 10); err != nil || len(jobs) != 0 {
		t.Fatalf("claim while in flight = %+v err=%v, want none", jobs, err)
	}
	// Completing message 1 releases message 2.
	if err := s.CompleteAgentJob(ctx, first, 1, JobCompleted, ""); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if jobs, err = s.ClaimAgentJobs(ctx, "r2", uid, 10); err != nil || len(jobs) != 1 || jobs[0].ID != second {
		t.Fatalf("claim after complete = %+v err=%v, want [%d]", jobs, err, second)
	}
}

func TestInsertAgentAction_IdempotentPerJob(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	jid := seedJob(t, s, uid, "evt:v1:1:1:1")
	claimed, err := s.ClaimAgentJobs(ctx, "r", uid, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
	}
	attempt := claimed[0].Attempts

	first, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, JobID: jid, Attempt: attempt, ActionType: ActionTypeReply,
		PolicyDecision: "require_approval", ApprovalCode: "AB12",
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	// A redelivered job proposing again — same attempt, an unresolved response
	// retried by the caller — must land on the SAME row — same id, and
	// crucially the original approval code, not a second live one.
	second, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, JobID: jid, Attempt: attempt, ActionType: ActionTypeReply,
		PolicyDecision: "require_approval", ApprovalCode: "ZZ99",
	})
	if err != nil {
		t.Fatalf("re-insert: %v", err)
	}
	if second != first {
		t.Fatalf("re-insert id = %d, want %d", second, first)
	}
	a, err := s.GetAgentActionByCode(ctx, uid, "AB12")
	if err != nil || a.ID != first {
		t.Fatalf("original code lookup: %+v err=%v", a, err)
	}
	if _, err := s.GetAgentActionByCode(ctx, uid, "ZZ99"); err == nil {
		t.Fatal("second approval code must not exist")
	}
	// A different action type for the same job is a separate row.
	if third, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, JobID: jid, Attempt: attempt, ActionType: ActionTypeOwnerSummary,
		PolicyDecision: "allow",
	}); err != nil || third == first {
		t.Fatalf("other type: id=%d err=%v", third, err)
	}
}

// TestInsertAgentAction_RequiresLiveJob guards the purge race: a worker still
// holding a claimed job must not be able to insert an action row once the
// job is gone — most importantly after HardDeleteAccount deleted the user's
// agent data, when a late insert would resurrect encrypted private content.
func TestInsertAgentAction_RequiresLiveJob(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	// Nonexistent job id.
	if _, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, JobID: 99999, ActionType: ActionTypeReply, PolicyDecision: "deny",
	}); !errors.Is(err, ErrAgentJobNotFound) {
		t.Fatalf("bogus job err = %v, want ErrAgentJobNotFound", err)
	}

	// Another user's job must be invisible.
	other := seedAgentUser(t, s, "other")
	foreign := seedJob(t, s, other, "evt:v1:9:9:9")
	if _, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, JobID: foreign, ActionType: ActionTypeReply, PolicyDecision: "deny",
	}); !errors.Is(err, ErrAgentJobNotFound) {
		t.Fatalf("foreign job err = %v, want ErrAgentJobNotFound", err)
	}

	// After the account purge the job is deleted; the late insert must fail
	// rather than leave an orphaned encrypted payload behind.
	jid := seedJob(t, s, uid, "evt:v1:1:1:2")
	if err := purgeAgentData(ctx, s.DB, uid); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if _, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, JobID: jid, ActionType: ActionTypeReply,
		PolicyDecision: "require_approval", Payload: "secret draft",
	}); !errors.Is(err, ErrAgentJobNotFound) {
		t.Fatalf("post-purge err = %v, want ErrAgentJobNotFound", err)
	}
	var n int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM agent_actions WHERE user_id = $1`, uid,
	).Scan(&n); err != nil || n != 0 {
		t.Fatalf("post-purge action rows = %d err=%v, want 0", n, err)
	}
}

// TestInsertAgentAction_RejectsAfterJobNoLongerActive guards a Codex finding
// on #308: if CompleteJob commits on the server but its HTTP response never
// reaches the caller (a lost response, not a lost request), the caller's
// local completed-guard never fires and can still issue another
// state-changing tool call afterward, believing the job is still open.
// Without a server-side fence, that late call would still persist an
// agent_actions row — and once an executor (A-PR7/#297) consumes approved
// rows, could still get sent — despite the job already being terminal.
// InsertAgentAction must reject any job-tied insert once the job is no
// longer processing under the exact attempt the caller claimed it with,
// covering both ways that can happen: the job reached a terminal status, or
// it was reclaimed under a new attempt (visibility-timeout requeue) after a
// stale worker's local state fell behind.
func TestInsertAgentAction_RejectsAfterJobNoLongerActive(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")

	t.Run("terminal status", func(t *testing.T) {
		jid := seedJob(t, s, uid, "evt:v1:1:1:terminal")
		claimed, err := s.ClaimAgentJobs(ctx, "r", uid, 1)
		if err != nil || len(claimed) != 1 {
			t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
		}
		attempt := claimed[0].Attempts
		// Simulate CompleteJob committing server-side (e.g. status=ignored)
		// while the caller never observed the response.
		if err := s.CompleteAgentJob(ctx, jid, attempt, JobIgnored, ""); err != nil {
			t.Fatalf("complete: %v", err)
		}
		if _, err := s.InsertAgentAction(ctx, AgentAction{
			UserID: uid, JobID: jid, Attempt: attempt, ActionType: ActionTypeReply,
			PolicyDecision: "require_approval", Payload: "late reply",
		}); !errors.Is(err, ErrAgentJobNotFound) {
			t.Fatalf("post-completion insert err = %v, want ErrAgentJobNotFound", err)
		}
	})

	t.Run("stale attempt after requeue", func(t *testing.T) {
		jid := seedJob(t, s, uid, "evt:v1:1:1:stale-attempt")
		claimed, err := s.ClaimAgentJobs(ctx, "r", uid, 1)
		if err != nil || len(claimed) != 1 {
			t.Fatalf("claim: jobs=%+v err=%v", claimed, err)
		}
		staleAttempt := claimed[0].Attempts
		if _, err := s.RetryAgentJob(ctx, jid, staleAttempt, "worker crashed"); err != nil {
			t.Fatalf("retry: %v", err)
		}
		// RetryAgentJob backs next_run_at off by AgentJobBackoff (30s+); pull it
		// back to now so the reclaim below doesn't have to sleep for it.
		if _, err := s.DB.ExecContext(ctx,
			`UPDATE agent_jobs SET next_run_at = $1 WHERE id = $2`, time.Now().UTC(), jid,
		); err != nil {
			t.Fatalf("unbackoff: %v", err)
		}
		reclaimed, err := s.ClaimAgentJobs(ctx, "r", uid, 1)
		if err != nil || len(reclaimed) != 1 {
			t.Fatalf("reclaim: jobs=%+v err=%v", reclaimed, err)
		}
		if reclaimed[0].Attempts == staleAttempt {
			t.Fatalf("reclaim did not bump attempt: still %d", staleAttempt)
		}
		// The stale worker, still believing it owns staleAttempt, must not be
		// able to persist an action against the job's now-active attempt.
		if _, err := s.InsertAgentAction(ctx, AgentAction{
			UserID: uid, JobID: jid, Attempt: staleAttempt, ActionType: ActionTypeReply,
			PolicyDecision: "require_approval", Payload: "stale reply",
		}); !errors.Is(err, ErrAgentJobNotFound) {
			t.Fatalf("stale-attempt insert err = %v, want ErrAgentJobNotFound", err)
		}
	})
}

func TestSweepAgentMessageBodies_ExpiresPendingJobs(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	// Jobs whose events carry a BODY: the sweep must close the stale one —
	// events without a body are deliberately left alone (their jobs don't
	// depend on the swept payload).
	seedBodyJob := func(eventID string) int64 {
		t.Helper()
		if _, _, err := s.InsertIncomingEvent(ctx, IncomingEvent{
			EventID: eventID, UserID: uid, Kind: EventKindPrivateMessage,
			ChatTGID: 1, SenderTGID: 1, MessageID: 1, Body: "hello",
		}); err != nil {
			t.Fatalf("insert event: %v", err)
		}
		id, enqueued, err := s.EnqueueAgentJob(ctx, eventID, uid, 0)
		if err != nil || !enqueued {
			t.Fatalf("enqueue: %v", err)
		}
		return id
	}
	oldJob := seedBodyJob("evt:old")
	freshJob := seedBodyJob("evt:fresh")
	// Age the first event past the retention window.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE incoming_events SET created_at = $1 WHERE event_id = $2`,
		time.Now().UTC().Add(-48*time.Hour), "evt:old",
	); err != nil {
		t.Fatalf("age event: %v", err)
	}
	if _, err := s.SweepAgentMessageBodies(ctx, 24*time.Hour); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	// The stale event's pending job is closed — a later claim would find an
	// empty payload; the fresh job is untouched.
	got, err := s.GetAgentJob(ctx, uid, oldJob)
	if err != nil || got.Status != JobIgnored {
		t.Fatalf("old job = %+v err=%v, want ignored", got, err)
	}
	if got, err = s.GetAgentJob(ctx, uid, freshJob); err != nil || got.Status != JobPending {
		t.Fatalf("fresh job = %+v err=%v, want pending", got, err)
	}
}

func TestEnqueueAgentJob_RejectsUnknownEvent(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	// No incoming_events row for this id: enqueueing must fail loudly instead
	// of creating a poison job that can never load its payload.
	if _, _, err := s.EnqueueAgentJob(ctx, "evt:ghost", uid, 0); err != ErrIncomingEventNotFound {
		t.Fatalf("unknown event err = %v, want ErrIncomingEventNotFound", err)
	}
	// An event owned by another user must not satisfy the pair check either.
	other := seedAgentUser(t, s, "other")
	if _, _, err := s.InsertIncomingEvent(ctx, IncomingEvent{
		EventID: "evt:foreign", UserID: other, Kind: EventKindPrivateMessage,
		ChatTGID: 1, SenderTGID: 1, MessageID: 1,
	}); err != nil {
		t.Fatalf("event: %v", err)
	}
	if _, _, err := s.EnqueueAgentJob(ctx, "evt:foreign", uid, 0); err != ErrIncomingEventNotFound {
		t.Fatalf("foreign event err = %v, want ErrIncomingEventNotFound", err)
	}
}

func TestRequeueStaleAgentJobs(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	fresh := seedJob(t, s, uid, "evt:v1:1:1:1")
	stale := seedJob(t, s, uid, "evt:v1:1:1:2")
	exhausted := seedJob(t, s, uid, "evt:v1:1:1:3")

	if _, err := s.ClaimAgentJobs(ctx, "r", uid, 3); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// Backdate two claims past the visibility window; exhaust one of them.
	old := time.Now().UTC().Add(-10 * time.Minute)
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_jobs SET claimed_at = $1 WHERE id IN ($2, $3)`, old, stale, exhausted,
	); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_jobs SET attempts = max_attempts WHERE id = $1`, exhausted,
	); err != nil {
		t.Fatalf("exhaust: %v", err)
	}

	requeued, dead, err := s.RequeueStaleAgentJobs(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("requeue: %v", err)
	}
	if requeued != 1 || dead != 1 {
		t.Fatalf("requeued=%d dead=%d, want 1/1", requeued, dead)
	}
	for id, want := range map[int64]string{fresh: JobProcessing, stale: JobPending, exhausted: JobDeadLetter} {
		got, err := s.GetAgentJob(ctx, uid, id)
		if err != nil {
			t.Fatalf("get %d: %v", id, err)
		}
		if got.Status != want {
			t.Fatalf("job %d status = %q, want %q", id, got.Status, want)
		}
	}

	counts, err := s.CountAgentJobs(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if counts[JobProcessing] != 1 || counts[JobPending] != 1 || counts[JobDeadLetter] != 1 {
		t.Fatalf("counts = %v", counts)
	}
}
