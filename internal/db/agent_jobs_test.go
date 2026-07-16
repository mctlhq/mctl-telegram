package db

import (
	"context"
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

	jobs, err := s.ClaimAgentJobs(ctx, "replica-a", 5)
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
	jobs, err = s.ClaimAgentJobs(ctx, "replica-b", 5)
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
	if _, err := s.ClaimAgentJobs(ctx, "r", 1); err != nil {
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
	if _, err := s.ClaimAgentJobs(ctx, "r", 1); err != nil {
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
	if _, err := s.ClaimAgentJobs(ctx, "r", 1); err != nil {
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
	if _, err := s.ClaimAgentJobs(ctx, "r", 1); err != nil {
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
	first, err := s.ClaimAgentJobs(ctx, "worker-a", 1)
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
	second, err := s.ClaimAgentJobs(ctx, "worker-b", 1)
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
	if _, err := s.ClaimAgentJobs(ctx, "r", 1); err != nil {
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

func TestRequeueStaleAgentJobs(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	fresh := seedJob(t, s, uid, "evt:v1:1:1:1")
	stale := seedJob(t, s, uid, "evt:v1:1:1:2")
	exhausted := seedJob(t, s, uid, "evt:v1:1:1:3")

	if _, err := s.ClaimAgentJobs(ctx, "r", 3); err != nil {
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
