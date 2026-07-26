package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrAgentJobNotFound is returned when a job id does not match, or a status
// transition loses its compare-and-set race.
var ErrAgentJobNotFound = errors.New("agent job not found")

// ErrAgentJobResultRequired is returned when status=completed is requested
// without an exact durable action/lead id to bind to the job.
var ErrAgentJobResultRequired = errors.New("agent job durable result required")

// ErrAgentJobResultInvalid is returned when a supplied result id does not
// belong to the same user and job.
var ErrAgentJobResultInvalid = errors.New("agent job durable result invalid")

// Agent job statuses. A job is the unit of at-least-once delivery from an
// incoming event to the external Claude agent:
//
//	pending → processing → completed | failed | ignored
//	processing → pending           (retry with backoff, or stale requeue)
//	processing/pending → dead_letter (attempts exhausted)
//
// The claim (pending→processing) increments attempts; retries re-arm
// next_run_at with exponential backoff computed from the attempt count.
const (
	JobPending    = "pending"
	JobProcessing = "processing"
	JobCompleted  = "completed"
	JobFailed     = "failed"
	JobDeadLetter = "dead_letter"
	JobIgnored    = "ignored"
)

// AgentJob is one queued unit of agent work, keyed 1:1 to an incoming event.
type AgentJob struct {
	ID             int64
	EventID        string
	UserID         int64
	ConversationID int64 // 0 ⇒ not associated yet
	Status         string
	Attempts       int
	MaxAttempts    int
	NextRunAt      time.Time
	ClaimedBy      string
	ClaimedAt      time.Time // zero value ⇒ never claimed
	LastError      string
	ResultActionID int64
	ResultLeadID   int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// AgentJobBackoff returns the retry delay before attempt n+1 given n failed
// attempts so far: min(30s * 2^(n-1), 30m). Exposed as a pure function so the
// schedule is unit-testable without a database.
func AgentJobBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	d := 30 * time.Second
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= 30*time.Minute {
			return 30 * time.Minute
		}
	}
	return d
}

// isPostgres reports (and caches) whether the underlying connection is
// Postgres, using the same pg_catalog probe as Migrate. The claim query is
// the one place the two dialects genuinely diverge (FOR UPDATE SKIP LOCKED).
//
// The result is cached only once the probe returns a DEFINITIVE answer:
// nil error (the pg_catalog table exists ⇒ Postgres) or SQLite's
// "no such table" (⇒ not Postgres). Any other error — a cancelled/timed-out
// context, a dropped connection — is NOT cached, so a probe that fails for a
// reason unrelated to the dialect re-probes next call instead of permanently
// poisoning every future claim onto the wrong path. An unresolved probe
// returns false, which is safe (ClaimAgentJobs guards the outer UPDATE on
// status) but slower; the next call re-probes.
func (s *Store) isPostgres(ctx context.Context) bool {
	s.pgMu.Lock()
	defer s.pgMu.Unlock()
	if s.pgResolved {
		return s.pgFlag
	}
	err := s.DB.QueryRowContext(ctx,
		"SELECT 1 FROM pg_catalog.pg_database WHERE datname = current_database()",
	).Scan(new(int))
	switch {
	case err == nil:
		s.pgFlag, s.pgResolved = true, true
	case strings.Contains(err.Error(), "no such table"):
		// SQLite rejecting the pg_catalog reference — a definitive "not
		// Postgres". Every other failure (cancelled context, dropped
		// connection, server restart) says nothing about the dialect, so it
		// must not be cached: a Postgres store that hit a startup hiccup would
		// otherwise be stuck on the non-SKIP-LOCKED claim path forever.
		s.pgFlag, s.pgResolved = false, true
	}
	return s.pgFlag
}

// EnqueueAgentJob inserts a pending job for an event. Idempotent on event_id:
// returns enqueued=false (no error) when a job for that event already exists,
// mirroring InsertIncomingEvent so redelivered updates cannot double-enqueue.
func (s *Store) EnqueueAgentJob(ctx context.Context, eventID string, userID, conversationID int64) (jobID int64, enqueued bool, err error) {
	if eventID == "" {
		return 0, false, errors.New("event id required")
	}
	if userID <= 0 {
		return 0, false, errors.New("user id required")
	}
	// A non-zero conversation must belong to the enqueuing user, matching the
	// guards on InsertAgentAction / InsertConversationMessage. Without it a job
	// could be claimed as one user but tied to another user's conversation.
	if conversationID != 0 {
		if _, err := s.GetConversation(ctx, userID, conversationID); err != nil {
			return 0, false, err
		}
	}
	var convID any
	if conversationID != 0 {
		convID = conversationID
	}
	// Source the insert from incoming_events: a job whose event row does not
	// exist for this user is a poison pill — the worker loads the payload via
	// GetIncomingEvent(user_id, event_id), fails every attempt, and
	// dead-letters. Requiring the pair here turns that runtime failure loop
	// into an immediate ErrEventNotFound for the caller.
	err = s.DB.QueryRowContext(ctx,
		`INSERT INTO agent_jobs(event_id, user_id, conversation_id)
		 SELECT $1, $2, $3 FROM incoming_events
		  WHERE event_id = $1 AND user_id = $2
		 ON CONFLICT (event_id) DO NOTHING
		 RETURNING id`,
		eventID, userID, convID,
	).Scan(&jobID)
	if errors.Is(err, sql.ErrNoRows) {
		// Either the job already exists (idempotent success) or the event row
		// is missing (caller bug). Distinguish so the bad call surfaces.
		var one int
		probeErr := s.DB.QueryRowContext(ctx,
			`SELECT 1 FROM incoming_events WHERE event_id = $1 AND user_id = $2`,
			eventID, userID,
		).Scan(&one)
		if errors.Is(probeErr, sql.ErrNoRows) {
			return 0, false, ErrIncomingEventNotFound
		}
		if probeErr != nil {
			return 0, false, fmt.Errorf("enqueue agent job: %w", probeErr)
		}
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("enqueue agent job: %w", err)
	}
	return jobID, true, nil
}

// InsertEventAndEnqueueJob persists an incoming event and its job in ONE
// transaction, returning enqueued=false when the event was already ingested.
//
// This is the listener's ingestion primitive and exists because the two writes
// must not be separable: InsertIncomingEvent's dedup contract says a duplicate
// event must not be re-enqueued, so a crash after the event commit but before a
// separate enqueue would strand that event with no job — every gotd redelivery
// would then dedup and the message would never reach the agent. Committing both
// together makes ingestion all-or-nothing, so a redelivery either finds the
// complete pair or recreates it.
func (s *Store) InsertEventAndEnqueueJob(ctx context.Context, ev IncomingEvent, conversationID int64) (jobID int64, enqueued bool, err error) {
	if ev.EventID == "" {
		return 0, false, errors.New("event id required")
	}
	if ev.UserID <= 0 {
		return 0, false, errors.New("user id required")
	}
	if ev.Kind == "" {
		return 0, false, errors.New("event kind required")
	}
	if conversationID != 0 {
		if _, err := s.GetConversation(ctx, ev.UserID, conversationID); err != nil {
			return 0, false, err
		}
	}
	var body []byte
	if ev.Body != "" {
		body, err = s.Crypt.SealForUser([]byte(ev.Body), ev.UserID)
		if err != nil {
			return 0, false, fmt.Errorf("seal event body: %w", err)
		}
	}
	meta := ev.Meta
	if meta == "" {
		meta = "{}"
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("begin ingest tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var eventRowID int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO incoming_events
		   (event_id, user_id, kind, chat_tg_id, sender_tg_id, message_id, body_encrypted, meta)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (event_id) DO NOTHING
		 RETURNING id`,
		ev.EventID, ev.UserID, ev.Kind, ev.ChatTGID, ev.SenderTGID, ev.MessageID, body, meta,
	).Scan(&eventRowID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil // already ingested (with its job) — nothing to do
	}
	if err != nil {
		return 0, false, fmt.Errorf("insert incoming event: %w", err)
	}

	var convID any
	if conversationID != 0 {
		convID = conversationID
	}
	err = tx.QueryRowContext(ctx,
		`INSERT INTO agent_jobs(event_id, user_id, conversation_id)
		 VALUES($1,$2,$3)
		 ON CONFLICT (event_id) DO NOTHING
		 RETURNING id`,
		ev.EventID, ev.UserID, convID,
	).Scan(&jobID)
	if errors.Is(err, sql.ErrNoRows) {
		// An orphan job already exists for this event id (only reachable if a
		// prior partial write is being repaired); the event row is now present,
		// so treat the pair as complete.
		if err := tx.Commit(); err != nil {
			return 0, false, fmt.Errorf("commit ingest tx: %w", err)
		}
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("enqueue agent job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("commit ingest tx: %w", err)
	}
	return jobID, true, nil
}

// ClaimAgentJobs atomically claims up to limit due pending jobs for this
// replica, scoped to userID: flips them to processing, increments attempts,
// stamps claimed_by/claimed_at, and opens an agent_job_attempts row per
// claim.
//
// The user_id filter is load-bearing, not an optimization: the agent API's
// POST /jobs/claim is called with a specific caller's aud=agent token, and
// without this filter a worker authenticated for one account could claim —
// and thereby leak the event_id/conversation_id of, and starve — another
// account's jobs. userID must be > 0; callers outside a per-user request
// context (none currently exist) would need a separate cross-account
// entrypoint, not a userID<=0 escape hatch here.
//
// On Postgres the inner SELECT uses FOR UPDATE SKIP LOCKED so concurrent
// replicas never claim the same row. SQLite runs with a single connection
// (Open sets SetMaxOpenConns(1)), so the plain form is race-free there.
func (s *Store) ClaimAgentJobs(ctx context.Context, replicaID string, userID int64, limit int) ([]AgentJob, error) {
	if userID <= 0 {
		return nil, errors.New("user id required")
	}
	if limit <= 0 {
		limit = 1
	}
	now := time.Now().UTC()
	lock := ""
	if s.isPostgres(ctx) {
		lock = " FOR UPDATE SKIP LOCKED"
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin claim tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The outer UPDATE re-checks status = pending. With SKIP LOCKED this is
	// redundant; without it (SQLite, or a Postgres claim while the dialect
	// probe is unresolved) it is what makes a concurrent double-select safe:
	// the loser blocks on the row lock, re-evaluates the predicate against the
	// winner's committed row, sees processing, and skips it.
	//
	// The NOT EXISTS clause serializes each conversation: a job is claimable
	// only when no earlier job (by id — arrival order) of the same
	// conversation is still pending or in flight. Without it, two replicas
	// could claim messages 1 and 2 of one dialog concurrently (SKIP LOCKED
	// happily skips past a locked older row) and answer message 2 first —
	// e.g. replying after an owner takeover that message 1 would have
	// recorded. Head-of-line blocking per conversation is intentional:
	// message order beats throughput inside a dialog. Jobs without a
	// conversation are unconstrained (the NULL comparison never matches).
	rows, err := tx.QueryContext(ctx,
		`UPDATE agent_jobs
		    SET status = $1, attempts = attempts + 1,
		        claimed_by = $2, claimed_at = $3, updated_at = $3
		  WHERE status = $4 AND id IN (
		        SELECT j.id FROM agent_jobs j
		         WHERE j.status = $4 AND j.next_run_at <= $3 AND j.user_id = $6
		           AND NOT EXISTS (
		               SELECT 1 FROM agent_jobs p
		                WHERE p.conversation_id = j.conversation_id
		                  AND (p.status = $1 OR (p.status = $4 AND p.id < j.id))
		           )
		         ORDER BY j.next_run_at, j.id
		         LIMIT $5`+lock+`
		  )
		 RETURNING id, event_id, user_id, conversation_id, status, attempts,
		           max_attempts, next_run_at, claimed_by, claimed_at, last_error,
		           result_action_id, result_lead_id, created_at, updated_at`,
		JobProcessing, replicaID, now, JobPending, limit, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("claim agent jobs: %w", err)
	}
	jobs, err := scanAgentJobs(rows)
	if err != nil {
		return nil, err
	}
	// UPDATE ... RETURNING makes no ordering promise, so re-establish the
	// subquery's oldest-first order before handing the batch to the worker —
	// messages in one conversation must be processed in arrival order.
	sort.Slice(jobs, func(i, k int) bool {
		if !jobs[i].NextRunAt.Equal(jobs[k].NextRunAt) {
			return jobs[i].NextRunAt.Before(jobs[k].NextRunAt)
		}
		return jobs[i].ID < jobs[k].ID
	})
	for _, j := range jobs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO agent_job_attempts(job_id, attempt, started_at) VALUES($1,$2,$3)`,
			j.ID, j.Attempts, now,
		); err != nil {
			return nil, fmt.Errorf("insert job attempt: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit claim tx: %w", err)
	}
	return jobs, nil
}

func scanAgentJobs(rows *sql.Rows) ([]AgentJob, error) {
	defer func() { _ = rows.Close() }()
	var out []AgentJob
	for rows.Next() {
		var (
			j                            AgentJob
			convID                       sql.NullInt64
			claimedBy                    sql.NullString
			claimedAt                    sql.NullTime
			lastErr                      sql.NullString
			resultActionID, resultLeadID sql.NullInt64
		)
		if err := rows.Scan(&j.ID, &j.EventID, &j.UserID, &convID, &j.Status, &j.Attempts,
			&j.MaxAttempts, &j.NextRunAt, &claimedBy, &claimedAt, &lastErr,
			&resultActionID, &resultLeadID, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan agent job: %w", err)
		}
		j.ConversationID = convID.Int64
		j.ClaimedBy = claimedBy.String
		j.LastError = lastErr.String
		j.ResultActionID = resultActionID.Int64
		j.ResultLeadID = resultLeadID.Int64
		if claimedAt.Valid {
			j.ClaimedAt = claimedAt.Time
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// GetAgentJob returns a job by id, scoped to the owning user.
func (s *Store) GetAgentJob(ctx context.Context, userID, id int64) (*AgentJob, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, event_id, user_id, conversation_id, status, attempts,
		        max_attempts, next_run_at, claimed_by, claimed_at, last_error,
		        result_action_id, result_lead_id, created_at, updated_at
		   FROM agent_jobs WHERE id = $1 AND user_id = $2`,
		id, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("get agent job: %w", err)
	}
	jobs, err := scanAgentJobs(rows)
	if err != nil {
		return nil, err
	}
	if len(jobs) == 0 {
		return nil, ErrAgentJobNotFound
	}
	return &jobs[0], nil
}

// CompleteAgentJob closes a processing job with a terminal status
// (completed, failed, or ignored) and finishes its open attempt row.
//
// attempt is the claim identity: the Attempts value the caller received from
// ClaimAgentJobs. The compare-and-set matches on it as well as the status, so
// a worker whose claim has since been requeued by the stale-claim sweeper (and
// re-claimed by another worker, incrementing attempts) cannot overwrite the
// newer claim's outcome. Returns ErrAgentJobNotFound when the job is not
// processing under that exact claim.
func (s *Store) CompleteAgentJob(ctx context.Context, jobID int64, attempt int, status, note string) error {
	if status != JobCompleted && status != JobFailed && status != JobIgnored {
		return fmt.Errorf("invalid terminal job status %q", status)
	}
	now := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin complete tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx,
		`UPDATE agent_jobs SET status = $1, last_error = $2, updated_at = $3
		  WHERE id = $4 AND status = $5 AND attempts = $6`,
		status, nullable(note), now, jobID, JobProcessing, attempt,
	)
	if err != nil {
		return fmt.Errorf("complete agent job: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAgentJobNotFound
	}
	if err := finishOpenAttempt(ctx, tx, jobID, status, note, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit complete tx: %w", err)
	}
	return nil
}

// CompleteAgentJobWithResult atomically verifies exact durable result ids and
// closes one user-scoped claim. The result checks and terminal transition run
// in the same transaction and are fenced by attempt, eliminating the
// handler-level "EXISTS then complete" TOCTOU window.
func (s *Store) CompleteAgentJobWithResult(
	ctx context.Context,
	userID, jobID int64,
	attempt int,
	status, note string,
	resultActionID, resultLeadID int64,
) error {
	if userID <= 0 {
		return errors.New("user id required")
	}
	if status != JobCompleted && status != JobFailed && status != JobIgnored {
		return fmt.Errorf("invalid terminal job status %q", status)
	}
	if status == JobCompleted && resultActionID <= 0 && resultLeadID <= 0 {
		return ErrAgentJobResultRequired
	}
	if status != JobCompleted && (resultActionID > 0 || resultLeadID > 0) {
		return ErrAgentJobResultInvalid
	}

	now := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin complete-with-result tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if resultActionID > 0 {
		var exists bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS(
			    SELECT 1 FROM agent_actions
			     WHERE id = $1 AND job_id = $2 AND user_id = $3
			)`,
			resultActionID, jobID, userID,
		).Scan(&exists); err != nil {
			return fmt.Errorf("verify job result action: %w", err)
		}
		if !exists {
			return ErrAgentJobResultInvalid
		}
	}
	if resultLeadID > 0 {
		var exists bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS(
			    SELECT 1 FROM job_leads
			     WHERE id = $1 AND job_id = $2 AND user_id = $3
			)`,
			resultLeadID, jobID, userID,
		).Scan(&exists); err != nil {
			return fmt.Errorf("verify job result lead: %w", err)
		}
		if !exists {
			return ErrAgentJobResultInvalid
		}
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE agent_jobs
		    SET status = $1, last_error = $2,
		        result_action_id = $3, result_lead_id = $4, updated_at = $5
		  WHERE id = $6 AND user_id = $7 AND status = $8 AND attempts = $9`,
		status, nullable(note), nullableInt(resultActionID), nullableInt(resultLeadID),
		now, jobID, userID, JobProcessing, attempt,
	)
	if err != nil {
		return fmt.Errorf("complete agent job with result: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAgentJobNotFound
	}
	if err := finishOpenAttempt(ctx, tx, jobID, status, note, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit complete-with-result tx: %w", err)
	}
	return nil
}

// RetryAgentJob returns a processing job to the queue after a transient
// failure. When attempts have reached max_attempts the job goes to
// dead_letter instead; otherwise it becomes pending with next_run_at pushed
// out by the exponential backoff for its attempt count. Returns the resulting
// status so the caller can count dead-letters.
func (s *Store) RetryAgentJob(ctx context.Context, jobID int64, attempt int, errMsg string) (string, error) {
	now := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin retry tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var attempts, maxAttempts int
	err = tx.QueryRowContext(ctx,
		`SELECT attempts, max_attempts FROM agent_jobs
		  WHERE id = $1 AND status = $2 AND attempts = $3`,
		jobID, JobProcessing, attempt,
	).Scan(&attempts, &maxAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrAgentJobNotFound
	}
	if err != nil {
		return "", fmt.Errorf("select job for retry: %w", err)
	}

	status := JobPending
	nextRun := now.Add(AgentJobBackoff(attempts))
	if attempts >= maxAttempts {
		status = JobDeadLetter
		nextRun = now
	}
	// The SELECT above took no row lock, so between it and this UPDATE another
	// transaction (e.g. the stale-claim sweeper) may have moved the row out of
	// processing. Guard on status again and check RowsAffected: a zero count
	// means we lost that race, so roll back and report it rather than
	// returning a status we never actually wrote.
	res, err := tx.ExecContext(ctx,
		`UPDATE agent_jobs
		    SET status = $1, next_run_at = $2, last_error = $3, updated_at = $4
		  WHERE id = $5 AND status = $6 AND attempts = $7`,
		status, nextRun, nullable(errMsg), now, jobID, JobProcessing, attempt,
	)
	if err != nil {
		return "", fmt.Errorf("retry agent job: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrAgentJobNotFound
	}
	if err := finishOpenAttempt(ctx, tx, jobID, JobFailed, errMsg, now); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit retry tx: %w", err)
	}
	return status, nil
}

// finishOpenAttempt closes the newest still-running attempt row for a job.
func finishOpenAttempt(ctx context.Context, ex execer, jobID int64, status, errMsg string, now time.Time) error {
	if _, err := ex.ExecContext(ctx,
		`UPDATE agent_job_attempts SET finished_at = $1, status = $2, error = $3
		  WHERE id = (
		        SELECT id FROM agent_job_attempts
		         WHERE job_id = $4 AND finished_at IS NULL
		         ORDER BY id DESC LIMIT 1
		  )`,
		now, status, nullable(errMsg), jobID,
	); err != nil {
		return fmt.Errorf("finish job attempt: %w", err)
	}
	return nil
}

// RequeueStaleAgentJobs returns processing jobs whose claim is older than
// visibility to the queue (crash recovery: the worker died mid-job). Jobs
// that have exhausted their attempts go to dead_letter instead of looping
// forever. Returns (requeued, deadLettered).
func (s *Store) RequeueStaleAgentJobs(ctx context.Context, visibility time.Duration) (int64, int64, error) {
	if visibility <= 0 {
		return 0, 0, nil
	}
	now := time.Now().UTC()
	cutoff := now.Add(-visibility)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin requeue tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock order matters: workers (CompleteAgentJob / RetryAgentJob) update
	// agent_jobs first and agent_job_attempts second, so the sweep must do the
	// same — transition the stale jobs first, collect the ids it actually
	// moved, then close those jobs' attempt rows. Touching attempts first
	// would take the two tables' locks in the opposite order and deadlock on
	// Postgres against a still-alive worker finishing the same job.
	deadIDs, err := requeueTransition(ctx, tx,
		`UPDATE agent_jobs
		    SET status = $1, last_error = $2, updated_at = $3
		  WHERE status = $4 AND claimed_at < $5 AND attempts >= max_attempts
		 RETURNING id`,
		JobDeadLetter, "visibility timeout, attempts exhausted", now, JobProcessing, cutoff,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("dead-letter stale jobs: %w", err)
	}
	requeuedIDs, err := requeueTransition(ctx, tx,
		`UPDATE agent_jobs
		    SET status = $1, next_run_at = $2, last_error = $3, updated_at = $2
		  WHERE status = $4 AND claimed_at < $5
		 RETURNING id`,
		JobPending, now, "visibility timeout, requeued", JobProcessing, cutoff,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("requeue stale jobs: %w", err)
	}

	// Close the abandoned attempt rows of exactly the jobs transitioned above.
	// Otherwise the timed-out attempt stays open forever: the next claim opens
	// another running attempt and finishOpenAttempt only ever closes the
	// newest one, corrupting attempt history and any open-attempt monitoring.
	for _, id := range append(append([]int64{}, deadIDs...), requeuedIDs...) {
		if _, err := tx.ExecContext(ctx,
			`UPDATE agent_job_attempts
			    SET finished_at = $1, status = $2, error = $3
			  WHERE job_id = $4 AND finished_at IS NULL`,
			now, JobFailed, "visibility timeout", id,
		); err != nil {
			return 0, 0, fmt.Errorf("close stale attempts: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit requeue tx: %w", err)
	}
	return int64(len(requeuedIDs)), int64(len(deadIDs)), nil
}

// requeueTransition runs one stale-claim UPDATE ... RETURNING id and collects
// the ids of the rows it transitioned.
func requeueTransition(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]int64, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// purgeAgentJobs deletes a user's queue rows within the caller's transaction.
// Registered with the base purgeAgentData (agent_domain.go) via
// purgeAgentJobsHook so account deletion also drops queued/attempted jobs; the
// queue tables live in this PR, so their purge lives here rather than in the
// base list.
func purgeAgentJobs(ctx context.Context, ex execer, userID int64) error {
	stmts := []string{
		// Take the job row locks FIRST, matching the worker's lock order
		// (agent_jobs → agent_job_attempts). Deleting attempts before locking
		// the jobs would take the two tables in the opposite order and could
		// deadlock on Postgres against CompleteAgentJob/RetryAgentJob running
		// for the same user's processing job. The self-assignment is a no-op
		// write whose only purpose is acquiring those locks.
		`UPDATE agent_jobs SET updated_at = updated_at WHERE user_id = $1`,
		`DELETE FROM agent_job_attempts WHERE job_id IN (SELECT id FROM agent_jobs WHERE user_id = $1)`,
		`DELETE FROM agent_jobs WHERE user_id = $1`,
	}
	for _, q := range stmts {
		if _, err := ex.ExecContext(ctx, q, userID); err != nil {
			return fmt.Errorf("purge agent jobs: %w", err)
		}
	}
	return nil
}

func init() { purgeAgentJobsHook = purgeAgentJobs }

// CountAgentJobs returns the number of jobs per status, for the queue gauges.
func (s *Store) CountAgentJobs(ctx context.Context) (map[string]int64, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT status, COUNT(*) FROM agent_jobs GROUP BY status`,
	)
	if err != nil {
		return nil, fmt.Errorf("count agent jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]int64)
	for rows.Next() {
		var status string
		var n int64
		if err := rows.Scan(&status, &n); err != nil {
			return nil, fmt.Errorf("scan job count: %w", err)
		}
		out[status] = n
	}
	return out, rows.Err()
}
