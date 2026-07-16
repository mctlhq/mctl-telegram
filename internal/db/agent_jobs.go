package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrAgentJobNotFound is returned when a job id does not match, or a status
// transition loses its compare-and-set race.
var ErrAgentJobNotFound = errors.New("agent job not found")

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
// nil error (the pg_catalog table exists ⇒ Postgres) or a genuine
// "relation does not exist" from SQLite (⇒ not Postgres). A transient error —
// a cancelled/timed-out context, a dropped connection — is NOT cached, so a
// probe that fails for a reason unrelated to the dialect re-probes next call
// instead of permanently poisoning every future claim onto the wrong path.
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
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Transient — do not cache; re-probe on the next call.
	default:
		// The query itself was rejected (SQLite has no pg_catalog.pg_database):
		// a definitive "not Postgres".
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
	err = s.DB.QueryRowContext(ctx,
		`INSERT INTO agent_jobs(event_id, user_id, conversation_id)
		 VALUES($1,$2,$3)
		 ON CONFLICT (event_id) DO NOTHING
		 RETURNING id`,
		eventID, userID, convID,
	).Scan(&jobID)
	if errors.Is(err, sql.ErrNoRows) {
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
// replica: flips them to processing, increments attempts, stamps
// claimed_by/claimed_at, and opens an agent_job_attempts row per claim.
//
// On Postgres the inner SELECT uses FOR UPDATE SKIP LOCKED so concurrent
// replicas never claim the same row. SQLite runs with a single connection
// (Open sets SetMaxOpenConns(1)), so the plain form is race-free there.
func (s *Store) ClaimAgentJobs(ctx context.Context, replicaID string, limit int) ([]AgentJob, error) {
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

	rows, err := tx.QueryContext(ctx,
		`UPDATE agent_jobs
		    SET status = $1, attempts = attempts + 1,
		        claimed_by = $2, claimed_at = $3, updated_at = $3
		  WHERE id IN (
		        SELECT id FROM agent_jobs
		         WHERE status = $4 AND next_run_at <= $3
		         ORDER BY next_run_at, id
		         LIMIT $5`+lock+`
		  )
		 RETURNING id, event_id, user_id, conversation_id, status, attempts,
		           max_attempts, next_run_at, claimed_by, claimed_at, last_error,
		           created_at, updated_at`,
		JobProcessing, replicaID, now, JobPending, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("claim agent jobs: %w", err)
	}
	jobs, err := scanAgentJobs(rows)
	if err != nil {
		return nil, err
	}
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
			j         AgentJob
			convID    sql.NullInt64
			claimedBy sql.NullString
			claimedAt sql.NullTime
			lastErr   sql.NullString
		)
		if err := rows.Scan(&j.ID, &j.EventID, &j.UserID, &convID, &j.Status, &j.Attempts,
			&j.MaxAttempts, &j.NextRunAt, &claimedBy, &claimedAt, &lastErr,
			&j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan agent job: %w", err)
		}
		j.ConversationID = convID.Int64
		j.ClaimedBy = claimedBy.String
		j.LastError = lastErr.String
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
		        created_at, updated_at
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
	// means we lost that race, so roll back (the deferred Rollback discards the
	// spurious attempt row too) and report it rather than returning a status we
	// never actually wrote.
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

	// Close the attempt rows of the claims we are about to abandon, before the
	// status flips. Otherwise the timed-out attempt stays open forever: the next
	// claim opens another running attempt and finishOpenAttempt only ever closes
	// the newest one, corrupting attempt history and any open-attempt monitoring.
	if _, err := tx.ExecContext(ctx,
		`UPDATE agent_job_attempts
		    SET finished_at = $1, status = $2, error = $3
		  WHERE finished_at IS NULL
		    AND job_id IN (
		        SELECT id FROM agent_jobs WHERE status = $4 AND claimed_at < $5
		    )`,
		now, JobFailed, "visibility timeout", JobProcessing, cutoff,
	); err != nil {
		return 0, 0, fmt.Errorf("close stale attempts: %w", err)
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE agent_jobs
		    SET status = $1, last_error = $2, updated_at = $3
		  WHERE status = $4 AND claimed_at < $5 AND attempts >= max_attempts`,
		JobDeadLetter, "visibility timeout, attempts exhausted", now, JobProcessing, cutoff,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("dead-letter stale jobs: %w", err)
	}
	dead, _ := res.RowsAffected()
	res, err = tx.ExecContext(ctx,
		`UPDATE agent_jobs
		    SET status = $1, next_run_at = $2, last_error = $3, updated_at = $2
		  WHERE status = $4 AND claimed_at < $5`,
		JobPending, now, "visibility timeout, requeued", JobProcessing, cutoff,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("requeue stale jobs: %w", err)
	}
	requeued, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit requeue tx: %w", err)
	}
	return requeued, dead, nil
}

// purgeAgentJobs deletes a user's queue rows within the caller's transaction.
// Registered with the base purgeAgentData (agent_domain.go) via
// purgeAgentJobsHook so account deletion also drops queued/attempted jobs; the
// queue tables live in this PR, so their purge lives here rather than in the
// base list.
func purgeAgentJobs(ctx context.Context, ex execer, userID int64) error {
	stmts := []string{
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
