package db

// pa_jobs.go is the Personal Assistant run loop's queue and ledger (issue
// #1313 slice d1; threat model T4, T10, T13). It implements jobs.Store.
//
//   - pa_jobs is the queue. A partial unique index allows one queued
//     (pending or held) and one claimed job per principal, so the database
//     itself enforces "one active job per principal".
//   - pa_usage is the PA ledger (owner decision 2026-11-18: its own table,
//     not agent_usage, whose user_id is an MCTL account a PA principal may
//     not have). A claim takes the managed ledger's global lock
//     (managedBudgetLockKey) and its global_day window sums agent_usage and
//     pa_usage alike, so PA spend counts against the platform daily cap and
//     the managed claim path counts PA spend too (usageSums,
//     budgetCandidateFilter).
//   - pa_rate is the per-principal fixed rate window.
//
// Every read failure wraps jobs.ErrUnreadable: it is never "not found", "no
// spend" or "allowed" (I9). Timestamps are unix milliseconds, as in the
// other pa_* tables.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

var _ jobs.Store = (*Store)(nil)

// PAUsageRetention is how long settled and held pa_usage rows are kept: the
// longest budget window is a calendar month, so 62 days always covers it.
const PAUsageRetention = 62 * 24 * time.Hour

func paJobsSchema(pg bool) []string {
	intT, realT, idT := "INTEGER", "REAL", "INTEGER PRIMARY KEY AUTOINCREMENT"
	if pg {
		intT, realT, idT = "BIGINT", "DOUBLE PRECISION", "BIGSERIAL PRIMARY KEY"
	}
	return []string{
		`CREATE TABLE IF NOT EXISTS pa_jobs (
			id ` + idT + `,
			principal ` + intT + ` NOT NULL,
			conversation_id TEXT NOT NULL,
			update_id ` + intT + ` NOT NULL,
			consent_version TEXT NOT NULL,
			status TEXT NOT NULL,
			attempts ` + intT + ` NOT NULL DEFAULT 0,
			turns ` + intT + ` NOT NULL DEFAULT 0,
			tool_calls ` + intT + ` NOT NULL DEFAULT 0,
			execution_context TEXT NOT NULL DEFAULT '',
			context_digest TEXT NOT NULL DEFAULT '',
			tool_set TEXT NOT NULL DEFAULT '',
			lease_until_ms ` + intT + ` NOT NULL DEFAULT 0,
			held_until_ms ` + intT + ` NOT NULL DEFAULT 0,
			hold_notified ` + intT + ` NOT NULL DEFAULT 0,
			created_at_ms ` + intT + ` NOT NULL,
			updated_at_ms ` + intT + ` NOT NULL
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_pa_jobs_queued ON pa_jobs(principal) WHERE status IN ('pending', 'held')`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_pa_jobs_running ON pa_jobs(principal) WHERE status = 'claimed'`,
		`CREATE INDEX IF NOT EXISTS idx_pa_jobs_status ON pa_jobs(status, created_at_ms)`,
		`CREATE TABLE IF NOT EXISTS pa_usage (
			id ` + idT + `,
			job_id ` + intT + ` NOT NULL,
			attempt ` + intT + ` NOT NULL,
			principal ` + intT + ` NOT NULL,
			reserved_usd ` + realT + ` NOT NULL,
			cost_usd ` + realT + `,
			status TEXT NOT NULL,
			created_at_ms ` + intT + ` NOT NULL,
			updated_at_ms ` + intT + ` NOT NULL,
			UNIQUE (job_id, attempt)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pa_usage_created ON pa_usage(created_at_ms)`,
		`CREATE INDEX IF NOT EXISTS idx_pa_usage_principal ON pa_usage(principal, created_at_ms)`,
		`CREATE TABLE IF NOT EXISTS pa_rate (
			principal ` + intT + ` PRIMARY KEY,
			window_start_ms ` + intT + ` NOT NULL,
			count ` + intT + ` NOT NULL
		)`,
		// Handler failures of an update, counted outside the update's
		// (rolled back) transaction, so a deterministically failing update
		// is acknowledged after a bounded number of Telegram retries.
		`CREATE TABLE IF NOT EXISTS pa_update_failures (
			update_id ` + intT + ` PRIMARY KEY,
			attempts ` + intT + ` NOT NULL,
			updated_at_ms ` + intT + ` NOT NULL
		)`,
	}
}

func migratePAJobs(ctx context.Context, dbConn *sql.DB, pg bool) error {
	for _, s := range paJobsSchema(pg) {
		if _, err := dbConn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate pa jobs: %w", err)
		}
	}
	// The recorded handler error of an update acknowledged after too many
	// failed attempts. Empty for every update that ran.
	return addColumnIfMissing(ctx, dbConn, pg, "pa_updates", "handler_error", "TEXT NOT NULL DEFAULT ''", "TEXT NOT NULL DEFAULT ''")
}

func jobsUnreadable(op string, err error) error {
	return fmt.Errorf("%w: %s: %v", jobs.ErrUnreadable, op, err)
}

// AdmitPAMessage implements jobs.Store. It runs under the principal lock
// the webhook transaction already holds, so read-then-write is not racy.
func (s *Store) AdmitPAMessage(ctx context.Context, tx *sql.Tx, principal int64, now time.Time, limit int, window time.Duration) (jobs.RateDecision, error) {
	if tx == nil || principal <= 0 || limit <= 0 || window <= 0 {
		return jobs.RateDecision{}, fmt.Errorf("%w: rate", jobs.ErrInvalid)
	}
	nowMS := now.UnixMilli()
	var startMS, count int64
	err := tx.QueryRowContext(ctx, `SELECT window_start_ms, count FROM pa_rate WHERE principal = $1`, principal).Scan(&startMS, &count)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		count = 1
		if _, err := tx.ExecContext(ctx, `INSERT INTO pa_rate(principal, window_start_ms, count) VALUES($1, $2, 1)`, principal, nowMS); err != nil {
			return jobs.RateDecision{}, fmt.Errorf("pa rate: insert: %w", err)
		}
	case err != nil:
		return jobs.RateDecision{}, jobsUnreadable("rate", err)
	case startMS+window.Milliseconds() <= nowMS:
		count = 1
		if _, err := tx.ExecContext(ctx, `UPDATE pa_rate SET window_start_ms = $1, count = 1 WHERE principal = $2`, nowMS, principal); err != nil {
			return jobs.RateDecision{}, fmt.Errorf("pa rate: reset: %w", err)
		}
	default:
		count++
		if _, err := tx.ExecContext(ctx, `UPDATE pa_rate SET count = $1 WHERE principal = $2`, count, principal); err != nil {
			return jobs.RateDecision{}, fmt.Errorf("pa rate: count: %w", err)
		}
	}
	return jobs.RateDecision{Allowed: count <= int64(limit), Notify: count == int64(limit)+1}, nil
}

// EnqueuePAJob implements jobs.Store. A queued job of the same conversation
// absorbs the message (it reads the whole conversation when it runs). A
// queued job of another conversation is cancelled first: it could only be
// cancelled at claim anyway, and the new message must not be lost with it.
func (s *Store) EnqueuePAJob(ctx context.Context, tx *sql.Tx, req jobs.EnqueueRequest) (jobs.EnqueueOutcome, error) {
	if tx == nil || req.Principal <= 0 || req.ConversationID == "" || req.ConsentVersion == "" || req.UpdateID < 0 {
		return 0, fmt.Errorf("%w: enqueue", jobs.ErrInvalid)
	}
	nowMS := req.Now.UnixMilli()
	var queuedConv string
	err := tx.QueryRowContext(ctx,
		`SELECT conversation_id FROM pa_jobs WHERE principal = $1 AND status IN ($2, $3)`,
		req.Principal, string(jobs.StatusPending), string(jobs.StatusHeld)).Scan(&queuedConv)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return 0, jobsUnreadable("enqueue: queued job", err)
	case queuedConv == req.ConversationID:
		return jobs.Coalesced, nil
	default:
		if err := cancelPAJobs(ctx, tx, req.Principal, nowMS, jobs.StatusPending, jobs.StatusHeld); err != nil {
			return 0, err
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO pa_jobs(principal, conversation_id, update_id, consent_version, status, created_at_ms, updated_at_ms)
		 VALUES($1, $2, $3, $4, $5, $6, $6)`,
		req.Principal, req.ConversationID, req.UpdateID, req.ConsentVersion, string(jobs.StatusPending), nowMS); err != nil {
		return 0, fmt.Errorf("enqueue pa job: %w", err)
	}
	return jobs.Enqueued, nil
}

// cancelPAJobs cancels the principal's jobs in the given statuses. A
// cancelled claimed job's reservation moves to held: its token has left the
// server and the run may already have spent up to the reservation.
func cancelPAJobs(ctx context.Context, tx *sql.Tx, principal, nowMS int64, statuses ...jobs.Status) error {
	args := []any{string(jobs.StatusCancelled), nowMS, principal}
	in := ""
	for i, st := range statuses {
		if i > 0 {
			in += ", "
		}
		args = append(args, string(st))
		in += fmt.Sprintf("$%d", len(args))
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE pa_jobs SET status = $1, updated_at_ms = $2 WHERE principal = $3 AND status IN (`+in+`)`, args...); err != nil {
		return fmt.Errorf("cancel pa jobs: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE pa_usage SET status = $1, updated_at_ms = $2
		  WHERE principal = $3 AND status = $4
		    AND job_id IN (SELECT id FROM pa_jobs WHERE principal = $3 AND status <> $5)`,
		jobs.UsageHeld, nowMS, principal, jobs.UsageReserved, string(jobs.StatusClaimed)); err != nil {
		return fmt.Errorf("cancel pa jobs: hold usage: %w", err)
	}
	return nil
}

// CancelPAJobs cancels every pending, held and claimed job of the
// principal, in the caller's transaction (consent withdrawal, /forget).
func (s *Store) CancelPAJobs(ctx context.Context, tx *sql.Tx, principal int64, now time.Time) error {
	if tx == nil || principal <= 0 {
		return fmt.Errorf("%w: cancel", jobs.ErrInvalid)
	}
	return cancelPAJobs(ctx, tx, principal, now.UnixMilli(), jobs.StatusPending, jobs.StatusHeld, jobs.StatusClaimed)
}

// ExpirePAJobs ends every claimed job whose lease ran out and holds its
// reservation at the full amount. It runs in its own short transaction
// before a claim: the claim must not hold another principal's job row while
// it waits for a principal lock (a turn holds that lock and then wants the
// row).
func (s *Store) ExpirePAJobs(ctx context.Context, now time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("expire pa jobs: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	nowMS := now.UnixMilli()
	if _, err := tx.ExecContext(ctx,
		`UPDATE pa_jobs SET status = $1, updated_at_ms = $2 WHERE status = $3 AND lease_until_ms <= $2`,
		string(jobs.StatusExpired), nowMS, string(jobs.StatusClaimed)); err != nil {
		return fmt.Errorf("expire pa jobs: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE pa_usage SET status = $1, updated_at_ms = $2
		  WHERE status = $3 AND job_id IN (SELECT id FROM pa_jobs WHERE status <> $4)`,
		jobs.UsageHeld, nowMS, jobs.UsageReserved, string(jobs.StatusClaimed)); err != nil {
		return fmt.Errorf("expire pa jobs: hold usage: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("expire pa jobs: commit: %w", err)
	}
	return nil
}

const paJobColumns = `id, principal, conversation_id, update_id, consent_version, status, attempts, turns,
	tool_calls, execution_context, context_digest, tool_set, lease_until_ms, held_until_ms, created_at_ms`

func scanPAJob(row interface{ Scan(...any) error }) (jobs.Job, error) {
	var (
		j                         jobs.Job
		status, ec, tools         string
		leaseMS, heldMS, createMS int64
	)
	if err := row.Scan(&j.ID, &j.Principal, &j.ConversationID, &j.UpdateID, &j.ConsentVersion, &status,
		&j.Attempts, &j.Turns, &j.ToolCalls, &ec, &j.ContextDigest, &tools, &leaseMS, &heldMS, &createMS); err != nil {
		return jobs.Job{}, err
	}
	j.Status = jobs.Status(status)
	switch j.Status {
	case jobs.StatusPending, jobs.StatusHeld, jobs.StatusClaimed, jobs.StatusDone, jobs.StatusCancelled, jobs.StatusExpired:
	default:
		return jobs.Job{}, fmt.Errorf("unknown job status")
	}
	if ec != "" {
		j.ExecutionContext = []byte(ec)
	}
	if tools != "" {
		if err := json.Unmarshal([]byte(tools), &j.ToolSet); err != nil {
			return jobs.Job{}, fmt.Errorf("tool set: %w", err)
		}
	}
	if leaseMS > 0 {
		j.LeaseUntil = time.UnixMilli(leaseMS).UTC()
	}
	if heldMS > 0 {
		j.HeldUntil = time.UnixMilli(heldMS).UTC()
	}
	j.CreatedAt = time.UnixMilli(createMS).UTC()
	return j, nil
}

// paWindowSums returns the durable (settled cost plus held reservations)
// and in-flight (reserved) PA usage created at or after sinceMS. principal 0
// means every principal.
func paWindowSums(ctx context.Context, tx *sql.Tx, sinceMS, principal int64) (durable, inflight float64, err error) {
	q := `SELECT COALESCE(SUM(CASE WHEN status = 'settled' THEN COALESCE(cost_usd, reserved_usd)
	                               WHEN status = 'held' THEN reserved_usd ELSE 0 END), 0),
	             COALESCE(SUM(CASE WHEN status = 'reserved' THEN reserved_usd ELSE 0 END), 0)
	        FROM pa_usage WHERE created_at_ms >= $1`
	args := []any{sinceMS}
	if principal > 0 {
		q += ` AND principal = $2`
		args = append(args, principal)
	}
	if err := tx.QueryRowContext(ctx, q, args...).Scan(&durable, &inflight); err != nil {
		return 0, 0, fmt.Errorf("sum pa usage: %w", err)
	}
	return durable, inflight, nil
}

// ClaimPAJob implements jobs.Store.
func (s *Store) ClaimPAJob(ctx context.Context, req jobs.ClaimRequest) (jobs.ClaimResult, error) {
	if !req.Budget.Valid() || req.Lease <= 0 || req.Gate == nil || req.Build == nil || req.Now.IsZero() {
		return jobs.ClaimResult{}, fmt.Errorf("%w: claim", jobs.ErrInvalid)
	}
	pg, err := s.postgresDialect(ctx)
	if err != nil {
		return jobs.ClaimResult{}, jobsUnreadable("claim: dialect", err)
	}
	if err := s.ExpirePAJobs(ctx, req.Now); err != nil {
		return jobs.ClaimResult{}, err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return jobs.ClaimResult{}, fmt.Errorf("claim pa job: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// The managed ledger's global lock first, exactly as a managed claim
	// takes it (lockManagedBudget), so the two claim paths serialise on one
	// global_day window.
	if err := s.lockManagedBudget(ctx, tx, pg, 0); err != nil {
		return jobs.ClaimResult{}, err
	}
	nowMS := req.Now.UnixMilli()
	var id, principal int64
	err = tx.QueryRowContext(ctx,
		`SELECT j.id, j.principal FROM pa_jobs j
		  WHERE (j.status = $1 OR (j.status = $2 AND j.held_until_ms <= $3))
		    AND NOT EXISTS (SELECT 1 FROM pa_jobs c WHERE c.principal = j.principal AND c.status = $4)
		  ORDER BY j.created_at_ms, j.id LIMIT 1`,
		string(jobs.StatusPending), string(jobs.StatusHeld), nowMS, string(jobs.StatusClaimed)).Scan(&id, &principal)
	if errors.Is(err, sql.ErrNoRows) {
		return jobs.ClaimResult{Outcome: jobs.ClaimNone}, nil
	}
	if err != nil {
		return jobs.ClaimResult{}, jobsUnreadable("claim: pick", err)
	}
	// Serialise with the principal's webhook updates (withdrawal, /forget),
	// then read the job again under that lock.
	if err := s.LockPAPrincipal(ctx, tx, principal); err != nil {
		return jobs.ClaimResult{}, err
	}
	lock := ""
	if pg {
		lock = " FOR UPDATE"
	}
	j, err := scanPAJob(tx.QueryRowContext(ctx,
		`SELECT `+paJobColumns+` FROM pa_jobs WHERE id = $1 AND principal = $2`+lock, id, principal))
	if err != nil {
		return jobs.ClaimResult{}, jobsUnreadable("claim: job", err)
	}
	if j.Status != jobs.StatusPending && (j.Status != jobs.StatusHeld || j.HeldUntil.After(req.Now)) {
		// Cancelled between the pick and the lock.
		if err := tx.Commit(); err != nil {
			return jobs.ClaimResult{}, fmt.Errorf("claim pa job: commit: %w", err)
		}
		return jobs.ClaimResult{Outcome: jobs.ClaimNone}, nil
	}
	if err := req.Gate(ctx, tx, j, req.Now); err != nil {
		if !errors.Is(err, jobs.ErrGone) {
			return jobs.ClaimResult{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE pa_jobs SET status = $1, updated_at_ms = $2 WHERE id = $3`,
			string(jobs.StatusCancelled), nowMS, j.ID); err != nil {
			return jobs.ClaimResult{}, fmt.Errorf("claim pa job: cancel: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return jobs.ClaimResult{}, fmt.Errorf("claim pa job: commit: %w", err)
		}
		j.Status = jobs.StatusCancelled
		return jobs.ClaimResult{Outcome: jobs.ClaimCancelled, Job: j}, nil
	}

	res, err := s.paBudget(ctx, tx, req, j)
	if err != nil {
		return jobs.ClaimResult{}, err
	}
	switch res.Outcome {
	case jobs.ClaimHeld:
		notify := 0
		err := tx.QueryRowContext(ctx, `SELECT hold_notified FROM pa_jobs WHERE id = $1`, j.ID).Scan(&notify)
		if err != nil {
			return jobs.ClaimResult{}, jobsUnreadable("claim: hold notified", err)
		}
		res.Notify = notify == 0
		if _, err := tx.ExecContext(ctx,
			`UPDATE pa_jobs SET status = $1, held_until_ms = $2, hold_notified = 1, updated_at_ms = $3 WHERE id = $4`,
			string(jobs.StatusHeld), res.Job.HeldUntil.UnixMilli(), nowMS, j.ID); err != nil {
			return jobs.ClaimResult{}, fmt.Errorf("claim pa job: hold: %w", err)
		}
		res.Job.Status = jobs.StatusHeld
	case jobs.ClaimClaimed:
		attempt := j.Attempts + 1
		var resID int64
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO pa_usage(job_id, attempt, principal, reserved_usd, status, created_at_ms, updated_at_ms)
			 VALUES($1, $2, $3, $4, $5, $6, $6) RETURNING id`,
			j.ID, attempt, j.Principal, req.Budget.PerJobUSD, jobs.UsageReserved, nowMS).Scan(&resID); err != nil {
			return jobs.ClaimResult{}, fmt.Errorf("claim pa job: reserve: %w", err)
		}
		j.Status, j.Attempts, j.Turns, j.ToolCalls = jobs.StatusClaimed, attempt, 0, 0
		j.LeaseUntil = req.Now.Add(req.Lease).UTC()
		j.HeldUntil = time.Time{}
		ecJSON, digest, tools, err := req.Build(ctx, tx, j, resID)
		if err != nil {
			if !errors.Is(err, jobs.ErrInvalid) {
				return jobs.ClaimResult{}, err
			}
			// A job that cannot be built (a tool outside the read-only
			// catalog, say) fails the same way on every attempt. Left
			// pending it would stay the oldest job and block every
			// principal's queue, so it is cancelled with nothing reserved.
			_ = tx.Rollback()
			if cerr := s.cancelInvalidPAJob(ctx, j.ID, req.Now); cerr != nil {
				return jobs.ClaimResult{}, errors.Join(err, cerr)
			}
			return jobs.ClaimResult{}, err
		}
		if len(ecJSON) == 0 || digest == "" {
			return jobs.ClaimResult{}, fmt.Errorf("%w: claim: empty execution context", jobs.ErrInvalid)
		}
		if tools == nil {
			tools = []string{}
		}
		toolsJSON, err := json.Marshal(tools)
		if err != nil {
			return jobs.ClaimResult{}, fmt.Errorf("claim pa job: tool set: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE pa_jobs SET status = $1, attempts = $2, turns = 0, tool_calls = 0, execution_context = $3,
			        context_digest = $4, tool_set = $5, lease_until_ms = $6, held_until_ms = 0, updated_at_ms = $7
			  WHERE id = $8`,
			string(jobs.StatusClaimed), attempt, string(ecJSON), digest, string(toolsJSON),
			j.LeaseUntil.UnixMilli(), nowMS, j.ID); err != nil {
			return jobs.ClaimResult{}, fmt.Errorf("claim pa job: claim: %w", err)
		}
		j.ExecutionContext, j.ContextDigest, j.ToolSet = ecJSON, digest, slices.Clone(tools)
		res.Job, res.ReservationID = j, resID
	}
	if err := tx.Commit(); err != nil {
		return jobs.ClaimResult{}, fmt.Errorf("claim pa job: commit: %w", err)
	}
	return res, nil
}

type paWindow struct {
	scope             string
	cap               float64
	durable, inflight float64
	end               time.Time
}

func (w paWindow) room(perJob float64, withInflight bool) bool {
	used := w.durable
	if withInflight {
		used += w.inflight
	}
	return w.cap-used+budgetEpsilon >= perJob
}

// paBudget decides a claim against the three windows. The global window sums
// the managed ledger and the PA ledger; a failure to read either is an
// error, never zero spend.
func (s *Store) paBudget(ctx context.Context, tx *sql.Tx, req jobs.ClaimRequest, j jobs.Job) (jobs.ClaimResult, error) {
	now := req.Now.UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	windows := []paWindow{
		{scope: jobs.ScopeGlobalDay, cap: req.Budget.GlobalDayUSD, end: dayStart.AddDate(0, 0, 1)},
		{scope: jobs.ScopePrincipalMonth, cap: req.Budget.PrincipalMonthUSD, end: monthStart.AddDate(0, 1, 0)},
		{scope: jobs.ScopePrincipalDay, cap: req.Budget.PrincipalDayUSD, end: dayStart.AddDate(0, 0, 1)},
	}
	var err error
	for i := range windows {
		w := &windows[i]
		switch w.scope {
		case jobs.ScopeGlobalDay:
			// usageSums with no account sums the managed ledger and pa_usage.
			w.durable, w.inflight, err = usageSums(ctx, tx, dayStart, 0)
		case jobs.ScopePrincipalMonth:
			w.durable, w.inflight, err = paWindowSums(ctx, tx, monthStart.UnixMilli(), j.Principal)
		case jobs.ScopePrincipalDay:
			w.durable, w.inflight, err = paWindowSums(ctx, tx, dayStart.UnixMilli(), j.Principal)
		}
		if err != nil {
			return jobs.ClaimResult{}, jobsUnreadable("budget: pa ledger", err)
		}
	}
	all := true
	for _, w := range windows {
		all = all && w.room(req.Budget.PerJobUSD, true)
	}
	if all {
		return jobs.ClaimResult{Outcome: jobs.ClaimClaimed, Job: j}, nil
	}
	for _, w := range windows {
		if !w.room(req.Budget.PerJobUSD, false) {
			j.HeldUntil = w.end
			return jobs.ClaimResult{Outcome: jobs.ClaimHeld, Job: j, Scope: w.scope}, nil
		}
	}
	for _, w := range windows {
		if !w.room(req.Budget.PerJobUSD, true) {
			return jobs.ClaimResult{Outcome: jobs.ClaimDeferred, Job: j, Scope: w.scope}, nil
		}
	}
	return jobs.ClaimResult{Outcome: jobs.ClaimDeferred, Job: j}, nil
}

// loadRunningPAJob loads the job of ref under the principal lock and checks
// that it is still running under exactly this attempt and context.
func (s *Store) loadRunningPAJob(ctx context.Context, tx *sql.Tx, pg bool, ref jobs.Ref, now time.Time) (jobs.Job, error) {
	if err := s.LockPAPrincipal(ctx, tx, ref.Principal); err != nil {
		return jobs.Job{}, err
	}
	lock := ""
	if pg {
		lock = " FOR UPDATE"
	}
	j, err := scanPAJob(tx.QueryRowContext(ctx,
		`SELECT `+paJobColumns+` FROM pa_jobs WHERE id = $1 AND principal = $2`+lock, ref.JobID, ref.Principal))
	if errors.Is(err, sql.ErrNoRows) {
		return jobs.Job{}, jobs.ErrNotFound
	}
	if err != nil {
		return jobs.Job{}, jobsUnreadable("job", err)
	}
	if j.Status != jobs.StatusClaimed || j.Attempts != ref.Attempt || j.ContextDigest != ref.Digest ||
		!j.LeaseUntil.After(now) {
		return jobs.Job{}, jobs.ErrStale
	}
	return j, nil
}

// beginRunning resolves the dialect before the transaction opens (on
// SQLite the probe would wait for the one connection the transaction
// holds), then loads the running job of ref under the principal lock.
func (s *Store) beginRunning(ctx context.Context, ref jobs.Ref, now time.Time) (*sql.Tx, jobs.Job, error) {
	pg, err := s.postgresDialect(ctx)
	if err != nil {
		return nil, jobs.Job{}, jobsUnreadable("dialect", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, jobs.Job{}, fmt.Errorf("pa job: begin: %w", err)
	}
	j, err := s.loadRunningPAJob(ctx, tx, pg, ref, now)
	if err != nil {
		_ = tx.Rollback()
		return nil, jobs.Job{}, err
	}
	return tx, j, nil
}

// runGate applies the gate and, when it reports ErrGone, cancels the job
// and commits that, so the refusal is durable.
func runGate(ctx context.Context, tx *sql.Tx, gate jobs.Gate, j jobs.Job, now time.Time) error {
	if gate == nil {
		return fmt.Errorf("%w: no gate", jobs.ErrInvalid)
	}
	err := gate(ctx, tx, j, now)
	if err == nil {
		return nil
	}
	if !errors.Is(err, jobs.ErrGone) {
		return err
	}
	if cerr := cancelOne(ctx, tx, j, now.UnixMilli()); cerr != nil {
		return cerr
	}
	if cerr := tx.Commit(); cerr != nil {
		return fmt.Errorf("cancel pa job: commit: %w", cerr)
	}
	return jobs.ErrGone
}

func cancelOne(ctx context.Context, tx *sql.Tx, j jobs.Job, nowMS int64) error {
	if _, err := tx.ExecContext(ctx, `UPDATE pa_jobs SET status = $1, updated_at_ms = $2 WHERE id = $3 AND principal = $4`,
		string(jobs.StatusCancelled), nowMS, j.ID, j.Principal); err != nil {
		return fmt.Errorf("cancel pa job: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE pa_usage SET status = $1, updated_at_ms = $2 WHERE job_id = $3 AND attempt = $4 AND status = $5`,
		jobs.UsageHeld, nowMS, j.ID, j.Attempts, jobs.UsageReserved); err != nil {
		return fmt.Errorf("cancel pa job: hold usage: %w", err)
	}
	return nil
}

// ReleasePAClaim implements jobs.Store.
func (s *Store) ReleasePAClaim(ctx context.Context, ref jobs.Ref, requeue bool) error {
	if !ref.Valid() {
		return fmt.Errorf("%w: release", jobs.ErrInvalid)
	}
	tx, j, err := s.beginRunning(ctx, ref, time.Now())
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM pa_usage WHERE job_id = $1 AND attempt = $2 AND status = $3`,
		j.ID, j.Attempts, jobs.UsageReserved); err != nil {
		return fmt.Errorf("release pa claim: usage: %w", err)
	}
	next := jobs.StatusCancelled
	if requeue {
		// A queued job of the principal already reads the same
		// conversation when it runs; only one may be queued.
		var queued int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM pa_jobs WHERE principal = $1 AND status IN ($2, $3)`,
			j.Principal, string(jobs.StatusPending), string(jobs.StatusHeld)).Scan(&queued); err != nil {
			return jobsUnreadable("release: queued", err)
		}
		if queued == 0 {
			next = jobs.StatusPending
		}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE pa_jobs SET status = $1, lease_until_ms = 0, execution_context = '', context_digest = '', tool_set = '',
		        updated_at_ms = $2 WHERE id = $3`,
		string(next), time.Now().UnixMilli(), j.ID); err != nil {
		return fmt.Errorf("release pa claim: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("release pa claim: commit: %w", err)
	}
	return nil
}

// RunningPAJob implements jobs.Store.
func (s *Store) RunningPAJob(ctx context.Context, ref jobs.Ref, now time.Time) (jobs.Job, error) {
	if !ref.Valid() {
		return jobs.Job{}, fmt.Errorf("%w: running job", jobs.ErrInvalid)
	}
	tx, j, err := s.beginRunning(ctx, ref, now)
	if err != nil {
		return jobs.Job{}, err
	}
	_ = tx.Rollback()
	return j, nil
}

// AdmitPATurn implements jobs.Store.
func (s *Store) AdmitPATurn(ctx context.Context, ref jobs.Ref, req jobs.TurnRequest) (jobs.Job, error) {
	if !ref.Valid() || req.MaxContextTokens <= 0 || req.ContextTokens < 0 || req.MaxTurns <= 0 {
		return jobs.Job{}, fmt.Errorf("%w: turn", jobs.ErrInvalid)
	}
	tx, j, err := s.beginRunning(ctx, ref, req.Now)
	if err != nil {
		return jobs.Job{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := runGate(ctx, tx, req.Gate, j, req.Now); err != nil {
		return jobs.Job{}, err
	}
	if req.ContextTokens > req.MaxContextTokens {
		return jobs.Job{}, jobs.ErrContextTooLarge
	}
	if j.Turns >= req.MaxTurns {
		return jobs.Job{}, jobs.ErrToolCap
	}
	if _, err := tx.ExecContext(ctx, `UPDATE pa_jobs SET turns = turns + 1, updated_at_ms = $1 WHERE id = $2`,
		req.Now.UnixMilli(), j.ID); err != nil {
		return jobs.Job{}, fmt.Errorf("admit pa turn: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return jobs.Job{}, fmt.Errorf("admit pa turn: commit: %w", err)
	}
	j.Turns++
	return j, nil
}

// AdmitPAToolCall implements jobs.Store: the tool must be in the job's
// signed tool set (S1-I1), the run under its tool-call cap (S1-R2), its
// reservation still live, and consent and the conversation still valid.
// The count is taken in the same transaction as the checks, so concurrent
// proposals cannot overshoot the cap.
func (s *Store) AdmitPAToolCall(ctx context.Context, ref jobs.Ref, req jobs.ToolCallRequest) (jobs.Job, error) {
	if !ref.Valid() || req.Tool == "" || req.MaxToolCalls <= 0 {
		return jobs.Job{}, fmt.Errorf("%w: tool call", jobs.ErrInvalid)
	}
	tx, j, err := s.beginRunning(ctx, ref, req.Now)
	if err != nil {
		return jobs.Job{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := runGate(ctx, tx, req.Gate, j, req.Now); err != nil {
		return jobs.Job{}, err
	}
	if !slices.Contains(j.ToolSet, req.Tool) {
		return jobs.Job{}, jobs.ErrToolNotInSet
	}
	if j.ToolCalls >= req.MaxToolCalls {
		return jobs.Job{}, jobs.ErrToolCap
	}
	var status string
	err = tx.QueryRowContext(ctx, `SELECT status FROM pa_usage WHERE job_id = $1 AND attempt = $2`, j.ID, j.Attempts).Scan(&status)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return jobs.Job{}, jobs.ErrBudget
	case err != nil:
		return jobs.Job{}, jobsUnreadable("tool call: reservation", err)
	case status != jobs.UsageReserved:
		return jobs.Job{}, jobs.ErrBudget
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE pa_jobs SET tool_calls = tool_calls + 1, updated_at_ms = $1 WHERE id = $2 AND tool_calls < $3`,
		req.Now.UnixMilli(), j.ID, req.MaxToolCalls)
	if err != nil {
		return jobs.Job{}, fmt.Errorf("admit pa tool call: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return jobs.Job{}, jobsUnreadable("tool call: count", err)
	}
	if n != 1 {
		return jobs.Job{}, jobs.ErrToolCap
	}
	if err := tx.Commit(); err != nil {
		return jobs.Job{}, fmt.Errorf("admit pa tool call: commit: %w", err)
	}
	j.ToolCalls++
	return j, nil
}

// FinishPAJob implements jobs.Store. The reply is recorded, the reservation
// settled and the job marked done in one transaction; the send happens
// after the commit, never inside it.
func (s *Store) FinishPAJob(ctx context.Context, ref jobs.Ref, req jobs.FinishRequest) (jobs.Job, error) {
	if !ref.Valid() {
		return jobs.Job{}, fmt.Errorf("%w: finish", jobs.ErrInvalid)
	}
	tx, j, err := s.beginRunning(ctx, ref, req.Now)
	if err != nil {
		return jobs.Job{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := runGate(ctx, tx, req.Gate, j, req.Now); err != nil {
		return jobs.Job{}, err
	}
	if req.Record != nil {
		if err := req.Record(ctx, tx, j); err != nil {
			return jobs.Job{}, err
		}
	}
	nowMS := req.Now.UnixMilli()
	// An unreported cost settles at the full reservation.
	q, args := `UPDATE pa_usage SET status = $1, cost_usd = reserved_usd, updated_at_ms = $2
		  WHERE job_id = $3 AND attempt = $4 AND status = $5`, []any{jobs.UsageSettled, nowMS, j.ID, j.Attempts, jobs.UsageReserved}
	if req.CostUSD >= 0 {
		q, args = `UPDATE pa_usage SET status = $1, cost_usd = $6, updated_at_ms = $2
		  WHERE job_id = $3 AND attempt = $4 AND status = $5`, append(args, req.CostUSD)
	}
	res, err := tx.ExecContext(ctx, q, args...)
	if err != nil {
		return jobs.Job{}, fmt.Errorf("finish pa job: settle: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return jobs.Job{}, jobsUnreadable("finish: settle count", err)
	}
	if n != 1 {
		return jobs.Job{}, jobs.ErrBudget
	}
	if _, err := tx.ExecContext(ctx, `UPDATE pa_jobs SET status = $1, updated_at_ms = $2 WHERE id = $3`,
		string(jobs.StatusDone), nowMS, j.ID); err != nil {
		return jobs.Job{}, fmt.Errorf("finish pa job: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return jobs.Job{}, fmt.Errorf("finish pa job: commit: %w", err)
	}
	j.Status = jobs.StatusDone
	return j, nil
}

// PAConversationOpen reports whether conversationID is the principal's
// open, unexpired conversation: nil, convo-style absence as jobs.ErrGone,
// or a read error. The run loop's gate uses it at every step.
func (s *Store) PAConversationOpen(ctx context.Context, tx *sql.Tx, principal int64, conversationID string, now time.Time) error {
	if tx == nil || principal <= 0 || conversationID == "" {
		return fmt.Errorf("%w: conversation", jobs.ErrInvalid)
	}
	var one int
	err := tx.QueryRowContext(ctx,
		`SELECT 1 FROM pa_conversations WHERE id = $1 AND principal = $2 AND closed_at_ms = 0 AND expires_at_ms > $3`,
		conversationID, principal, now.UnixMilli()).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return jobs.ErrGone
	}
	if err != nil {
		return jobsUnreadable("conversation", err)
	}
	return nil
}

// PAUsageRow is one pa_usage row, for tests and reconciliation.
type PAUsageRow struct {
	JobID, Principal int64
	Attempt          int
	Reserved         float64
	Cost             sql.NullFloat64
	Status           string
}

// PAUsageFor returns the principal's ledger rows in id order.
func (s *Store) PAUsageFor(ctx context.Context, principal int64) ([]PAUsageRow, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT job_id, principal, attempt, reserved_usd, cost_usd, status FROM pa_usage WHERE principal = $1 ORDER BY id`, principal)
	if err != nil {
		return nil, jobsUnreadable("usage", err)
	}
	defer rows.Close()
	var out []PAUsageRow
	for rows.Next() {
		var r PAUsageRow
		if err := rows.Scan(&r.JobID, &r.Principal, &r.Attempt, &r.Reserved, &r.Cost, &r.Status); err != nil {
			return nil, jobsUnreadable("usage: scan", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, jobsUnreadable("usage: rows", err)
	}
	return out, nil
}

// cancelInvalidPAJob cancels a queued job whose execution context cannot be
// built. It runs in its own transaction after the claim's was rolled back,
// so no reservation exists for it.
func (s *Store) cancelInvalidPAJob(ctx context.Context, id int64, now time.Time) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE pa_jobs SET status = $1, updated_at_ms = $2 WHERE id = $3 AND status IN ($4, $5)`,
		string(jobs.StatusCancelled), now.UnixMilli(), id, string(jobs.StatusPending), string(jobs.StatusHeld))
	if err != nil {
		return fmt.Errorf("claim pa job: cancel invalid: %w", err)
	}
	return nil
}
