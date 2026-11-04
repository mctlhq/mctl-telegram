package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
)

// Usage ledger statuses (ADR 0008 section 5). There is deliberately no
// "released" status: a reservation leaves the ledger only through
// ReleaseUnissuedClaim, which deletes the row of an attempt whose token never
// left the server.
const (
	UsageReserved = "reserved"
	UsageHeld     = "held"
	UsageSettled  = "settled"
)

// Budget scopes, the "scope" label of the budget counters.
const (
	BudgetScopeAccountDay   = "account_day"
	BudgetScopeAccountMonth = "account_month"
	BudgetScopeGlobalDay    = "global_day"
)

// NotificationBudget is the owner notification queued once per exhausted
// budget window.
const NotificationBudget = "budget"

// ErrUsageConflict means a cost report repeated an already settled attempt
// with different figures. Nothing was changed.
var ErrUsageConflict = errors.New("usage already settled with different values")

// ErrUsageCredential means a cost report for a managed-runtime job came with
// a credential that is not bound to that job (an account token). Only the
// pool-issued job token may settle a managed reservation: otherwise the
// account owner could settle their own reservations at zero and get around
// the caps that are meant to limit them. Nothing was changed.
var ErrUsageCredential = errors.New("managed job usage requires the job's own credential")

// managedBudgetLockKey is the Postgres advisory lock key of the global
// managed budget. It is taken before any account lock (see reserveBudget).
const managedBudgetLockKey = "mctl-telegram:managed-budget:global"

// ManagedBudget configures the server-authoritative caps of the managed pool.
// A zero value (PerJobUSD <= 0) disables the budget code entirely.
type ManagedBudget struct {
	// PerJobUSD is the reservation made for every claimed managed job.
	PerJobUSD       float64
	AccountDayUSD   float64
	AccountMonthUSD float64
	GlobalDayUSD    float64
	// ClaimNotAfter, when set, ends managed claims at that instant: from then on
	// a claim takes nothing and reserves nothing, without a pause or a
	// notification. Jobs already claimed finish and settle normally.
	ClaimNotAfter time.Time
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

func (b *ManagedBudget) now() time.Time {
	if b.Now != nil {
		return b.Now().UTC()
	}
	return time.Now().UTC()
}

// WithManagedBudget turns on the budget enforcement of managed claims. A
// budget without a positive per-job reservation is ignored.
func (s *Store) WithManagedBudget(b ManagedBudget) *Store {
	if b.PerJobUSD <= 0 {
		s.budget = nil
		return s
	}
	s.budget = &b
	return s
}

// Usage is what a worker reports for one attempt. Identity (user, job,
// attempt, runtime) never comes from it.
type Usage struct {
	CostUSD      float64
	Model        string
	Runner       string
	InputTokens  int64
	OutputTokens int64
	// JobScoped is a fact about the credential, set by the server from the
	// authenticated identity and never from the report: true when the caller
	// holds a token bound to this job. A managed-runtime job accepts only
	// such a report (ErrUsageCredential).
	JobScoped bool
}

// UsageOutcome is the result of RecordAgentJobUsage.
type UsageOutcome int

const (
	// UsageRecorded means the attempt was settled by this call.
	UsageRecorded UsageOutcome = iota + 1
	// UsageUnchanged means an identical report had already settled it.
	UsageUnchanged
)

// budgetEvent is a budget decision to be counted after the claim commits.
type budgetEvent struct {
	exhausted bool
	scope     string
}

func (s *Store) countBudgetEvent(ev *budgetEvent) {
	if ev == nil || s.metrics == nil {
		return
	}
	if ev.exhausted {
		s.metrics.AgentBudgetExhaustedTotal.WithLabelValues(ev.scope).Inc()
	} else {
		s.metrics.AgentBudgetDeferredTotal.WithLabelValues(ev.scope).Inc()
	}
}

// budgeted reports whether a claim must reserve budget.
func (s *Store) budgeted(runtime string, maxInflight int) bool {
	return s.budget != nil && runtime == RuntimeManaged && maxInflight > 0
}

// lockManagedBudget takes the global budget lock. It must be the first lock a
// managed claim takes: the global pause updates other accounts' profile rows
// while holding it, so a claim that held an account lock or a profile row and
// then waited here could close a cycle (40P01).
func (s *Store) lockManagedBudget(ctx context.Context, tx *sql.Tx, pg bool, userID int64) error {
	if s.budgetLockHook != nil {
		s.budgetLockHook(userID)
	}
	if !pg {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, managedBudgetLockKey); err != nil {
		return fmt.Errorf("lock managed budget: %w", err)
	}
	return nil
}

type budgetWindow struct {
	scope    string
	cap      float64
	durable  float64
	inflight float64
	end      time.Time
}

const budgetEpsilon = 1e-9

func (w budgetWindow) slots(perJob float64, withInflight bool) int {
	used := w.durable
	if withInflight {
		used += w.inflight
	}
	n := math.Floor((w.cap-used)/perJob + budgetEpsilon)
	if n < 0 {
		return 0
	}
	return int(n)
}

// usageSums returns the durable (settled cost plus held reservations) and the
// in-flight (reserved) managed usage created at or after since. userID 0
// means every account.
func usageSums(ctx context.Context, tx *sql.Tx, since time.Time, userID int64) (durable, inflight float64, err error) {
	q := `SELECT COALESCE(SUM(CASE WHEN status = 'settled' THEN COALESCE(cost_usd, 0)
	                               WHEN status = 'held' THEN reserved_usd ELSE 0 END), 0),
	             COALESCE(SUM(CASE WHEN status = 'reserved' THEN reserved_usd ELSE 0 END), 0)
	        FROM agent_usage WHERE runtime = 'managed' AND created_at >= $1`
	args := []any{since.UTC()}
	if userID > 0 {
		q += ` AND user_id = $2`
		args = append(args, userID)
	}
	if err := tx.QueryRowContext(ctx, q, args...).Scan(&durable, &inflight); err != nil {
		return 0, 0, fmt.Errorf("sum managed usage: %w", err)
	}
	return durable, inflight, nil
}

// reserveBudget returns how many jobs of userID this claim may still take
// under every cap, given the global budget lock is held. A result of 0 means
// the claim takes nothing; when the cap is durably exhausted it has stamped
// the pause (and queued the notification) in tx, so the caller must commit.
func (s *Store) reserveBudget(ctx context.Context, tx *sql.Tx, userID int64, limit int) (int, *budgetEvent, error) {
	b := s.budget
	now := b.now()
	if !b.ClaimNotAfter.IsZero() && !now.Before(b.ClaimNotAfter) {
		return 0, nil, nil
	}
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)

	dayCap, monthCap := b.AccountDayUSD, b.AccountMonthUSD
	var oDay, oMonth sql.NullFloat64
	err := tx.QueryRowContext(ctx,
		`SELECT managed_budget_usd_day, managed_budget_usd_month FROM agent_profiles WHERE user_id = $1`,
		userID).Scan(&oDay, &oMonth)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, nil, fmt.Errorf("read managed budget override: %w", err)
	}
	if oDay.Valid {
		dayCap = oDay.Float64
	}
	if oMonth.Valid {
		monthCap = oMonth.Float64
	}

	// Order matters for the pause decision: global day, account month, account day.
	windows := []budgetWindow{
		{scope: BudgetScopeGlobalDay, cap: b.GlobalDayUSD, end: dayStart.AddDate(0, 0, 1)},
		{scope: BudgetScopeAccountMonth, cap: monthCap, end: monthStart.AddDate(0, 1, 0)},
		{scope: BudgetScopeAccountDay, cap: dayCap, end: dayStart.AddDate(0, 0, 1)},
	}
	for i := range windows {
		since, uid := dayStart, int64(0)
		switch windows[i].scope {
		case BudgetScopeAccountMonth:
			since, uid = monthStart, userID
		case BudgetScopeAccountDay:
			uid = userID
		}
		if windows[i].durable, windows[i].inflight, err = usageSums(ctx, tx, since, uid); err != nil {
			return 0, nil, err
		}
	}

	room := limit
	for _, w := range windows {
		room = min(room, w.slots(b.PerJobUSD, true))
	}
	if room > 0 {
		return room, nil, nil
	}
	for _, w := range windows {
		if w.slots(b.PerJobUSD, false) < 1 {
			if err := s.pauseForBudget(ctx, tx, userID, w.scope, w.end, now); err != nil {
				return 0, nil, err
			}
			return 0, &budgetEvent{exhausted: true, scope: w.scope}, nil
		}
	}
	for _, w := range windows {
		if w.slots(b.PerJobUSD, true) < 1 {
			return 0, &budgetEvent{scope: w.scope}, nil
		}
	}
	return 0, nil, nil
}

// pauseForBudget stamps budget_paused_until = end on the exhausted account (or,
// for the global scope, on every managed account with a pending job) and
// queues one budget notification for each account whose pause actually moved
// forward, so there is one notification per account and window.
func (s *Store) pauseForBudget(ctx context.Context, tx *sql.Tx, userID int64, scope string, end, now time.Time) error {
	var ids []int64
	var err error
	if scope == BudgetScopeGlobalDay {
		ids, err = requeueTransition(ctx, tx,
			`UPDATE agent_profiles SET budget_paused_until = $1
			  WHERE runtime = 'managed'
			    AND (budget_paused_until IS NULL OR budget_paused_until < $1)
			    AND EXISTS (SELECT 1 FROM agent_jobs j WHERE j.user_id = agent_profiles.user_id AND j.status = $2)
			 RETURNING user_id`, end.UTC(), JobPending)
	} else {
		ids, err = requeueTransition(ctx, tx,
			`UPDATE agent_profiles SET budget_paused_until = $1
			  WHERE user_id = $2 AND (budget_paused_until IS NULL OR budget_paused_until < $1)
			 RETURNING user_id`, end.UTC(), userID)
	}
	if err != nil {
		return fmt.Errorf("pause for budget: %w", err)
	}
	for _, id := range ids {
		var body []byte
		if s.Crypt != nil {
			msg := fmt.Sprintf("Your assistant paused: the managed %s budget is used up. Messages stay queued and it resumes at %s UTC.",
				budgetScopeLabel(scope), end.UTC().Format("2006-01-02 15:04"))
			if body, err = s.Crypt.SealForUser([]byte(msg), id); err != nil {
				return fmt.Errorf("seal budget notification: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO owner_notifications(user_id, kind, action_id, body_encrypted, status)
			 VALUES($1,$2,NULL,$3,$4)`,
			id, NotificationBudget, body, NotificationPending); err != nil {
			return fmt.Errorf("queue budget notification: %w", err)
		}
	}
	return nil
}

func budgetScopeLabel(scope string) string {
	switch scope {
	case BudgetScopeAccountMonth:
		return "monthly"
	case BudgetScopeGlobalDay:
		return "daily platform"
	}
	return "daily"
}

// insertReservation records the reservation of one claimed managed job in the
// claim's transaction.
func (s *Store) insertReservation(ctx context.Context, tx *sql.Tx, j AgentJob) error {
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO agent_usage(job_id, attempt, user_id, runtime, reserved_usd, status, created_at, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$7)`,
		j.ID, j.Attempts, j.UserID, RuntimeManaged, s.budget.PerJobUSD, UsageReserved, s.budget.now()); err != nil {
		return fmt.Errorf("insert usage reservation: %w", err)
	}
	return nil
}

// RecordAgentJobUsage settles the usage row of one claim attempt and keeps
// agent_jobs.cost_usd at the last reported cost. The user, job and attempt
// are the claim's identity and the runtime is read from the job row; none of
// them comes from the report. A repeat with identical figures changes
// nothing; a repeat with different figures is ErrUsageConflict. A stale
// attempt is ErrAgentJobNotFound.
func (s *Store) RecordAgentJobUsage(ctx context.Context, userID, jobID int64, attempt int, u Usage) (UsageOutcome, error) {
	if userID <= 0 {
		return 0, errors.New("user id required")
	}
	now := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin usage tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	lock := ""
	if s.isPostgres(ctx) {
		lock = " FOR UPDATE"
	}
	var rt sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT runtime FROM agent_jobs WHERE id = $1 AND user_id = $2 AND attempts = $3`+lock,
		jobID, userID, attempt).Scan(&rt)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrAgentJobNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("select job for usage: %w", err)
	}
	runtime := RuntimeOwn
	if rt.Valid && rt.String == RuntimeManaged {
		runtime = RuntimeManaged
	}
	// Decided under the job row lock, so a pool claim cannot slip in between
	// a runtime check and the settle.
	if runtime == RuntimeManaged && !u.JobScoped {
		return 0, ErrUsageCredential
	}

	var (
		rowID                 int64
		status, runner, model string
		in, out               int64
		cost                  sql.NullFloat64
	)
	err = tx.QueryRowContext(ctx,
		`SELECT id, status, runner, model, input_tokens, output_tokens, cost_usd
		   FROM agent_usage WHERE job_id = $1 AND attempt = $2`, jobID, attempt,
	).Scan(&rowID, &status, &runner, &model, &in, &out, &cost)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx,
			`UPDATE agent_jobs SET cost_usd = $1, updated_at = $2 WHERE id = $3`, u.CostUSD, now, jobID); err != nil {
			return 0, fmt.Errorf("record agent job cost: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO agent_usage(job_id, attempt, user_id, runtime, runner, model, input_tokens, output_tokens,
			                         reserved_usd, cost_usd, status, created_at, updated_at, settled_at)
			 VALUES($1,$2,$3,$4,$5,$6,$7,$8,0,$9,$10,$11,$11,$11)`,
			jobID, attempt, userID, runtime, u.Runner, u.Model, u.InputTokens, u.OutputTokens,
			u.CostUSD, UsageSettled, now); err != nil {
			return 0, fmt.Errorf("insert settled usage: %w", err)
		}
	case err != nil:
		return 0, fmt.Errorf("select usage row: %w", err)
	case status == UsageSettled:
		if cost.Valid && cost.Float64 == u.CostUSD && model == u.Model && runner == u.Runner &&
			in == u.InputTokens && out == u.OutputTokens {
			return UsageUnchanged, nil
		}
		return 0, ErrUsageConflict
	default:
		if _, err := tx.ExecContext(ctx,
			`UPDATE agent_jobs SET cost_usd = $1, updated_at = $2 WHERE id = $3`, u.CostUSD, now, jobID); err != nil {
			return 0, fmt.Errorf("record agent job cost: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE agent_usage SET status = $1, cost_usd = $2, runner = $3, model = $4,
			        input_tokens = $5, output_tokens = $6, updated_at = $7, settled_at = $7
			  WHERE id = $8`,
			UsageSettled, u.CostUSD, u.Runner, u.Model, u.InputTokens, u.OutputTokens, now, rowID); err != nil {
			return 0, fmt.Errorf("settle usage: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit usage tx: %w", err)
	}
	return UsageRecorded, nil
}

// holdReservations moves the still-reserved rows of jobs whose attempt the
// sweeper just ended to held. Their token has left the server and the run may
// have spent up to the per-job cap, so the reservation keeps counting at the
// full per-job amount. A late cost report settles it only while the job's
// attempts still equal the row's attempt (RecordAgentJobUsage fences on the
// current attempt): once the job is re-claimed, the old attempt's report is
// refused and the row charges the full reservation until its window ends.
// That is deliberate: a pool job token expires at the same deadline the
// sweeper uses, so such a report would be refused with 401 anyway.
func holdReservations(ctx context.Context, tx *sql.Tx, ids []int64, now time.Time) error {
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx,
			`UPDATE agent_usage SET status = $1, updated_at = $2 WHERE job_id = $3 AND status = $4`,
			UsageHeld, now, id, UsageReserved); err != nil {
			return fmt.Errorf("hold usage reservation: %w", err)
		}
	}
	return nil
}

// reservationEndGrace is how long a reservation of an attempt that has
// already ended (completed, failed, retried or dead-lettered by the worker)
// stays reserved before the sweeper holds it. The worker reports cost right
// after the run, but the agent can close its job through a tool before that
// report lands; holding at once would turn a cents-sized run into a durable
// 0.50 and could pause the account until the window ends. After the grace a
// missing report is a missing report, and the row must count as durable so
// that exhaustion pauses and notifies instead of deferring silently.
const reservationEndGrace = 2 * time.Minute

// holdEndedReservations moves to held every still-reserved managed row whose
// attempt has ended (the job is no longer processing under that attempt) and
// whose job has not transitioned for reservationEndGrace. It runs in the
// sweeper's transaction after agent_jobs is locked, so it follows the same
// lock order as holdReservations. A late report still settles a held row
// while the job's attempts equal the row's attempt (RecordAgentJobUsage).
func holdEndedReservations(ctx context.Context, tx *sql.Tx, now time.Time) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE agent_usage SET status = $1, updated_at = $2
		  WHERE status = $3 AND runtime = 'managed'
		    AND EXISTS (
		        SELECT 1 FROM agent_jobs j
		         WHERE j.id = agent_usage.job_id
		           AND (j.status <> $4 OR j.attempts <> agent_usage.attempt)
		           AND j.updated_at < $5
		    )`,
		UsageHeld, now, UsageReserved, JobProcessing, now.Add(-reservationEndGrace)); err != nil {
		return fmt.Errorf("hold ended reservations: %w", err)
	}
	return nil
}

// HeldUsage reports the unsettled held reservations of the current UTC day:
// the reservation reconciliation drift.
func (s *Store) HeldUsage(ctx context.Context) (usd float64, rows int64, err error) {
	now := time.Now().UTC()
	if s.budget != nil {
		now = s.budget.now()
	}
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(reserved_usd), 0), COUNT(*) FROM agent_usage
		  WHERE status = $1 AND runtime = 'managed' AND created_at >= $2`,
		UsageHeld, dayStart).Scan(&usd, &rows); err != nil {
		return 0, 0, fmt.Errorf("held usage: %w", err)
	}
	return usd, rows, nil
}

// budgetCandidateFilter returns the SQL predicates and args ListManagedClaimCandidates
// adds when a budget is configured. start is the index of the first free placeholder.
func (s *Store) budgetCandidateFilter(now time.Time, start int) (string, []any) {
	if s.budget == nil {
		return "", nil
	}
	n := strconv.Itoa(start)
	m := strconv.Itoa(start + 1)
	o := strconv.Itoa(start + 2)
	p := strconv.Itoa(start + 3)
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return `AND (ap.budget_paused_until IS NULL OR ap.budget_paused_until <= $` + n + `)
		    AND (SELECT COALESCE(SUM(COALESCE(u.cost_usd, u.reserved_usd)), 0) FROM agent_usage u
		          WHERE u.runtime = 'managed' AND u.created_at >= $` + m + `) + $` + o + ` <= $` + p + ` + 1e-9`,
		[]any{now.UTC(), dayStart, s.budget.PerJobUSD, s.budget.GlobalDayUSD}
}
