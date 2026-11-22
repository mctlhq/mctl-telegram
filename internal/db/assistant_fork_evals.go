package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Fork eval runs (P4.3 S2, docs/assistants/adr-forks.md "Promotion (P4.3)").
// A run scores one fork version against one suite; its verdict is computed
// server-side by a caller-supplied scorer inside the transaction that
// finishes the last task, and every rate limit is enforced in the
// transaction that creates the run, so a refused request writes nothing.
//
// internal/agenteval imports this package, so the store cannot import it:
// ForkEvalBinding mirrors agenteval.RunBinding and the scorer is a callback.

// Run states.
const (
	ForkEvalQueued     = "queued"
	ForkEvalRunning    = "running"
	ForkEvalPassed     = "passed"
	ForkEvalFailed     = "failed"
	ForkEvalIncomplete = "incomplete"
	ForkEvalExpired    = "expired"
	ForkEvalCancelled  = "cancelled"
)

// Task states.
const (
	forkEvalTaskPending     = "pending"
	forkEvalTaskClaimed     = "claimed"
	forkEvalTaskDone        = "done"
	forkEvalTaskInfraFailed = "infra_failed"
)

const (
	// ForkEvalRunTTL is how long a run may stay queued or running.
	ForkEvalRunTTL = 24 * time.Hour

	forkEvalPerAccount24h   = 3
	forkEvalGlobal24h       = 20
	forkEvalScoredPerDigest = 2
	// forkEvalMaxAttempts is one claim plus one retry after a lease expires. An
	// explicit infraFailed finish marks the run incomplete with no retry.
	forkEvalMaxAttempts = 2

	// forkEvalScored is the one predicate for "this run has a verdict".
	forkEvalScored = `state IN ('passed','failed')`
)

var (
	ErrForkEvalRunOpen      = errors.New("eval_run_open")
	ErrForkEvalAccountLimit = errors.New("eval_account_limit")
	ErrForkEvalGlobalLimit  = errors.New("eval_global_limit")
	ErrForkEvalDigestPassed = errors.New("eval_digest_passed")
	ErrForkEvalDigestLimit  = errors.New("eval_digest_limit")
	ErrForkEvalNoTask       = errors.New("eval_no_task")
	ErrForkEvalTaskStale    = errors.New("eval_task_stale")
	ErrForkEvalRunNotFound  = errors.New("eval_run_not_found")
)

// ForkEvalBinding names what a run evaluates. It mirrors
// agenteval.RunBinding field for field.
type ForkEvalBinding struct {
	UserID         int64
	ForkDigest     string
	BaseDigest     string
	SuiteDigest    string
	HarnessVersion string
}

// ForkEvalRun is one stored run. Report is opaque bytes.
type ForkEvalRun struct {
	ID int64
	ForkEvalBinding
	State      string
	CreatedAt  time.Time
	FinishedAt *time.Time
	Report     []byte
}

// ForkEvalTask is one claimed task.
type ForkEvalTask struct {
	RunID     int64
	Binding   ForkEvalBinding
	FixtureID string
	Attempt   int
	Deadline  time.Time
}

// ForkEvalTaskResult is one finished task's opaque result.
type ForkEvalTaskResult struct {
	FixtureID string
	Result    []byte
}

// ForkEvalScorer computes the verdict of a run from all its task results,
// ordered by fixture sequence.
type ForkEvalScorer func(results []ForkEvalTaskResult) (passed bool, report []byte, err error)

func (b ForkEvalBinding) valid() bool {
	return b.UserID > 0 && b.ForkDigest != "" && b.BaseDigest != "" && b.SuiteDigest != "" && b.HarnessVersion != ""
}

// CreateForkEvalRun creates a queued run with one pending task per fixture
// id, under the account's fork lock, after checking the fork version exists
// and every limit. The first refusal returns its typed error and writes
// nothing.
func (s *Store) CreateForkEvalRun(ctx context.Context, b ForkEvalBinding, fixtureIDs []string, now time.Time) (int64, error) {
	if !b.valid() {
		return 0, errors.New("eval run binding incomplete")
	}
	if len(fixtureIDs) == 0 {
		return 0, errors.New("eval run needs at least one fixture")
	}
	seen := make(map[string]bool, len(fixtureIDs))
	for _, id := range fixtureIDs {
		if id == "" || seen[id] {
			return 0, errors.New("eval fixture ids must be non-empty and unique")
		}
		seen[id] = true
	}
	now = now.UTC()
	since := now.Add(-ForkEvalRunTTL)
	tx, err := s.beginForkTx(ctx, b.UserID)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	count := func(what, q string, args ...any) (int, error) {
		var n int
		if err := tx.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
			return 0, fmt.Errorf("count %s: %w", what, err)
		}
		return n, nil
	}
	var one int
	err = tx.QueryRowContext(ctx,
		`SELECT 1 FROM assistant_forks WHERE user_id = $1 AND digest = $2`,
		b.UserID, b.ForkDigest).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrAssistantForkNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("check assistant fork: %w", err)
	}
	n, err := count("open fork eval runs",
		`SELECT COUNT(*) FROM assistant_fork_eval_runs WHERE user_id = $1 AND state IN ('queued','running')`, b.UserID)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		return 0, ErrForkEvalRunOpen
	}
	if n, err = count("account fork eval runs",
		`SELECT COUNT(*) FROM assistant_fork_eval_runs WHERE user_id = $1 AND created_at > $2`, b.UserID, since); err != nil {
		return 0, err
	}
	if n >= forkEvalPerAccount24h {
		return 0, ErrForkEvalAccountLimit
	}
	if n, err = count("global fork eval runs",
		`SELECT COUNT(*) FROM assistant_fork_eval_runs WHERE created_at > $1`, since); err != nil {
		return 0, err
	}
	if n >= forkEvalGlobal24h {
		return 0, ErrForkEvalGlobalLimit
	}
	var passed, scored int
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(CASE WHEN state = 'passed' THEN 1 ELSE 0 END), 0),
		        COALESCE(SUM(CASE WHEN `+forkEvalScored+` THEN 1 ELSE 0 END), 0)
		   FROM assistant_fork_eval_runs WHERE user_id = $1 AND fork_digest = $2`,
		b.UserID, b.ForkDigest).Scan(&passed, &scored); err != nil {
		return 0, fmt.Errorf("count scored fork eval runs: %w", err)
	}
	if passed > 0 {
		return 0, ErrForkEvalDigestPassed
	}
	if scored >= forkEvalScoredPerDigest {
		return 0, ErrForkEvalDigestLimit
	}

	var runID int64
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO assistant_fork_eval_runs(user_id, fork_digest, base_digest, suite_digest, harness_version, state, created_at)
		 VALUES ($1, $2, $3, $4, $5, 'queued', $6) RETURNING id`,
		b.UserID, b.ForkDigest, b.BaseDigest, b.SuiteDigest, b.HarnessVersion, now).Scan(&runID); err != nil {
		return 0, fmt.Errorf("insert fork eval run: %w", err)
	}
	for i, id := range fixtureIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO assistant_fork_eval_tasks(run_id, fixture_id, seq, state) VALUES ($1, $2, $3, 'pending')`,
			runID, id, i); err != nil {
			return 0, fmt.Errorf("insert fork eval task: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit fork eval run: %w", err)
	}
	return runID, nil
}

// ClaimForkEvalTask atomically claims the oldest claimable task of an open
// run and leases it for lease. userID > 0 restricts the claim to that
// account; userID == 0 claims for any account (the pool credential). A task
// whose lease passed at attempt 1 is offered again at attempt 2; one whose
// lease passed at attempt 2 makes its run incomplete. ErrForkEvalNoTask when
// nothing is claimable.
func (s *Store) ClaimForkEvalTask(ctx context.Context, userID int64, now time.Time, lease time.Duration) (*ForkEvalTask, error) {
	if userID < 0 {
		return nil, errors.New("user id invalid")
	}
	now = now.UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin fork eval claim: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	scope, scopeArgs := ``, []any{}
	if userID > 0 {
		scope = ` AND user_id = $4`
		scopeArgs = []any{userID}
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE assistant_fork_eval_runs SET state = 'incomplete', finished_at = $1
		  WHERE state = 'running'`+scope+`
		    AND id IN (SELECT run_id FROM assistant_fork_eval_tasks
		                WHERE state = 'claimed' AND deadline <= $2 AND attempt >= $3)`,
		append([]any{now, now, forkEvalMaxAttempts}, scopeArgs...)...); err != nil {
		return nil, fmt.Errorf("expire fork eval tasks: %w", err)
	}

	rscope := ``
	if userID > 0 {
		rscope = ` AND r.user_id = $4`
	}
	var (
		t         ForkEvalTask
		taskState string
		oldAtt    int
		runState  string
	)
	err = tx.QueryRowContext(ctx,
		`SELECT t.run_id, t.fixture_id, t.state, t.attempt, r.state,
		        r.user_id, r.fork_digest, r.base_digest, r.suite_digest, r.harness_version
		   FROM assistant_fork_eval_tasks t
		   JOIN assistant_fork_eval_runs r ON r.id = t.run_id
		  WHERE r.state IN ('queued','running') AND r.created_at > $1
		    AND (t.state = 'pending'
		         OR (t.state = 'claimed' AND t.deadline <= $2 AND t.attempt < $3))`+rscope+`
		  ORDER BY r.created_at, r.id, t.seq LIMIT 1`,
		append([]any{now.Add(-ForkEvalRunTTL), now, forkEvalMaxAttempts}, scopeArgs...)...).Scan(
		&t.RunID, &t.FixtureID, &taskState, &oldAtt, &runState,
		&t.Binding.UserID, &t.Binding.ForkDigest, &t.Binding.BaseDigest, &t.Binding.SuiteDigest, &t.Binding.HarnessVersion)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return nil, fmt.Errorf("commit fork eval claim: %w", err)
		}
		return nil, ErrForkEvalNoTask
	}
	if err != nil {
		return nil, fmt.Errorf("select fork eval task: %w", err)
	}
	t.Attempt = oldAtt + 1
	t.Deadline = now.Add(lease)
	res, err := tx.ExecContext(ctx,
		`UPDATE assistant_fork_eval_tasks SET state = 'claimed', attempt = attempt + 1, deadline = $1
		  WHERE run_id = $2 AND fixture_id = $3 AND state = $4 AND attempt = $5`,
		t.Deadline, t.RunID, t.FixtureID, taskState, oldAtt)
	if err != nil {
		return nil, fmt.Errorf("claim fork eval task: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// A concurrent claim won; the caller polls again.
		return nil, ErrForkEvalNoTask
	}
	if runState == ForkEvalQueued {
		if _, err := tx.ExecContext(ctx,
			`UPDATE assistant_fork_eval_runs SET state = 'running' WHERE id = $1 AND state = 'queued'`, t.RunID); err != nil {
			return nil, fmt.Errorf("start fork eval run: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit fork eval claim: %w", err)
	}
	return &t, nil
}

// FinishForkEvalTask records the outcome of a claimed task. result is stored
// as given and is opaque to the store: the caller must pass only fixture id,
// category, action, flags, leak-marker ids and cost, never model output text.
// When it records the last unfinished task of the run, score is called over
// all results and the run becomes passed or failed with the report, in the
// same transaction; the verdict comes only from score. infraFailed marks the
// task infra_failed and the run incomplete. A task not claimed at attempt, or
// a run not running, is ErrForkEvalTaskStale and nothing is written. A scorer
// error rolls everything back. userID > 0 restricts the finish to that
// account's run, as in ClaimForkEvalTask (0 is the pool); a foreign run is
// ErrForkEvalTaskStale. A run past ForkEvalRunTTL is stale too, so the TTL
// means the same thing as at claim time. It returns the run's state after the call.
func (s *Store) FinishForkEvalTask(ctx context.Context, userID, runID int64, fixtureID string, attempt int, infraFailed bool, result []byte, score ForkEvalScorer, now time.Time) (string, error) {
	if userID < 0 {
		return "", errors.New("user id invalid")
	}
	if !infraFailed && score == nil {
		return "", errors.New("scorer required")
	}
	now = now.UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin fork eval finish: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The no-op write takes the run's row lock, so two finishers of one run
	// serialize and the last one sees every other task done.
	lockArgs := []any{runID, now.Add(-ForkEvalRunTTL)}
	lockScope := ``
	if userID > 0 {
		lockScope = ` AND user_id = $3`
		lockArgs = append(lockArgs, userID)
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE assistant_fork_eval_runs SET state = state
		  WHERE id = $1 AND state = 'running' AND created_at > $2`+lockScope, lockArgs...)
	if err != nil {
		return "", fmt.Errorf("lock fork eval run: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrForkEvalTaskStale
	}
	taskState := forkEvalTaskDone
	if infraFailed {
		taskState = forkEvalTaskInfraFailed
		result = nil
	}
	res, err = tx.ExecContext(ctx,
		`UPDATE assistant_fork_eval_tasks SET state = $1, result_json = $2
		  WHERE run_id = $3 AND fixture_id = $4 AND state = 'claimed' AND attempt = $5`,
		taskState, result, runID, fixtureID, attempt)
	if err != nil {
		return "", fmt.Errorf("finish fork eval task: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrForkEvalTaskStale
	}
	state := ForkEvalRunning
	if infraFailed {
		state = ForkEvalIncomplete
		if _, err := tx.ExecContext(ctx,
			`UPDATE assistant_fork_eval_runs SET state = 'incomplete', finished_at = $1 WHERE id = $2`, now, runID); err != nil {
			return "", fmt.Errorf("mark fork eval run incomplete: %w", err)
		}
	} else {
		var left int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM assistant_fork_eval_tasks WHERE run_id = $1 AND state <> 'done'`, runID).Scan(&left); err != nil {
			return "", fmt.Errorf("count unfinished fork eval tasks: %w", err)
		}
		if left == 0 {
			results, err := forkEvalResults(ctx, tx, runID)
			if err != nil {
				return "", err
			}
			passed, report, err := score(results)
			if err != nil {
				return "", fmt.Errorf("score fork eval run: %w", err)
			}
			state = ForkEvalFailed
			if passed {
				state = ForkEvalPassed
			}
			if _, err := tx.ExecContext(ctx,
				`UPDATE assistant_fork_eval_runs SET state = $1, report_json = $2, finished_at = $3 WHERE id = $4`,
				state, report, now, runID); err != nil {
				return "", fmt.Errorf("store fork eval verdict: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit fork eval finish: %w", err)
	}
	return state, nil
}

func forkEvalResults(ctx context.Context, tx *sql.Tx, runID int64) ([]ForkEvalTaskResult, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT fixture_id, result_json FROM assistant_fork_eval_tasks WHERE run_id = $1 ORDER BY seq`, runID)
	if err != nil {
		return nil, fmt.Errorf("load fork eval results: %w", err)
	}
	defer rows.Close()
	var out []ForkEvalTaskResult
	for rows.Next() {
		var r ForkEvalTaskResult
		if err := rows.Scan(&r.FixtureID, &r.Result); err != nil {
			return nil, fmt.Errorf("scan fork eval result: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load fork eval results: %w", err)
	}
	return out, nil
}

// LatestScoredForkEvalRun returns the newest passed or failed run of the
// account's fork digest, or ErrForkEvalRunNotFound. Runs without a verdict
// are never returned.
func (s *Store) LatestScoredForkEvalRun(ctx context.Context, userID int64, digest string) (*ForkEvalRun, error) {
	var (
		r        ForkEvalRun
		finished sql.NullTime
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, user_id, fork_digest, base_digest, suite_digest, harness_version, state, created_at, finished_at, report_json
		   FROM assistant_fork_eval_runs
		  WHERE user_id = $1 AND fork_digest = $2 AND `+forkEvalScored+`
		  ORDER BY created_at DESC, id DESC LIMIT 1`, userID, digest).Scan(
		&r.ID, &r.UserID, &r.ForkDigest, &r.BaseDigest, &r.SuiteDigest, &r.HarnessVersion,
		&r.State, &r.CreatedAt, &finished, &r.Report)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrForkEvalRunNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load scored fork eval run: %w", err)
	}
	if finished.Valid {
		t := finished.Time
		r.FinishedAt = &t
	}
	return &r, nil
}

// ExpireForkEvalRuns sets every queued or running run created at or before
// now-ForkEvalRunTTL to expired and returns how many.
func (s *Store) ExpireForkEvalRuns(ctx context.Context, now time.Time) (int64, error) {
	now = now.UTC()
	res, err := s.DB.ExecContext(ctx,
		`UPDATE assistant_fork_eval_runs SET state = 'expired', finished_at = $1
		  WHERE state IN ('queued','running') AND created_at <= $2`, now, now.Add(-ForkEvalRunTTL))
	if err != nil {
		return 0, fmt.Errorf("expire fork eval runs: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
