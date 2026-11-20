package db

// pa_outbox.go is the Personal Assistant outbox (issue #1313 slice d2; see
// internal/pa/jobs/outbox.go for the rules). Rows are written in the
// transaction of the state change that owes the message and carry no
// message text: a notice is a kind, a reply names its sealed assistant
// fragment.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

var _ jobs.OutboxStore = (*Store)(nil)

// paOutboxTable is the pa_outbox DDL under name. job_id is NULL on a
// conversation-level row (#1348): NULLs are distinct under UNIQUE (job_id,
// kind), so those rows are keyed by idx_pa_outbox_update instead, while a
// job-level row keeps the (job, kind) key it always had.
func paOutboxTable(pg bool, name string) string {
	intT, idT := "INTEGER", "INTEGER PRIMARY KEY AUTOINCREMENT"
	if pg {
		intT, idT = "BIGINT", "BIGSERIAL PRIMARY KEY"
	}
	return `CREATE TABLE IF NOT EXISTS ` + name + ` (
			id ` + idT + `,
			principal ` + intT + ` NOT NULL,
			job_id ` + intT + `,
			update_id ` + intT + ` NOT NULL DEFAULT 0,
			kind TEXT NOT NULL,
			button TEXT NOT NULL DEFAULT '',
			conversation_id TEXT NOT NULL DEFAULT '',
			fragment_seq ` + intT + ` NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			attempts ` + intT + ` NOT NULL DEFAULT 0,
			sent_parts ` + intT + ` NOT NULL DEFAULT 0,
			next_at_ms ` + intT + ` NOT NULL,
			lease_until_ms ` + intT + ` NOT NULL DEFAULT 0,
			created_at_ms ` + intT + ` NOT NULL,
			updated_at_ms ` + intT + ` NOT NULL,
			UNIQUE (job_id, kind)
		)`
}

// paOutboxIndexes run after the table has every column.
var paOutboxIndexes = []string{
	`CREATE INDEX IF NOT EXISTS idx_pa_outbox_due ON pa_outbox(status, next_at_ms)`,
	`CREATE INDEX IF NOT EXISTS idx_pa_outbox_principal ON pa_outbox(principal, id)`,
	`CREATE UNIQUE INDEX IF NOT EXISTS idx_pa_outbox_update ON pa_outbox(principal, update_id, kind) WHERE job_id IS NULL`,
}

// migratePAOutbox creates pa_outbox, or brings a table created before #1348
// (job_id NOT NULL, no update_id or button) to the current shape. Rows
// already there are job-level and keep their key.
func migratePAOutbox(ctx context.Context, dbConn *sql.DB, pg bool) error {
	if _, err := dbConn.ExecContext(ctx, paOutboxTable(pg, "pa_outbox")); err != nil {
		return fmt.Errorf("migrate pa outbox: %w", err)
	}
	notNull, err := paOutboxJobIDNotNull(ctx, dbConn, pg)
	if err != nil {
		return err
	}
	if notNull {
		if pg {
			// Postgres drops the constraint in place; a replica that loses
			// the race runs the same statement again, which is a no-op.
			for _, q := range []string{
				`ALTER TABLE pa_outbox ADD COLUMN IF NOT EXISTS update_id BIGINT NOT NULL DEFAULT 0`,
				`ALTER TABLE pa_outbox ADD COLUMN IF NOT EXISTS button TEXT NOT NULL DEFAULT ''`,
				`ALTER TABLE pa_outbox ALTER COLUMN job_id DROP NOT NULL`,
			} {
				if _, err := dbConn.ExecContext(ctx, q); err != nil {
					return fmt.Errorf("migrate pa outbox: %w", err)
				}
			}
		} else if err := rebuildSQLitePAOutbox(ctx, dbConn); err != nil {
			return err
		}
	}
	for _, q := range paOutboxIndexes {
		if _, err := dbConn.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("migrate pa outbox: %w", err)
		}
	}
	return nil
}

// paOutboxJobIDNotNull reports whether pa_outbox.job_id still has the NOT
// NULL of the pre-#1348 table. A failed catalog read is an error, never
// "already migrated".
func paOutboxJobIDNotNull(ctx context.Context, dbConn *sql.DB, pg bool) (bool, error) {
	q := `SELECT "notnull" <> 0 FROM pragma_table_info('pa_outbox') WHERE name = 'job_id'`
	if pg {
		q = `SELECT attnotnull FROM pg_attribute
		      WHERE attrelid = to_regclass('pa_outbox') AND attname = 'job_id' AND attnum > 0 AND NOT attisdropped`
	}
	var notNull bool
	if err := dbConn.QueryRowContext(ctx, q).Scan(&notNull); err != nil {
		return false, fmt.Errorf("migrate pa outbox: read job_id: %w", err)
	}
	return notNull, nil
}

// rebuildSQLitePAOutbox copies a pre-#1348 SQLite pa_outbox into the
// current shape: SQLite cannot drop a NOT NULL in place. SQLite serves one
// process (local development), so nothing races the rebuild; it runs in
// one transaction, so a failure leaves the old table as it was.
func rebuildSQLitePAOutbox(ctx context.Context, dbConn *sql.DB) error {
	tx, err := dbConn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrate pa outbox: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	const cols = `id, principal, job_id, kind, conversation_id, fragment_seq, status, attempts, sent_parts,
		next_at_ms, lease_until_ms, created_at_ms, updated_at_ms`
	for _, q := range []string{
		`DROP TABLE IF EXISTS pa_outbox_rebuild`,
		paOutboxTable(false, "pa_outbox_rebuild"),
		`INSERT INTO pa_outbox_rebuild (` + cols + `) SELECT ` + cols + ` FROM pa_outbox`,
		`DROP TABLE pa_outbox`,
		`ALTER TABLE pa_outbox_rebuild RENAME TO pa_outbox`,
	} {
		if _, err := tx.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("migrate pa outbox: rebuild: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrate pa outbox: rebuild: commit: %w", err)
	}
	return nil
}

// enqueuePAOutbox inserts item in tx, once per (job, kind) for a job-level
// row and once per (principal, update, kind) for a conversation-level one.
func enqueuePAOutbox(ctx context.Context, tx *sql.Tx, item jobs.OutboxItem, nowMS int64) error {
	if tx == nil || !item.Valid() {
		return fmt.Errorf("%w: outbox item", jobs.ErrInvalid)
	}
	if item.Kind.ConversationLevel() {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO pa_outbox(principal, job_id, update_id, kind, button, status, attempts,
			                       next_at_ms, created_at_ms, updated_at_ms)
			 VALUES($1, NULL, $2, $3, $4, $5, 0, $6, $6, $6)
			 ON CONFLICT (principal, update_id, kind) WHERE job_id IS NULL DO NOTHING`,
			item.Principal, item.UpdateID, string(item.Kind), item.Button,
			string(jobs.OutboxPending), nowMS); err != nil {
			return fmt.Errorf("pa outbox: enqueue: %w", err)
		}
		return nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO pa_outbox(principal, job_id, kind, conversation_id, fragment_seq, status, attempts,
		                       next_at_ms, created_at_ms, updated_at_ms)
		 VALUES($1, $2, $3, $4, $5, $6, 0, $7, $7, $7)
		 ON CONFLICT (job_id, kind) DO NOTHING`,
		item.Principal, item.JobID, string(item.Kind), item.ConversationID, item.FragmentSeq,
		string(jobs.OutboxPending), nowMS); err != nil {
		return fmt.Errorf("pa outbox: enqueue: %w", err)
	}
	return nil
}

// enqueuePANotice records the message a Notice owes, in tx.
func enqueuePANotice(ctx context.Context, tx *sql.Tx, n jobs.Notice, nowMS int64) error {
	return enqueuePAOutbox(ctx, tx, jobs.OutboxItem{
		Principal: n.Principal, JobID: n.JobID, Kind: jobs.OutboxKindOf(n.Kind),
	}, nowMS)
}

// EnqueuePAOutbox implements jobs.OutboxStore.
func (s *Store) EnqueuePAOutbox(ctx context.Context, tx *sql.Tx, item jobs.OutboxItem, now time.Time) error {
	if now.IsZero() {
		return fmt.Errorf("%w: outbox time", jobs.ErrInvalid)
	}
	return enqueuePAOutbox(ctx, tx, item, now.UnixMilli())
}

// paOutboxColumns reads a conversation-level row's NULL job_id as 0.
const paOutboxColumns = `id, principal, COALESCE(job_id, 0), update_id, kind, button, conversation_id, fragment_seq,
	attempts, sent_parts, status, next_at_ms`

func scanPAOutbox(row interface{ Scan(...any) error }) (jobs.OutboxItem, error) {
	var it jobs.OutboxItem
	var kind, status string
	var nextMS int64
	if err := row.Scan(&it.ID, &it.Principal, &it.JobID, &it.UpdateID, &kind, &it.Button, &it.ConversationID, &it.FragmentSeq,
		&it.Attempts, &it.SentParts, &status, &nextMS); err != nil {
		return jobs.OutboxItem{}, err
	}
	// An unknown kind is handed to the deliverer as is: it refuses to send
	// it and fails the row, rather than the claim failing for every row.
	it.Kind, it.Status, it.NextAt = jobs.OutboxKind(kind), jobs.OutboxStatus(status), time.UnixMilli(nextMS).UTC()
	return it, nil
}

// ClaimPAOutbox implements jobs.OutboxStore.
func (s *Store) ClaimPAOutbox(ctx context.Context, req jobs.OutboxClaimRequest) (jobs.OutboxClaimResult, error) {
	if req.Now.IsZero() || req.Lease <= 0 || req.Limit <= 0 || req.Principal < 0 {
		return jobs.OutboxClaimResult{}, fmt.Errorf("%w: outbox claim", jobs.ErrInvalid)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return jobs.OutboxClaimResult{}, jobsStoreFault("outbox: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	nowMS := req.Now.UnixMilli()
	var res jobs.OutboxClaimResult
	// A row whose sending lease ran out may have reached Telegram: it is
	// never sent again (send-once), and it counts as unknown.
	r, err := tx.ExecContext(ctx,
		`UPDATE pa_outbox SET status = $1, lease_until_ms = 0, updated_at_ms = $2
		  WHERE status = $3 AND lease_until_ms <= $2`,
		string(jobs.OutboxUnknown), nowMS, string(jobs.OutboxSending))
	if err != nil {
		return jobs.OutboxClaimResult{}, jobsStoreFault("outbox: expire", err)
	}
	n, err := r.RowsAffected()
	if err != nil {
		return jobs.OutboxClaimResult{}, jobsStoreFault("outbox: expire count", err)
	}
	res.Unknown = int(n)
	// Per principal, only the oldest undelivered row is due, and none while
	// another row of the principal is sending: messages go out in order and
	// one principal's rows are never sent concurrently.
	q := `SELECT o.id FROM pa_outbox o
	  WHERE o.status = $1 AND o.next_at_ms <= $2
	    AND NOT EXISTS (SELECT 1 FROM pa_outbox e WHERE e.principal = o.principal
	                      AND ((e.id < o.id AND e.status = $1) OR e.status = $3))`
	args := []any{string(jobs.OutboxPending), nowMS, string(jobs.OutboxSending)}
	if req.Principal > 0 {
		args = append(args, req.Principal)
		q += fmt.Sprintf(" AND o.principal = $%d", len(args))
	}
	args = append(args, req.Limit)
	q += fmt.Sprintf(" ORDER BY o.id LIMIT $%d", len(args))
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return jobs.OutboxClaimResult{}, jobsStoreFault("outbox: due", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return jobs.OutboxClaimResult{}, jobsStoreFault("outbox: due scan", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return jobs.OutboxClaimResult{}, jobsStoreFault("outbox: due close", err)
	}
	if err := rows.Err(); err != nil {
		return jobs.OutboxClaimResult{}, jobsStoreFault("outbox: due rows", err)
	}
	if s.paOutboxAfterSelect != nil {
		s.paOutboxAfterSelect()
	}
	leaseMS := req.Now.Add(req.Lease).UnixMilli()
	for _, id := range ids {
		// Conditional on still pending: of two concurrent deliverers, one
		// claims the row and the other gets no row back.
		it, err := scanPAOutbox(tx.QueryRowContext(ctx,
			`UPDATE pa_outbox SET status = $1, attempts = attempts + 1, lease_until_ms = $2, updated_at_ms = $3
			  WHERE id = $4 AND status = $5 RETURNING `+paOutboxColumns,
			string(jobs.OutboxSending), leaseMS, nowMS, id, string(jobs.OutboxPending)))
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return jobs.OutboxClaimResult{}, jobsStoreFault("outbox: claim", err)
		}
		res.Items = append(res.Items, it)
	}
	if err := tx.Commit(); err != nil {
		return jobs.OutboxClaimResult{}, jobsStoreFault("outbox: commit", err)
	}
	return res, nil
}

// CompletePAOutbox implements jobs.OutboxStore.
func (s *Store) CompletePAOutbox(ctx context.Context, item jobs.OutboxItem, c jobs.OutboxCompletion) error {
	next := item.NextAt.UnixMilli()
	switch c.Status {
	case jobs.OutboxSent, jobs.OutboxFailed, jobs.OutboxDropped, jobs.OutboxUnknown:
	case jobs.OutboxPending:
		if c.RetryAt.IsZero() {
			return fmt.Errorf("%w: outbox retry without a time", jobs.ErrInvalid)
		}
		next = c.RetryAt.UnixMilli()
	default:
		return fmt.Errorf("%w: outbox completion %q", jobs.ErrInvalid, c.Status)
	}
	if item.ID <= 0 || item.Attempts <= 0 || c.Now.IsZero() {
		return fmt.Errorf("%w: outbox completion", jobs.ErrInvalid)
	}
	r, err := s.DB.ExecContext(ctx,
		`UPDATE pa_outbox SET status = $1, next_at_ms = $2, lease_until_ms = 0, updated_at_ms = $3
		  WHERE id = $4 AND status = $5 AND attempts = $6`,
		string(c.Status), next, c.Now.UnixMilli(), item.ID, string(jobs.OutboxSending), item.Attempts)
	if err != nil {
		return jobsStoreFault("outbox: complete", err)
	}
	n, err := r.RowsAffected()
	if err != nil {
		return jobsStoreFault("outbox: complete count", err)
	}
	if n != 1 {
		return jobs.ErrOutboxStale
	}
	return nil
}

// RecordPAOutboxParts implements jobs.OutboxStore. The count only grows,
// and only while the row is sending under this attempt.
func (s *Store) RecordPAOutboxParts(ctx context.Context, item jobs.OutboxItem, parts int, now time.Time) error {
	if item.ID <= 0 || item.Attempts <= 0 || parts <= 0 || now.IsZero() {
		return fmt.Errorf("%w: outbox parts", jobs.ErrInvalid)
	}
	r, err := s.DB.ExecContext(ctx,
		`UPDATE pa_outbox SET sent_parts = $1, updated_at_ms = $2
		  WHERE id = $3 AND status = $4 AND attempts = $5 AND sent_parts < $1`,
		parts, now.UnixMilli(), item.ID, string(jobs.OutboxSending), item.Attempts)
	if err != nil {
		return jobsStoreFault("outbox: parts", err)
	}
	n, err := r.RowsAffected()
	if err != nil {
		return jobsStoreFault("outbox: parts count", err)
	}
	if n != 1 {
		return jobs.ErrOutboxStale
	}
	return nil
}

// deletePAOutboxNotices deletes the principal's pending job notice rows in
// tx (/forget and consent withdrawal): a notice about a request the
// principal asked to forget is not sent afterwards. A pending reply stays,
// and is dropped when it comes due because its fragment is gone; a row that
// is sending is left to finish. Conversation-level rows stay too: they
// carry no conversation content, and the answer to the /forget or
// withdrawal itself is one of them.
func deletePAOutboxNotices(ctx context.Context, tx *sql.Tx, principal int64) error {
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM pa_outbox WHERE principal = $1 AND status = $2 AND kind <> $3 AND job_id IS NOT NULL`,
		principal, string(jobs.OutboxPending), string(jobs.OutboxReply)); err != nil {
		return fmt.Errorf("forget pa outbox notices: %w", err)
	}
	return nil
}

// PAOutboxRows returns every outbox row of principal, oldest first. For
// tests and operators; it is not on any request path.
func (s *Store) PAOutboxRows(ctx context.Context, principal int64) ([]jobs.OutboxItem, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT `+paOutboxColumns+` FROM pa_outbox WHERE principal = $1 ORDER BY id`, principal)
	if err != nil {
		return nil, jobsStoreFault("outbox rows", err)
	}
	defer rows.Close()
	var out []jobs.OutboxItem
	for rows.Next() {
		it, err := scanPAOutbox(rows)
		if err != nil {
			return nil, jobsStoreFault("outbox rows scan", err)
		}
		out = append(out, it)
	}
	if err := rows.Err(); err != nil {
		return nil, jobsStoreFault("outbox rows", err)
	}
	return out, nil
}
