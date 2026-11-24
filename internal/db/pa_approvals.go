package db

// pa_approvals.go is the Personal Assistant's durable approval and dispatch
// ledger (#1320 slice P2-S2; threat model T2 "Execution-time check and
// dispatch", T7). It implements approval.Store; the state machine is
// described in package approval.
//
// Every lookup is keyed by (principal, id) (I10). A failed read wraps
// approval.ErrUnreadable and is never "no approval", "expired" or an empty
// result (I9). The sealed arguments leave a row in the statement set that
// ends pending/approved; after that a row holds hashes and ids only.
//
// Nothing in the running service calls these methods yet. What does run is
// the retention: SweepPAState, ClosePAConversations, ForgetPAConversations
// and the account purge act on the (empty) tables.
//
// Timestamps are unix milliseconds, as in pa_connections.go.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

var _ approval.Store = (*Store)(nil)

// paApprovalsSchema returns the DDL of the ledger.
//
//   - pa_approvals: one row per approval card. sealed_args is NULL once the
//     approval left pending/approved. idempotency_key is unique, and is
//     copied to the dispatch the receipt pays for.
//   - pa_dispatches: one row per call that was, or is about to be, sent.
//     The unique idempotency_key is a second barrier behind the receipt
//     compare-and-set: one approval can never own two dispatch records.
func paApprovalsSchema(pg bool) []string {
	intT, blobT := "INTEGER", "BLOB"
	if pg {
		intT, blobT = "BIGINT", "BYTEA"
	}
	return []string{
		`CREATE TABLE IF NOT EXISTS pa_approvals (
			principal ` + intT + ` NOT NULL,
			id TEXT NOT NULL,
			approve_cb_id TEXT NOT NULL,
			cancel_cb_id TEXT NOT NULL,
			connection_id TEXT NOT NULL,
			authority_revision ` + intT + ` NOT NULL,
			server TEXT NOT NULL,
			tool TEXT NOT NULL,
			class TEXT NOT NULL,
			schema_sha TEXT NOT NULL,
			description_sha TEXT NOT NULL,
			annotation_sha TEXT NOT NULL,
			args_sha TEXT NOT NULL,
			sealed_args ` + blobT + `,
			conversation_id TEXT NOT NULL,
			job_id ` + intT + ` NOT NULL DEFAULT 0,
			idempotency_key TEXT NOT NULL,
			status TEXT NOT NULL,
			approver ` + intT + ` NOT NULL DEFAULT 0,
			created_at_ms ` + intT + ` NOT NULL,
			expires_at_ms ` + intT + ` NOT NULL,
			updated_at_ms ` + intT + ` NOT NULL,
			finished_at_ms ` + intT + ` NOT NULL DEFAULT 0,
			PRIMARY KEY (principal, id)
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_pa_approvals_idempotency ON pa_approvals(idempotency_key)`,
		`CREATE INDEX IF NOT EXISTS idx_pa_approvals_connection ON pa_approvals(principal, connection_id, status)`,
		`CREATE INDEX IF NOT EXISTS idx_pa_approvals_expiry ON pa_approvals(status, expires_at_ms)`,
		`CREATE TABLE IF NOT EXISTS pa_dispatches (
			principal ` + intT + ` NOT NULL,
			id TEXT NOT NULL,
			approval_id TEXT NOT NULL DEFAULT '',
			connection_id TEXT NOT NULL,
			authority_revision ` + intT + ` NOT NULL,
			server TEXT NOT NULL,
			tool TEXT NOT NULL,
			args_sha TEXT NOT NULL,
			idempotency_key TEXT NOT NULL,
			status TEXT NOT NULL,
			lease_until_ms ` + intT + ` NOT NULL DEFAULT 0,
			created_at_ms ` + intT + ` NOT NULL,
			updated_at_ms ` + intT + ` NOT NULL,
			finished_at_ms ` + intT + ` NOT NULL DEFAULT 0,
			PRIMARY KEY (principal, id)
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_pa_dispatches_idempotency ON pa_dispatches(idempotency_key)`,
		`CREATE INDEX IF NOT EXISTS idx_pa_dispatches_lease ON pa_dispatches(status, lease_until_ms)`,
	}
}

func migratePAApprovals(ctx context.Context, dbConn migrateDB, pg bool) error {
	for _, s := range paApprovalsSchema(pg) {
		if _, err := dbConn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate pa approvals: %w", err)
		}
	}
	return nil
}

func approvalUnreadable(op string, err error) error {
	return fmt.Errorf("%w: %s: %v", approval.ErrUnreadable, op, err)
}

// paApprovalCols never includes sealed_args: only the consume returns it.
const paApprovalCols = `principal, id, approve_cb_id, cancel_cb_id, connection_id, authority_revision,
	server, tool, class, schema_sha, description_sha, annotation_sha, args_sha, conversation_id, job_id,
	idempotency_key, status, approver, created_at_ms, expires_at_ms, finished_at_ms`

// scanPAApproval reads one row. sealed, when not nil, receives the
// sealed_args column that the caller appended to paApprovalCols. A status
// or class this build does not know is unreadable, never "some state that
// is not approved" (I9).
func scanPAApproval(r paRowScanner, sealed *[]byte) (approval.Approval, error) {
	var (
		a                        approval.Approval
		class, status            string
		createdMS, expMS, doneMS int64
	)
	dest := []any{&a.Principal, &a.ID, &a.ApproveCallbackID, &a.CancelCallbackID, &a.ConnectionID, &a.AuthorityRevision,
		&a.Server, &a.Tool, &class, &a.SchemaSHA, &a.DescriptionSHA, &a.AnnotationSHA, &a.ArgsSHA, &a.ConversationID, &a.JobID,
		&a.IdempotencyKey, &status, &a.Approver, &createdMS, &expMS, &doneMS}
	if sealed != nil {
		dest = append(dest, sealed)
	}
	if err := r.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return approval.Approval{}, approval.ErrNotFound
		}
		return approval.Approval{}, approvalUnreadable("scan approval", err)
	}
	a.Class, a.Status = catalog.Class(class), approval.Status(status)
	if !a.Status.Valid() || a.Validate() != nil || a.ID == "" || a.IdempotencyKey == "" {
		return approval.Approval{}, fmt.Errorf("%w: approval row has an invalid status or binding", approval.ErrUnreadable)
	}
	a.CreatedAt, a.ExpiresAt = time.UnixMilli(createdMS).UTC(), time.UnixMilli(expMS).UTC()
	if doneMS > 0 {
		a.FinishedAt = time.UnixMilli(doneMS).UTC()
	}
	return a, nil
}

const paDispatchCols = `principal, id, approval_id, connection_id, authority_revision, server, tool, args_sha,
	idempotency_key, status, lease_until_ms, created_at_ms, finished_at_ms`

func scanPADispatch(r paRowScanner) (approval.Dispatch, error) {
	var (
		d                          approval.Dispatch
		status                     string
		leaseMS, createdMS, doneMS int64
	)
	if err := r.Scan(&d.Principal, &d.ID, &d.ApprovalID, &d.ConnectionID, &d.AuthorityRevision, &d.Server, &d.Tool,
		&d.ArgsSHA, &d.IdempotencyKey, &status, &leaseMS, &createdMS, &doneMS); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return approval.Dispatch{}, approval.ErrNotFound
		}
		return approval.Dispatch{}, approvalUnreadable("scan dispatch", err)
	}
	d.Status = approval.DispatchStatus(status)
	if !d.Status.Valid() || d.Principal <= 0 || d.ID == "" || d.IdempotencyKey == "" {
		return approval.Dispatch{}, fmt.Errorf("%w: dispatch row has an invalid status or key", approval.ErrUnreadable)
	}
	d.CreatedAt = time.UnixMilli(createdMS).UTC()
	if leaseMS > 0 {
		d.LeaseUntil = time.UnixMilli(leaseMS).UTC()
	}
	if doneMS > 0 {
		d.FinishedAt = time.UnixMilli(doneMS).UTC()
	}
	return d, nil
}

// CreatePAApproval implements approval.Store. The row is inserted from the
// principal's own open conversation and active connection rows, so an
// approval for a conversation or connection that is not theirs, closed,
// expired, not active or at another revision inserts nothing.
func (s *Store) CreatePAApproval(ctx context.Context, tx *sql.Tx, a approval.Approval) error {
	if tx == nil || a.ID == "" || a.ApproveCallbackID == "" || a.CancelCallbackID == "" ||
		a.ApproveCallbackID == a.CancelCallbackID || a.IdempotencyKey == "" || len(a.SealedArgs) == 0 ||
		a.CreatedAt.IsZero() || a.Status != approval.StatusPending {
		return fmt.Errorf("%w: create approval", approval.ErrInvalid)
	}
	if err := a.Validate(); err != nil {
		return err
	}
	createdMS := a.CreatedAt.UnixMilli()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO pa_approvals(principal, id, approve_cb_id, cancel_cb_id, connection_id, authority_revision,
			server, tool, class, schema_sha, description_sha, annotation_sha, args_sha, sealed_args,
			conversation_id, job_id, idempotency_key, status, approver, created_at_ms, expires_at_ms, updated_at_ms)
		 SELECT cv.principal, $1, $2, $3, cn.id, cn.authority_revision,
			$4, $5, $6, $7, $8, $9, $10, $11,
			cv.id, $12, $13, $14, 0, $15, $16, $17
		 FROM pa_conversations cv JOIN pa_connections cn ON cn.principal = cv.principal
		 WHERE cv.principal = $18 AND cv.id = $19 AND cv.closed_at_ms = 0 AND cv.expires_at_ms > $20
		   AND cn.id = $21 AND cn.state = $22 AND cn.authority_revision = $23 AND cn.server = $24`,
		a.ID, a.ApproveCallbackID, a.CancelCallbackID,
		a.Server, a.Tool, string(a.Class), a.SchemaSHA, a.DescriptionSHA, a.AnnotationSHA, a.ArgsSHA, a.SealedArgs,
		a.JobID, a.IdempotencyKey, string(approval.StatusPending), createdMS, a.CreatedAt.Add(approval.TTL).UnixMilli(), createdMS,
		a.Principal, a.ConversationID, createdMS,
		a.ConnectionID, string(connection.StateActive), a.AuthorityRevision, a.Server)
	if err != nil {
		return fmt.Errorf("create pa approval: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return approvalUnreadable("create approval: rows affected", err)
	}
	if n != 1 {
		return fmt.Errorf("%w: conversation %s or connection %s", approval.ErrBinding, a.ConversationID, a.ConnectionID)
	}
	return nil
}

// GetPAApproval implements approval.Store.
func (s *Store) GetPAApproval(ctx context.Context, tx *sql.Tx, principal int64, id string) (approval.Approval, error) {
	if tx == nil || principal <= 0 || id == "" {
		return approval.Approval{}, fmt.Errorf("%w: get approval", approval.ErrInvalid)
	}
	return scanPAApproval(tx.QueryRowContext(ctx,
		`SELECT `+paApprovalCols+` FROM pa_approvals WHERE principal = $1 AND id = $2`, principal, id), nil)
}

// LookupPAApprovalByCallback implements approval.Store.
func (s *Store) LookupPAApprovalByCallback(ctx context.Context, tx *sql.Tx, principal int64, callbackID string) (approval.Approval, error) {
	if tx == nil || principal <= 0 || callbackID == "" {
		return approval.Approval{}, fmt.Errorf("%w: approval by callback", approval.ErrInvalid)
	}
	return scanPAApproval(tx.QueryRowContext(ctx,
		`SELECT `+paApprovalCols+` FROM pa_approvals
		 WHERE principal = $1 AND (approve_cb_id = $2 OR cancel_cb_id = $3)`, principal, callbackID, callbackID), nil)
}

// paApprovalRefusal names why a compare-and-set of principal's approval id
// matched no row. It reads the row the statement would have changed; when
// that read fails, or shows nothing that explains the miss, the answer is
// ErrUnreadable, never a guess. consume adds the checks only the receipt
// compare-and-set makes: the connection and the conversation.
func (s *Store) paApprovalRefusal(ctx context.Context, tx *sql.Tx, principal int64, id string, nowMS int64, consume bool) error {
	a, err := s.GetPAApproval(ctx, tx, principal, id)
	if err != nil {
		return err
	}
	switch a.Status {
	case approval.StatusDispatching, approval.StatusDone:
		return approval.ErrConsumed
	case approval.StatusCancelled:
		return approval.ErrCancelled
	case approval.StatusRefused:
		return approval.ErrRefused
	case approval.StatusExpired:
		return approval.ErrExpired
	}
	if a.ExpiresAt.UnixMilli() <= nowMS {
		return approval.ErrExpired
	}
	if !consume {
		if a.Status == approval.StatusApproved {
			return approval.ErrAlreadyApproved
		}
		return fmt.Errorf("%w: approval %s was not changed for a reason that could not be read", approval.ErrUnreadable, id)
	}
	if a.Status == approval.StatusPending {
		return approval.ErrNotApproved
	}
	c, err := getPAConn(ctx, tx, principal, a.ConnectionID, nil)
	switch {
	case errors.Is(err, connection.ErrNotFound):
		return approval.ErrAuthorityChanged
	case err != nil:
		return approvalUnreadable("consume: connection", err)
	case c.State != connection.StateActive || c.AuthorityRevision != a.AuthorityRevision:
		return approval.ErrAuthorityChanged
	}
	var open int
	err = tx.QueryRowContext(ctx,
		`SELECT 1 FROM pa_conversations WHERE principal = $1 AND id = $2 AND closed_at_ms = 0 AND expires_at_ms > $3`,
		principal, a.ConversationID, nowMS).Scan(&open)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return approval.ErrConversationClosed
	case err != nil:
		return approvalUnreadable("consume: conversation", err)
	}
	return fmt.Errorf("%w: approval %s was not consumed for a reason that could not be read", approval.ErrUnreadable, id)
}

// deletePAApprovalCallbacks deletes the Approve and Cancel callbacks of
// the principal's approvals matched by where (a predicate over
// pa_approvals, with $1 the principal and args from $2 on). It runs before
// the statement that changes or deletes those approvals.
func deletePAApprovalCallbacks(ctx context.Context, tx *sql.Tx, principal int64, where string, args ...any) error {
	all := append([]any{principal}, args...)
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM pa_callbacks WHERE principal = $1 AND (
			id IN (SELECT approve_cb_id FROM pa_approvals WHERE principal = $1 AND `+where+`)
			OR id IN (SELECT cancel_cb_id FROM pa_approvals WHERE principal = $1 AND `+where+`))`, all...); err != nil {
		return fmt.Errorf("pa approval callbacks: %w", err)
	}
	return nil
}

// ApprovePAApproval implements approval.Store.
func (s *Store) ApprovePAApproval(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) (approval.Approval, error) {
	if tx == nil || principal <= 0 || id == "" || now.IsZero() {
		return approval.Approval{}, fmt.Errorf("%w: approve", approval.ErrInvalid)
	}
	nowMS := now.UnixMilli()
	a, err := scanPAApproval(tx.QueryRowContext(ctx,
		`UPDATE pa_approvals SET status = $1, approver = principal, updated_at_ms = $2
		 WHERE principal = $3 AND id = $4 AND status = $5 AND expires_at_ms > $2
		 RETURNING `+paApprovalCols,
		string(approval.StatusApproved), nowMS, principal, id, string(approval.StatusPending)), nil)
	if errors.Is(err, approval.ErrNotFound) {
		return approval.Approval{}, s.paApprovalRefusal(ctx, tx, principal, id, nowMS, false)
	}
	if err != nil {
		return approval.Approval{}, err
	}
	if err := deletePAApprovalCallbacks(ctx, tx, principal, `id = $2`, id); err != nil {
		return approval.Approval{}, err
	}
	return a, nil
}

// endPAApproval moves one pending or approved approval to a state that
// ends it without a dispatch, erasing its arguments in the same statement.
func (s *Store) endPAApproval(ctx context.Context, tx *sql.Tx, principal int64, id string, to approval.Status, now time.Time) (approval.Approval, error) {
	if tx == nil || principal <= 0 || id == "" || now.IsZero() {
		return approval.Approval{}, fmt.Errorf("%w: end approval", approval.ErrInvalid)
	}
	nowMS := now.UnixMilli()
	if err := deletePAApprovalCallbacks(ctx, tx, principal, `id = $2`, id); err != nil {
		return approval.Approval{}, err
	}
	a, err := scanPAApproval(tx.QueryRowContext(ctx,
		`UPDATE pa_approvals SET status = $1, sealed_args = NULL, finished_at_ms = $2, updated_at_ms = $2
		 WHERE principal = $3 AND id = $4 AND status IN ($5, $6)
		 RETURNING `+paApprovalCols,
		string(to), nowMS, principal, id, string(approval.StatusPending), string(approval.StatusApproved)), nil)
	if errors.Is(err, approval.ErrNotFound) {
		// The statement has no expiry predicate: a card past its five
		// minutes that the sweep has not reached is cancelled like any other.
		return approval.Approval{}, s.paApprovalRefusal(ctx, tx, principal, id, nowMS, false)
	}
	return a, err
}

// CancelPAApproval implements approval.Store.
func (s *Store) CancelPAApproval(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) (approval.Approval, error) {
	return s.endPAApproval(ctx, tx, principal, id, approval.StatusCancelled, now)
}

// RefusePAApproval implements approval.Store.
func (s *Store) RefusePAApproval(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) (approval.Approval, error) {
	return s.endPAApproval(ctx, tx, principal, id, approval.StatusRefused, now)
}

// cancelPAApprovals cancels every pending or approved approval of
// principal, or only those bound to connectionID when it is not empty,
// erasing their arguments and deleting their callbacks, and returns the
// ids it cancelled. A consumed receipt is left as it is: a call on the
// wire is ended by its executor's post-dispatch check (fenced) or by the
// stale sweep (outcome_unknown), never by a cancel.
func cancelPAApprovals(ctx context.Context, tx *sql.Tx, principal, nowMS int64, connectionID string) ([]string, error) {
	where := `status IN ('pending', 'approved') AND ($2 = '' OR connection_id = $2)`
	if err := deletePAApprovalCallbacks(ctx, tx, principal, where, connectionID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx,
		`UPDATE pa_approvals SET status = 'cancelled', sealed_args = NULL, finished_at_ms = $3, updated_at_ms = $3
		 WHERE principal = $1 AND `+where+` RETURNING id`, principal, connectionID, nowMS)
	if err != nil {
		return nil, fmt.Errorf("cancel pa approvals: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, approvalUnreadable("cancel approvals: scan", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return nil, approvalUnreadable("cancel approvals: close", err)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cancel pa approvals: %w", err)
	}
	return ids, nil
}

// cancelPAApprovalsWithNotice is cancelPAApprovals for a change the
// principal did not make card by card: a connection that ended, a consent
// withdrawal, /forget, an admin disable (#1320 slice P2-S12, S2-C9). When
// it cancelled anything it queues, in tx, one jobs.OutboxActionsCancelled
// notice for all of it, keyed on the smallest cancelled id: the outbox
// holds one approval-level row per approval, so that approval can get no
// second report, and the executor reports nothing for an approval somebody
// else ended. When nothing was cancelled nothing is queued.
//
// Any failure fails tx: the caller's change (the revocation, the
// withdrawal, the disable) does not commit without the cancellation, nor
// the cancellation without its notice.
func cancelPAApprovalsWithNotice(ctx context.Context, tx *sql.Tx, principal, nowMS int64, connectionID string) (int64, error) {
	ids, err := cancelPAApprovals(ctx, tx, principal, nowMS, connectionID)
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	if err := enqueuePAOutbox(ctx, tx, jobs.OutboxItem{
		Principal: principal, Kind: jobs.OutboxActionsCancelled, ApprovalID: slices.Min(ids),
	}, nowMS); err != nil {
		return 0, fmt.Errorf("cancel pa approvals: notice: %w", err)
	}
	return int64(len(ids)), nil
}

// cancelPAApprovalsOfConnTx cancels, in tx, the approvals of principal that
// are bound to the connection and were not dispatched, with their notice.
// Every statement that changes a connection's authority revision calls it
// in the transaction of that change, next to
// revokePAPermissionsOfConnTx (threat model T2 "/disconnect" step 4): the
// revision compare-and-set of the consume already refuses such an
// approval, and this ends it, so its card answers "cancelled" and its
// arguments are erased at once. A failure fails the change.
func cancelPAApprovalsOfConnTx(ctx context.Context, tx *sql.Tx, principal int64, connectionID string, nowMS int64) error {
	if connectionID == "" {
		// An empty id would cancel every approval of the principal.
		return fmt.Errorf("%w: cancel approvals of a connection", approval.ErrInvalid)
	}
	if _, err := cancelPAApprovalsWithNotice(ctx, tx, principal, nowMS, connectionID); err != nil {
		return fmt.Errorf("pa connection: %w", err)
	}
	return nil
}

// CancelPAApprovalsForConnection implements approval.Store. It queues no
// notice: the connection transitions use cancelPAApprovalsOfConnTx.
func (s *Store) CancelPAApprovalsForConnection(ctx context.Context, tx *sql.Tx, principal int64, connectionID string, now time.Time) (int64, error) {
	if tx == nil || principal <= 0 || connectionID == "" || now.IsZero() {
		return 0, fmt.Errorf("%w: cancel approvals of a connection", approval.ErrInvalid)
	}
	ids, err := cancelPAApprovals(ctx, tx, principal, now.UnixMilli(), connectionID)
	return int64(len(ids)), err
}

// forgetPAApprovals deletes the principal's approvals and dispatch records
// (/forget, consent withdrawal). A call that is on the wire keeps its two
// rows: they hold no arguments, and deleting them would erase the only
// record that a write may have happened. FinishPADispatch or the stale
// sweep ends them, and SweepPAState deletes them after that.
//
// What was still waiting is cancelled first, on every connection of the
// principal, so that the principal is told once that it will not run
// (cancelPAApprovalsWithNotice, #1320 slice P2-S12); the rows then go like
// the rest. The notice names no call and survives the deletion.
func forgetPAApprovals(ctx context.Context, tx *sql.Tx, principal int64, nowMS int64) error {
	if _, err := cancelPAApprovalsWithNotice(ctx, tx, principal, nowMS, ""); err != nil {
		return err
	}
	if err := deletePAApprovalCallbacks(ctx, tx, principal, `status <> 'dispatching'`); err != nil {
		return err
	}
	for _, q := range []string{
		`DELETE FROM pa_approvals WHERE principal = $1 AND status <> 'dispatching'`,
		`DELETE FROM pa_dispatches WHERE principal = $1 AND status <> 'dispatching'`,
	} {
		if _, err := tx.ExecContext(ctx, q, principal); err != nil {
			return fmt.Errorf("forget pa approvals: %w", err)
		}
	}
	return nil
}

// ConsumePAApproval implements approval.Store: the single-use receipt.
//
// The UPDATE is the compare-and-set. Each predicate is one refusal of the
// threat model: the principal (S2-A4), status = approved (S2-A1: a second
// consume finds dispatching), the expiry (S2-A2), the connection active at
// the bound authority_revision (S2-C10, read from the connection row in
// the same statement, not passed in by the caller) and the conversation
// still open. On Postgres the caller locks the connection row first (T2
// step 1), so a concurrent /disconnect is ordered against this statement.
func (s *Store) ConsumePAApproval(ctx context.Context, tx *sql.Tx, req approval.ConsumeRequest) (approval.Approval, approval.Dispatch, error) {
	if tx == nil {
		return approval.Approval{}, approval.Dispatch{}, fmt.Errorf("%w: consume without a transaction", approval.ErrInvalid)
	}
	if err := req.Validate(); err != nil {
		return approval.Approval{}, approval.Dispatch{}, err
	}
	nowMS := req.Now.UnixMilli()
	var sealed []byte
	a, err := scanPAApproval(tx.QueryRowContext(ctx,
		`UPDATE pa_approvals SET status = $1, updated_at_ms = $2
		 WHERE principal = $3 AND id = $4
		   AND status = $5
		   AND expires_at_ms > $2
		   AND EXISTS (SELECT 1 FROM pa_connections c
		               WHERE c.principal = pa_approvals.principal AND c.id = pa_approvals.connection_id
		                 AND c.state = $6
		                 AND c.authority_revision = pa_approvals.authority_revision)
		   AND EXISTS (SELECT 1 FROM pa_conversations v
		               WHERE v.principal = pa_approvals.principal AND v.id = pa_approvals.conversation_id
		                 AND v.closed_at_ms = 0 AND v.expires_at_ms > $2)
		 RETURNING `+paApprovalCols+`, sealed_args`,
		string(approval.StatusDispatching), nowMS, req.Principal, req.ApprovalID,
		string(approval.StatusApproved), string(connection.StateActive)), &sealed)
	if errors.Is(err, approval.ErrNotFound) {
		return approval.Approval{}, approval.Dispatch{}, s.paApprovalRefusal(ctx, tx, req.Principal, req.ApprovalID, nowMS, true)
	}
	if err != nil {
		return approval.Approval{}, approval.Dispatch{}, err
	}
	if len(sealed) == 0 {
		return approval.Approval{}, approval.Dispatch{}, fmt.Errorf("%w: approved row %s has no arguments", approval.ErrUnreadable, a.ID)
	}
	a.SealedArgs = sealed
	// The arguments leave the row in the transaction that consumes the
	// receipt: the caller holds them in memory for the one call.
	if _, err := tx.ExecContext(ctx,
		`UPDATE pa_approvals SET sealed_args = NULL WHERE principal = $1 AND id = $2`, a.Principal, a.ID); err != nil {
		return approval.Approval{}, approval.Dispatch{}, approvalUnreadable("consume: erase arguments", err)
	}
	leaseMS := req.Now.Add(req.Lease).UnixMilli()
	res, err := tx.ExecContext(ctx,
		`INSERT INTO pa_dispatches(principal, id, approval_id, connection_id, authority_revision, server, tool,
			args_sha, idempotency_key, status, lease_until_ms, created_at_ms, updated_at_ms)
		 VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		 ON CONFLICT (idempotency_key) DO NOTHING`,
		a.Principal, req.DispatchID, a.ID, a.ConnectionID, a.AuthorityRevision, a.Server, a.Tool,
		a.ArgsSHA, a.IdempotencyKey, string(approval.DispatchDispatching), leaseMS, nowMS, nowMS)
	if err != nil {
		return approval.Approval{}, approval.Dispatch{}, approvalUnreadable("consume: dispatch record", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// The insert may or may not have happened: refuse, the caller
		// rolls back.
		return approval.Approval{}, approval.Dispatch{}, approvalUnreadable("consume: dispatch record: rows affected", err)
	}
	if n != 1 {
		// A dispatch already holds this idempotency key: the receipt paid
		// for a call before, whatever the approval row says now.
		return approval.Approval{}, approval.Dispatch{}, fmt.Errorf("%w: a dispatch record exists", approval.ErrConsumed)
	}
	a.Status = approval.StatusDispatching
	return a, approval.Dispatch{
		Principal: a.Principal, ID: req.DispatchID, ApprovalID: a.ID, ConnectionID: a.ConnectionID,
		AuthorityRevision: a.AuthorityRevision, Server: a.Server, Tool: a.Tool, ArgsSHA: a.ArgsSHA,
		IdempotencyKey: a.IdempotencyKey, Status: approval.DispatchDispatching,
		LeaseUntil: time.UnixMilli(leaseMS).UTC(), CreatedAt: time.UnixMilli(nowMS).UTC(),
	}, nil
}

// finishPAApprovalsOfDispatches moves to done every dispatching approval
// whose dispatch record is no longer dispatching. $1 is the time.
const finishPAApprovalsOfDispatches = `UPDATE pa_approvals SET status = 'done', finished_at_ms = $1, updated_at_ms = $1
	WHERE status = 'dispatching' AND EXISTS (SELECT 1 FROM pa_dispatches d
		WHERE d.principal = pa_approvals.principal AND d.approval_id = pa_approvals.id AND d.status <> 'dispatching')`

// FinishPADispatch implements approval.Store.
func (s *Store) FinishPADispatch(ctx context.Context, tx *sql.Tx, principal int64, dispatchID string, status approval.DispatchStatus, now time.Time) (approval.Dispatch, error) {
	if tx == nil || principal <= 0 || dispatchID == "" || !status.Final() || now.IsZero() {
		return approval.Dispatch{}, fmt.Errorf("%w: finish dispatch", approval.ErrInvalid)
	}
	nowMS := now.UnixMilli()
	d, err := scanPADispatch(tx.QueryRowContext(ctx,
		`UPDATE pa_dispatches SET status = $1, lease_until_ms = 0, finished_at_ms = $2, updated_at_ms = $2
		 WHERE principal = $3 AND id = $4 AND status = $5
		 RETURNING `+paDispatchCols,
		string(status), nowMS, principal, dispatchID, string(approval.DispatchDispatching)))
	if errors.Is(err, approval.ErrNotFound) {
		// Read what is there: no row is absence, a row in another status is
		// stale, and a failed read is neither.
		if _, rerr := scanPADispatch(tx.QueryRowContext(ctx,
			`SELECT `+paDispatchCols+` FROM pa_dispatches WHERE principal = $1 AND id = $2`, principal, dispatchID)); rerr != nil {
			return approval.Dispatch{}, rerr
		}
		return approval.Dispatch{}, approval.ErrDispatchStale
	}
	if err != nil {
		return approval.Dispatch{}, err
	}
	if _, err := tx.ExecContext(ctx, finishPAApprovalsOfDispatches+` AND principal = $2`, nowMS, principal); err != nil {
		return approval.Dispatch{}, approvalUnreadable("finish dispatch: approval", err)
	}
	return d, nil
}

// SweepStalePADispatches implements approval.Store: the restart sweep of
// T2. The only status it writes is outcome_unknown, and the only approval
// status done: a crashed dispatch is never made dispatchable again. A
// record whose lease has not run out belongs to a call that may still be
// in flight on another replica, and is left alone.
func (s *Store) SweepStalePADispatches(ctx context.Context, now time.Time) ([]approval.Dispatch, error) {
	if now.IsZero() {
		return nil, fmt.Errorf("%w: sweep dispatches", approval.ErrInvalid)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, approvalUnreadable("sweep dispatches: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	nowMS := now.UnixMilli()
	rows, err := tx.QueryContext(ctx,
		`UPDATE pa_dispatches SET status = $1, lease_until_ms = 0, finished_at_ms = $2, updated_at_ms = $2
		 WHERE status = $3 AND lease_until_ms <= $2
		 RETURNING `+paDispatchCols,
		string(approval.DispatchOutcomeUnknown), nowMS, string(approval.DispatchDispatching))
	if err != nil {
		return nil, approvalUnreadable("sweep dispatches", err)
	}
	var out []approval.Dispatch
	for rows.Next() {
		d, err := scanPADispatch(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Close(); err != nil {
		return nil, approvalUnreadable("sweep dispatches: close", err)
	}
	if err := rows.Err(); err != nil {
		return nil, approvalUnreadable("sweep dispatches: rows", err)
	}
	if _, err := tx.ExecContext(ctx, finishPAApprovalsOfDispatches, nowMS); err != nil {
		return nil, approvalUnreadable("sweep dispatches: approvals", err)
	}
	// The principal is owed the same notice a call that timed out gets,
	// written with the state change that owes it (P2-S3). The caller
	// appends the audit result entries after the commit.
	if err := enqueueStaleWriteNotices(ctx, tx, out, nowMS); err != nil {
		return nil, approvalUnreadable("sweep dispatches: notice", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, approvalUnreadable("sweep dispatches: commit", err)
	}
	return out, nil
}
