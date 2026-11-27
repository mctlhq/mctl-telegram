package db

// pa_writes.go is the store half of the Personal Assistant's write executor
// (#1320 slice P2-S3; threat model T2 "Execution-time check and dispatch",
// I4): the transactions the executor runs before and after an approved
// call, and the tx-scoped reads its checks use. The checks themselves are
// in internal/pa/connector/dispatch_write.go.
//
// No method here makes an outbound call, and the executor makes none while
// one of these transactions is open.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// BeginPAWrite opens a transaction of the write executor for principal and
// takes the principal lock in it, so it is ordered against the principal's
// webhook updates (Cancel, /new, /forget, consent withdrawal) and run
// steps. With budget it first takes the managed ledger's global lock, in
// the order every claim takes the two (budget, then principal): the
// pre-dispatch transaction does that, so that charging a call's cost in it
// later cannot close a lock cycle with a claim.
//
// The caller commits or rolls back.
func (s *Store) BeginPAWrite(ctx context.Context, principal int64, budget bool) (*sql.Tx, error) {
	if principal <= 0 {
		return nil, fmt.Errorf("%w: begin write", approval.ErrInvalid)
	}
	pg, err := s.postgresDialect(ctx)
	if err != nil {
		return nil, approvalUnreadable("begin write: dialect", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, approvalUnreadable("begin write", err)
	}
	if budget {
		if err := s.lockManagedBudget(ctx, tx, pg, 0); err != nil {
			_ = tx.Rollback()
			return nil, approvalUnreadable("begin write", err)
		}
	}
	if err := s.LockPAPrincipal(ctx, tx, principal); err != nil {
		_ = tx.Rollback()
		return nil, approvalUnreadable("begin write", err)
	}
	return tx, nil
}

// LockPAConnection reads the principal's connection inside tx and keeps
// the row still until tx ends (threat model T2 step 1). On Postgres that is
// SELECT ... FOR UPDATE: a /disconnect, an expiry or an activation that
// supersedes the connection either committed before this read, and is what
// it returns, or waits for tx and lands after the receipt was consumed,
// where the post-dispatch check sees it. On SQLite tx already holds the
// database write lock (BeginPAWrite wrote the principal lock row).
//
// A missing row is connection.ErrNotFound; every other failure wraps
// connection.ErrUnreadable and is never a row (I9).
func (s *Store) LockPAConnection(ctx context.Context, tx *sql.Tx, principal int64, id string) (connection.Connection, error) {
	if tx == nil || principal <= 0 || id == "" {
		return connection.Connection{}, fmt.Errorf("%w: lock connection", connection.ErrUnreadable)
	}
	pg, err := s.postgresDialect(ctx)
	if err != nil {
		return connection.Connection{}, fmt.Errorf("%w: lock connection: dialect: %v", connection.ErrUnreadable, err)
	}
	lock := ""
	if pg {
		lock = " FOR UPDATE"
	}
	return scanPAConn(tx.QueryRowContext(ctx,
		`SELECT `+paConnCols+` FROM pa_connections WHERE principal = $1 AND id = $2`+lock, principal, id), nil)
}

// PAConversationTaintIn is ReadPAConversationTaint inside tx: only a row
// read with a stored 0 is clean. A missing row and every failed read are
// tainted, with the error (I9, S2-I10).
func (s *Store) PAConversationTaintIn(ctx context.Context, tx *sql.Tx, principal int64, conversationID string) (bool, error) {
	if tx == nil || principal <= 0 || conversationID == "" {
		return true, fmt.Errorf("%w: conversation taint", convo.ErrInvalid)
	}
	var tainted int64
	err := tx.QueryRowContext(ctx,
		`SELECT tainted FROM pa_conversations WHERE id = $1 AND principal = $2`,
		conversationID, principal).Scan(&tainted)
	if errors.Is(err, sql.ErrNoRows) {
		return true, convo.ErrNotFound
	}
	if err != nil {
		return true, rowRead("conversation taint", err)
	}
	return tainted != 0, nil
}

// enqueueStaleWriteNotices queues, in the sweep's transaction, the notice
// of every dispatch record the sweep moved: the principal is told the call
// may or may not have happened, or, for a record the sweep ended as
// refused because its request was never made, that it was not carried
// out, in the same commit that stops it from ever being sent again. An
// approval that already has a notice keeps that one.
func enqueueStaleWriteNotices(ctx context.Context, tx *sql.Tx, moved []approval.Dispatch, nowMS int64) error {
	for _, d := range moved {
		if d.ApprovalID == "" {
			continue
		}
		kind := jobs.OutboxWriteUnknown
		if d.Status == approval.DispatchRefused {
			kind = jobs.OutboxWriteNotSent
		}
		if err := enqueuePAOutbox(ctx, tx, jobs.OutboxItem{
			Principal: d.Principal, Kind: kind, ApprovalID: d.ApprovalID,
		}, nowMS); err != nil {
			return err
		}
	}
	return nil
}
