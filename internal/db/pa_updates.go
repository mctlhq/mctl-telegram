package db

// pa_updates.go is the durable deduplication of Personal Assistant bot
// webhook deliveries (issue #1313, threat model T4). See the schema comment
// on pa_updates.

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// AcceptPAUpdate records updateID and, only if this call is the one that
// recorded it, runs fn inside the same transaction. It reports whether fn ran
// and committed.
//
//   - A duplicate update_id returns (false, nil) without calling fn. That is
//     the guarantee a Telegram retry relies on: no second run, no second
//     budget charge.
//   - An error from fn rolls the row back with fn's own writes and is
//     returned, so Telegram's retry of the same update is processed afresh
//     rather than deduplicated into silence.
//   - A database error is returned as an error, never as "duplicate": a
//     dedup row that could not be read or written is not evidence that the
//     update was already handled (I9).
//
// fn receives the transaction so a later slice can enqueue the run in the
// same commit as the dedup row.
func (s *Store) AcceptPAUpdate(ctx context.Context, updateID int64, fn func(context.Context, *sql.Tx) error) (bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("accept pa update: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO pa_updates(update_id, received_at) VALUES($1, $2)
		 ON CONFLICT (update_id) DO NOTHING`,
		updateID, time.Now().UTC(),
	)
	if err != nil {
		return false, fmt.Errorf("accept pa update: insert: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("accept pa update: rows affected: %w", err)
	}
	if n == 0 {
		return false, nil
	}
	if fn != nil {
		if err := fn(ctx, tx); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("accept pa update: commit: %w", err)
	}
	return true, nil
}

// RecordPAUpdateFailure counts one failed handling of updateID in its own
// transaction (the update's transaction has rolled back) and returns the
// count so far. An error is returned as an error: a failure that could not
// be counted must not be acknowledged (I9).
func (s *Store) RecordPAUpdateFailure(ctx context.Context, updateID int64) (int, error) {
	nowMS := time.Now().UnixMilli()
	var n int
	err := s.DB.QueryRowContext(ctx,
		`INSERT INTO pa_update_failures(update_id, attempts, updated_at_ms) VALUES($1, 1, $2)
		 ON CONFLICT (update_id) DO UPDATE SET attempts = pa_update_failures.attempts + 1, updated_at_ms = excluded.updated_at_ms
		 RETURNING attempts`, updateID, nowMS).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("record pa update failure: %w", err)
	}
	return n, nil
}

// AckFailedPAUpdate records updateID as handled with reason as its
// handler_error, without running anything, so Telegram stops redelivering a
// deterministically failing update. A duplicate is not an error.
func (s *Store) AckFailedPAUpdate(ctx context.Context, updateID int64, reason string) error {
	if reason == "" {
		return fmt.Errorf("ack failed pa update: reason required")
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO pa_updates(update_id, received_at, handler_error) VALUES($1, $2, $3)
		 ON CONFLICT (update_id) DO NOTHING`, updateID, time.Now().UTC(), reason); err != nil {
		return fmt.Errorf("ack failed pa update: %w", err)
	}
	return nil
}

// PAUpdateHandlerError returns the recorded handler error of updateID, ""
// for one that ran, and sql.ErrNoRows for one never recorded.
func (s *Store) PAUpdateHandlerError(ctx context.Context, updateID int64) (string, error) {
	var reason string
	err := s.DB.QueryRowContext(ctx, `SELECT handler_error FROM pa_updates WHERE update_id = $1`, updateID).Scan(&reason)
	return reason, err
}
