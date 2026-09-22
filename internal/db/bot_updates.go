package db

// bot_updates.go is the durable half of the login-bot update receiver
// (issue-619). It exists so that acknowledging an update to Telegram can never
// happen before the platform durably owns it.
//
// Telegram's acknowledgement for long-polling is the offset: an update is
// confirmed only when getUpdates is called with offset > update_id, and until
// then it is redelivered for 24 hours. NextOffset therefore reads MAX(update_id)
// back out of this table rather than taking it from the batch the poller is
// holding, which is the single property that makes every crash point safe:
//
//   - crash before AcceptUpdate commits -> no row, so the offset does not move,
//     so Telegram redelivers. Nothing is lost.
//   - crash after AcceptUpdate, before dispatch -> the offset has moved, but the
//     row is durably present with processed_at IS NULL and the startup sweep
//     picks it up. Acceptance was durable BEFORE the acknowledgement, which is
//     the whole point.
//   - crash during dispatch -> the claim and the processed_at write share one
//     transaction, so both roll back together and the row is re-claimed.
//
// Duplicate delivery is handled at acceptance by ON CONFLICT DO NOTHING on the
// update_id primary key, so a redelivered update is never dispatched a second
// time.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Update kinds recognised by the receiver. Anything else is accepted (so the
// offset advances and Telegram stops redelivering it) and recorded as
// KindUnsupported without being dispatched.
const (
	KindMessage       = "message"
	KindCallbackQuery = "callback_query"
	KindUnsupported   = "unsupported"
)

// Dispatch outcomes recorded on the row. These are the counter labels too, so
// "dropped safely and counted" is one fact in two places rather than two facts
// that can disagree.
const (
	OutcomeHandled      = "handled"
	OutcomeNoHandler    = "no_handler"
	OutcomeUnknownChat  = "unknown_chat"
	OutcomeUnsupported  = "unsupported"
	OutcomeHandlerError = "handler_error"
)

// PendingUpdate is an accepted update that has not been dispatched yet. It
// carries routing facts only: no message text, no callback payload, no phone
// number. Those are dropped at the transport boundary and never reach the
// database, so this struct cannot leak them downstream either.
type PendingUpdate struct {
	UpdateID int64
	Kind     string
	ChatID   sql.NullInt64
}

// AcceptUpdate durably records an inbound update and reports whether this call
// is the one that accepted it. A false return means the update_id was already
// present -- a Telegram redelivery, or a second poller in a configuration that
// should not exist -- and the caller must NOT dispatch it.
//
// This is deliberately a plain INSERT ... ON CONFLICT DO NOTHING rather than an
// upsert: an existing row must never be overwritten, because that row may
// already be claimed or processed and rewriting it would resurrect work that
// has been done.
func (s *Store) AcceptUpdate(ctx context.Context, updateID int64, kind string, chatID sql.NullInt64) (accepted bool, err error) {
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO bot_updates(update_id, kind, chat_id, received_at)
		 VALUES($1, $2, $3, $4)
		 ON CONFLICT (update_id) DO NOTHING`,
		updateID, kind, chatID, time.Now().UTC(),
	)
	if err != nil {
		return false, fmt.Errorf("accept update: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("accept update: rows affected: %w", err)
	}
	return n > 0, nil
}

// NextOffset returns the offset to pass to the next getUpdates call: one past
// the highest update_id this table durably holds, or 0 when it is empty (which
// Telegram reads as "send me whatever you have").
//
// Read from the database, never from memory. See the package comment -- this is
// what keeps the acknowledgement behind durable ownership.
func (s *Store) NextOffset(ctx context.Context) (int64, error) {
	var maxID sql.NullInt64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT MAX(update_id) FROM bot_updates`,
	).Scan(&maxID); err != nil {
		return 0, fmt.Errorf("next offset: %w", err)
	}
	if !maxID.Valid {
		return 0, nil
	}
	return maxID.Int64 + 1, nil
}

// ListPendingUpdates returns accepted-but-undispatched updates in arrival
// order, oldest first. The startup sweep uses it to recover work that was
// acknowledged to Telegram but whose dispatch did not complete.
func (s *Store) ListPendingUpdates(ctx context.Context, limit int) ([]PendingUpdate, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT update_id, kind, chat_id FROM bot_updates
		 WHERE processed_at IS NULL
		 ORDER BY update_id ASC
		 LIMIT $1`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list pending updates: %w", err)
	}
	defer rows.Close()
	var out []PendingUpdate
	for rows.Next() {
		var u PendingUpdate
		if err := rows.Scan(&u.UpdateID, &u.Kind, &u.ChatID); err != nil {
			return nil, fmt.Errorf("list pending updates: scan: %w", err)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ErrUpdateNotClaimable is returned by DispatchOnce when the row disappeared or
// was completed by someone else between the caller reading it and claiming it.
var ErrUpdateNotClaimable = errors.New("update not claimable")

// DispatchOnce runs fn for one accepted update and marks it processed in the
// SAME transaction, so the two cannot come apart.
//
// This is what closes the last crash seam. Marking processed before fn would
// lose the work if the process died during it; marking it after, in a separate
// statement, would re-run fn after a crash in between. Inside one transaction a
// crash rolls back the claim and anything fn wrote through the supplied tx
// together, and the update is simply re-claimed on the next sweep.
//
// The contract this imposes on handlers is therefore explicit: a handler's side
// effects must either live inside the supplied transaction or be idempotent. A
// side effect performed outside the database -- sending a Telegram message, for
// instance -- is at-least-once and is out of scope for the transport (#439
// owns delivery).
//
// The UPDATE ... WHERE processed_at IS NULL is the claim: if a concurrent
// caller processed the row first, zero rows match and this call reports
// ErrUpdateNotClaimable without running fn.
func (s *Store) DispatchOnce(ctx context.Context, updateID int64, fn func(context.Context, *sql.Tx) (string, error)) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("dispatch once: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx,
		`UPDATE bot_updates SET claimed_at = $1 WHERE update_id = $2 AND processed_at IS NULL`,
		now, updateID,
	)
	if err != nil {
		return fmt.Errorf("dispatch once: claim: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("dispatch once: claim rows: %w", err)
	}
	if n == 0 {
		return ErrUpdateNotClaimable
	}

	outcome, fnErr := fn(ctx, tx)
	if fnErr != nil {
		// Roll the claim back with it, so the update is retried rather than
		// silently marked done. The caller decides whether to record the
		// failure; see the receiver's handler-error path.
		return fnErr
	}
	if outcome == "" {
		outcome = OutcomeHandled
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE bot_updates SET processed_at = $1, outcome = $2 WHERE update_id = $3`,
		time.Now().UTC(), outcome, updateID,
	); err != nil {
		return fmt.Errorf("dispatch once: mark processed: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("dispatch once: commit: %w", err)
	}
	return nil
}

// MarkUpdateFailed records a terminal dispatch failure so a permanently broken
// update cannot block the pending sweep forever. It is separate from
// DispatchOnce on purpose: DispatchOnce rolls back on error so the work is
// retried, and only the caller knows when retrying has stopped being useful.
func (s *Store) MarkUpdateFailed(ctx context.Context, updateID int64) error {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE bot_updates SET processed_at = $1, outcome = $2 WHERE update_id = $3 AND processed_at IS NULL`,
		time.Now().UTC(), OutcomeHandlerError, updateID,
	); err != nil {
		return fmt.Errorf("mark update failed: %w", err)
	}
	return nil
}
