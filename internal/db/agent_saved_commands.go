package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// GetSavedCommandCursor returns the last Saved Messages message id examined by
// the history poller. found=false distinguishes a first activation from a
// legitimate baseline at message id zero.
func (s *Store) GetSavedCommandCursor(ctx context.Context, userID int64) (lastMessageID int64, found bool, err error) {
	err = s.DB.QueryRowContext(ctx,
		`SELECT last_message_id
		   FROM agent_saved_command_cursors
		  WHERE user_id = $1`,
		userID,
	).Scan(&lastMessageID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("get saved command cursor: %w", err)
	}
	return lastMessageID, true, nil
}

// AdvanceSavedCommandCursor creates or monotonically advances a user's Saved
// Messages history cursor. The CASE expression is portable across SQLite and
// PostgreSQL and prevents a slower concurrent delivery path from regressing
// the watermark.
func (s *Store) AdvanceSavedCommandCursor(ctx context.Context, userID, lastMessageID int64) error {
	if userID <= 0 {
		return errors.New("user id required")
	}
	if lastMessageID < 0 {
		return errors.New("last message id cannot be negative")
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO agent_saved_command_cursors(user_id, last_message_id, updated_at)
		 VALUES($1, $2, $3)
		 ON CONFLICT(user_id) DO UPDATE SET
		   last_message_id = CASE
		     WHEN excluded.last_message_id > agent_saved_command_cursors.last_message_id
		     THEN excluded.last_message_id
		     ELSE agent_saved_command_cursors.last_message_id
		   END,
		   updated_at = CASE
		     WHEN excluded.last_message_id > agent_saved_command_cursors.last_message_id
		     THEN excluded.updated_at
		     ELSE agent_saved_command_cursors.updated_at
		   END`,
		userID, lastMessageID, time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("advance saved command cursor: %w", err)
	}
	return nil
}
