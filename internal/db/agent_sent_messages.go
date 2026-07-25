package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MarkAgentSentMessage durably records the Telegram-assigned id of a
// programmatic send. The listener uses this correlation after restart so a
// replayed outgoing echo cannot be mistaken for a manual owner takeover.
func (s *Store) MarkAgentSentMessage(ctx context.Context, userID, messageID int64, retention time.Duration) error {
	if userID <= 0 || messageID <= 0 {
		return errors.New("user id and message id required")
	}
	now := time.Now().UTC()
	if retention > 0 {
		if _, err := s.DB.ExecContext(ctx,
			`DELETE FROM agent_sent_messages WHERE created_at < $1`,
			now.Add(-retention),
		); err != nil {
			return fmt.Errorf("sweep agent sent markers: %w", err)
		}
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO agent_sent_messages(user_id, tg_message_id, created_at)
		 VALUES($1,$2,$3)
		 ON CONFLICT(user_id, tg_message_id) DO UPDATE SET created_at=excluded.created_at`,
		userID, messageID, now,
	); err != nil {
		return fmt.Errorf("mark agent sent message: %w", err)
	}
	return nil
}

// ConsumeAgentSentMessage atomically removes and reports a fresh durable sent
// marker. A marker is one-shot because Telegram message ids are unique within
// a dialog update stream and only the first echo should be suppressed.
func (s *Store) ConsumeAgentSentMessage(ctx context.Context, userID, messageID int64, ttl time.Duration) (bool, error) {
	if userID <= 0 || messageID <= 0 {
		return false, nil
	}
	cutoff := time.Time{}
	if ttl > 0 {
		cutoff = time.Now().UTC().Add(-ttl)
	}
	var found int64
	err := s.DB.QueryRowContext(ctx,
		`DELETE FROM agent_sent_messages
		  WHERE user_id=$1 AND tg_message_id=$2 AND created_at >= $3
		  RETURNING tg_message_id`,
		userID, messageID, cutoff,
	).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		// Remove an exact stale marker too; otherwise repeated echoes would
		// keep looking it up until the next insertion-triggered sweep.
		_, _ = s.DB.ExecContext(ctx,
			`DELETE FROM agent_sent_messages WHERE user_id=$1 AND tg_message_id=$2`,
			userID, messageID,
		)
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("consume agent sent message: %w", err)
	}
	return found == messageID, nil
}
