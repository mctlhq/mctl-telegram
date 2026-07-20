package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// InsertEventEnqueueJobAndTouch persists an actionable incoming event, its
// pending job, and the conversation's last-incoming timestamp in one
// transaction. A duplicate event is a complete no-op, so gotd redelivery
// cannot make an old conversation look newly active.
func (s *Store) InsertEventEnqueueJobAndTouch(ctx context.Context, ev IncomingEvent, conversationID int64) (jobID int64, enqueued bool, err error) {
	if ev.EventID == "" {
		return 0, false, errors.New("event id required")
	}
	if ev.UserID <= 0 {
		return 0, false, errors.New("user id required")
	}
	if ev.Kind == "" {
		return 0, false, errors.New("event kind required")
	}
	if conversationID <= 0 {
		return 0, false, errors.New("conversation id required")
	}
	if _, err := s.GetConversation(ctx, ev.UserID, conversationID); err != nil {
		return 0, false, err
	}

	var body []byte
	if ev.Body != "" {
		body, err = s.Crypt.SealForUser([]byte(ev.Body), ev.UserID)
		if err != nil {
			return 0, false, fmt.Errorf("seal event body: %w", err)
		}
	}
	meta := ev.Meta
	if meta == "" {
		meta = "{}"
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, fmt.Errorf("begin ingest tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var eventRowID int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO incoming_events
		   (event_id, user_id, kind, chat_tg_id, sender_tg_id, message_id, body_encrypted, meta)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (event_id) DO NOTHING
		 RETURNING id`,
		ev.EventID, ev.UserID, ev.Kind, ev.ChatTGID, ev.SenderTGID, ev.MessageID, body, meta,
	).Scan(&eventRowID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("insert incoming event: %w", err)
	}

	err = tx.QueryRowContext(ctx,
		`INSERT INTO agent_jobs(event_id, user_id, conversation_id)
		 VALUES($1,$2,$3)
		 ON CONFLICT (event_id) DO NOTHING
		 RETURNING id`,
		ev.EventID, ev.UserID, conversationID,
	).Scan(&jobID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, false, fmt.Errorf("enqueue agent job: %w", err)
	}

	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx,
		`UPDATE conversations
		    SET last_incoming_at = $1, updated_at = $1
		  WHERE id = $2 AND user_id = $3`,
		now, conversationID, ev.UserID,
	)
	if err != nil {
		return 0, false, fmt.Errorf("touch conversation: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return 0, false, fmt.Errorf("touch conversation rows: %w", err)
	} else if n != 1 {
		return 0, false, ErrConversationNotFound
	}

	if err := tx.Commit(); err != nil {
		return 0, false, fmt.Errorf("commit ingest tx: %w", err)
	}
	return jobID, true, nil
}
