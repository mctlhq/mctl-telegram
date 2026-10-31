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
		`INSERT INTO agent_jobs(event_id, user_id, conversation_id, body_bytes)
		 VALUES($1,$2,$3,$4)
		 ON CONFLICT (event_id) DO NOTHING
		 RETURNING id`,
		ev.EventID, ev.UserID, conversationID, len(ev.Body),
	).Scan(&jobID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, false, fmt.Errorf("enqueue agent job: %w", err)
	}

	if err := applyPendingDeleteTx(ctx, tx, ev, jobID); err != nil {
		return 0, false, err
	}
	if err := ignoreInactiveConversationJobTx(ctx, tx, ev.UserID, conversationID, jobID); err != nil {
		return 0, false, err
	}

	now := time.Now().UTC()
	// With operator routing on, an event the worker will handle is not
	// published here; routeJobEventTx forwards it only if the job fails or is
	// denied. jobID is 0 when the job row already existed.
	var queued bool
	if !s.operatorRouting || jobID == 0 {
		queued, err = s.insertOutboxTx(ctx, tx, ev, now)
		if err != nil {
			return 0, false, err
		}
	}
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
	if queued && s.outboxNotify != nil {
		s.outboxNotify()
	}
	return jobID, true, nil
}

// ReasonConversationNotActive closes a job at ingest when its conversation is
// taken over, closed or paused (#601). Policy denies every reply in those
// states, so invoking the model could only end in a forced "ignored" at full
// cost; the event itself is still recorded for audit and for /mctl continue.
const ReasonConversationNotActive = "conversation not active: agent not invoked"

// ignoreInactiveConversationJobTx closes the new job as ignored when its
// conversation is not active. The state is read inside the ingest
// transaction, so a takeover committed before this event is always seen.
// Owner summaries are skipped with the reply: in a conversation the owner is
// handling, the owner reads the messages directly.
// With operator routing on, the event is not published to the operator
// stream either (the ingest outbox row is skipped because the job exists):
// the owner is handling the conversation, the same as a run ending ignored.
func ignoreInactiveConversationJobTx(ctx context.Context, tx *sql.Tx, userID, conversationID, jobID int64) error {
	if jobID == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agent_jobs SET status = $1, last_error = $2, updated_at = $3
		  WHERE id = $4 AND status = $5
		    AND EXISTS (
		        SELECT 1 FROM conversations
		         WHERE id = $6 AND user_id = $7 AND state <> $8
		    )`,
		JobIgnored, ReasonConversationNotActive, time.Now().UTC(), jobID, JobPending,
		conversationID, userID, ConversationActive,
	); err != nil {
		return fmt.Errorf("ignore job for inactive conversation: %w", err)
	}
	return nil
}

// applyPendingDeleteTx applies a delete that arrived before this message
// (#985). gotd dispatches a difference's deletes before its new messages, so
// RecordMessageDelete may have found nothing to delete and kept the delete in
// agent_pending_deletes. Taking it here records the message_delete event
// after the message's own event, so supersession sees the delete as later.
// The new job is then closed as ignored whenever the message has a recorded
// delete, the same as a delete of a message still queued. That also covers an
// edit ingested after the delete was applied: its event is newer than the
// delete, so supersession alone would treat it as current text.
func applyPendingDeleteTx(ctx context.Context, tx *sql.Tx, ev IncomingEvent, jobID int64) error {
	if ev.Kind != EventKindPrivateMessage && ev.Kind != EventKindMessageEdit {
		return nil
	}
	var selfTGID int64
	err := tx.QueryRowContext(ctx,
		`DELETE FROM agent_pending_deletes
		  WHERE user_id = $1 AND message_id = $2 AND created_at >= $3
		  RETURNING self_tg_id`,
		ev.UserID, ev.MessageID, time.Now().UTC().Add(-pendingDeleteTTL),
	).Scan(&selfTGID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("take pending delete: %w", err)
	default:
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO incoming_events
			   (event_id, user_id, kind, chat_tg_id, sender_tg_id, message_id, body_encrypted, meta)
			 VALUES($1,$2,$3,$4,$4,$5,NULL,'{}')
			 ON CONFLICT (event_id) DO NOTHING`,
			deleteEventID(selfTGID, ev.ChatTGID, ev.MessageID), ev.UserID, EventKindMessageDelete,
			ev.ChatTGID, ev.MessageID,
		); err != nil {
			return fmt.Errorf("record pending delete: %w", err)
		}
	}
	if jobID == 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agent_jobs SET status = $1, last_error = $2, updated_at = $3
		  WHERE id = $4 AND status = $5
		    AND EXISTS (
		        SELECT 1 FROM incoming_events
		         WHERE user_id = $6 AND chat_tg_id = $7 AND message_id = $8 AND kind = $9
		    )`,
		JobIgnored, ReasonSourceDeleted, time.Now().UTC(), jobID, JobPending,
		ev.UserID, ev.ChatTGID, ev.MessageID, EventKindMessageDelete,
	); err != nil {
		return fmt.Errorf("ignore job for deleted message: %w", err)
	}
	return nil
}
