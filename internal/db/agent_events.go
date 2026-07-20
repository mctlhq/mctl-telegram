package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrIncomingEventNotFound is returned by GetIncomingEvent when no row
// matches the requested event id.
var ErrIncomingEventNotFound = errors.New("incoming event not found")

// Incoming event kinds. The listener maps raw gotd updates onto exactly one
// of these before persisting; downstream consumers switch on the kind rather
// than re-parsing Telegram types.
const (
	EventKindPrivateMessage = "private_message" // new incoming DM from a non-bot user
	EventKindMessageEdit    = "message_edit"    // edit of an incoming DM
	EventKindOwnerOutgoing  = "owner_outgoing"  // owner sent a message in some dialog (takeover signal)
	EventKindSavedCommand   = "saved_command"   // owner message in Saved Messages that parses as /mctl ...
)

// IncomingEvent is a durable record of one Telegram update relevant to the
// communication agent. EventID is a deterministic dedup key
// (evt:v1:<account_tg_id>:<chat_id>:<message_id>[:e<edit_ts>]) enforced by a
// unique index: gotd's updates.Manager redelivers updates after a crash, and
// the index — not the listener — is what makes ingestion exactly-once.
//
// Body carries the plaintext message text in memory only; it is sealed with
// the owning user's derived key before hitting the DB and never logged.
type IncomingEvent struct {
	ID         int64
	EventID    string
	UserID     int64
	Kind       string
	ChatTGID   int64
	SenderTGID int64
	MessageID  int64
	Body       string
	Meta       string // JSON: sender username/display name, edit ts, flags. No message text.
	CreatedAt  time.Time
}

// InsertIncomingEvent persists an event if its EventID has not been seen
// before. Returns inserted=false (and no error) on a duplicate — the caller
// must then skip job enqueue. The body is encrypted with the owning user's
// derived key before storage.
func (s *Store) InsertIncomingEvent(ctx context.Context, ev IncomingEvent) (id int64, inserted bool, err error) {
	if ev.EventID == "" {
		return 0, false, errors.New("event id required")
	}
	if ev.UserID <= 0 {
		return 0, false, errors.New("user id required")
	}
	if ev.Kind == "" {
		return 0, false, errors.New("event kind required")
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
	// ON CONFLICT DO NOTHING ... RETURNING yields an empty result set on a
	// duplicate (sql.ErrNoRows) — one round-trip, no TOCTOU window between
	// insert and id fetch. Supported by both Postgres and SQLite >= 3.35.
	err = s.DB.QueryRowContext(ctx,
		`INSERT INTO incoming_events
		   (event_id, user_id, kind, chat_tg_id, sender_tg_id, message_id, body_encrypted, meta)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		 ON CONFLICT (event_id) DO NOTHING
		 RETURNING id`,
		ev.EventID, ev.UserID, ev.Kind, ev.ChatTGID, ev.SenderTGID, ev.MessageID, body, meta,
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("insert incoming event: %w", err)
	}
	return id, true, nil
}

// GetIncomingEvent returns the event with the given EventID, scoped to the
// owning user so an agent token for one account can never read another
// account's traffic. The body is decrypted before return.
func (s *Store) GetIncomingEvent(ctx context.Context, userID int64, eventID string) (*IncomingEvent, error) {
	var (
		ev   IncomingEvent
		body []byte
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, event_id, user_id, kind, chat_tg_id, sender_tg_id, message_id, body_encrypted, meta, created_at
		   FROM incoming_events WHERE event_id = $1 AND user_id = $2`,
		eventID, userID,
	).Scan(&ev.ID, &ev.EventID, &ev.UserID, &ev.Kind, &ev.ChatTGID, &ev.SenderTGID,
		&ev.MessageID, &body, &ev.Meta, &ev.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIncomingEventNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get incoming event: %w", err)
	}
	if len(body) > 0 {
		pt, err := s.Crypt.OpenForUser(body, ev.UserID)
		if err != nil {
			return nil, fmt.Errorf("open event body: %w", err)
		}
		ev.Body = string(pt)
	}
	return &ev, nil
}

// SweepAgentMessageBodies removes aged (encrypted) third-party message
// content from incoming_events and conversation_messages. Unlike audit rows
// this is a privacy requirement, not just table hygiene. retention <= 0 means
// keep forever (no-op), matching the audit sweeper convention. Returns the
// number of rows whose body was cleared.
//
// incoming_events rows are NOT deleted — the row is kept as a tombstone with
// body_encrypted nulled, because event_id is the exactly-once dedup key: a
// gotd redelivery after a long outage must still collide with the tombstone
// rather than be re-ingested. conversation_messages carry no dedup key and
// are hard-deleted.
func (s *Store) SweepAgentMessageBodies(ctx context.Context, retention time.Duration) (int64, error) {
	if retention <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-retention)
	var total int64
	// Close still-pending jobs for the events whose bodies are about to be
	// tombstoned: a claim after the null would load an empty payload, fail
	// every attempt, and dead-letter. Only pending jobs — a processing job's
	// worker already holds the payload, and its crash-recovery path (retry /
	// visibility requeue) handles the rest. This runs before the null so no
	// new claim can slip between the two statements.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_jobs SET status = $1, last_error = $2, updated_at = $3
		  WHERE status = $4 AND event_id IN (
		        SELECT event_id FROM incoming_events
		         WHERE created_at < $5 AND body_encrypted IS NOT NULL
		  )`,
		JobIgnored, "payload expired by retention sweep", time.Now().UTC(), JobPending, cutoff,
	); err != nil {
		return total, fmt.Errorf("expire jobs for swept events: %w", err)
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE incoming_events SET body_encrypted = NULL
		  WHERE created_at < $1 AND body_encrypted IS NOT NULL`, cutoff,
	)
	if err != nil {
		return total, fmt.Errorf("sweep incoming events: %w", err)
	}
	n, _ := res.RowsAffected()
	total += n
	res, err = s.DB.ExecContext(ctx,
		`DELETE FROM conversation_messages WHERE created_at < $1`, cutoff,
	)
	if err != nil {
		return total, fmt.Errorf("sweep conversation messages: %w", err)
	}
	n, _ = res.RowsAffected()
	total += n
	// Action payloads (proposed reply text) and owner-notification bodies are
	// also message-derived third-party content. Null their ciphertext past
	// retention; the rows themselves are kept for audit/lifecycle history.
	res, err = s.DB.ExecContext(ctx,
		`UPDATE agent_actions SET payload_encrypted = NULL
		  WHERE created_at < $1 AND payload_encrypted IS NOT NULL`, cutoff,
	)
	if err != nil {
		return total, fmt.Errorf("sweep action payloads: %w", err)
	}
	n, _ = res.RowsAffected()
	total += n
	res, err = s.DB.ExecContext(ctx,
		`UPDATE owner_notifications SET body_encrypted = NULL
		  WHERE created_at < $1 AND body_encrypted IS NOT NULL`, cutoff,
	)
	if err != nil {
		return total, fmt.Errorf("sweep notification bodies: %w", err)
	}
	n, _ = res.RowsAffected()
	total += n
	return total, nil
}
