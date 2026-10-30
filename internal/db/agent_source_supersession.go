package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// ErrAgentSourceSuperseded is returned by ReserveAgentActionSend when a
// message the action's job was built from has since been edited or deleted
// by its sender (#949, #950). The draft answers text that no longer exists,
// so the caller must deny the action instead of sending it.
var ErrAgentSourceSuperseded = errors.New("agent action source message superseded")

// SourceSupersededError carries the supersession kind (SourceEdited or
// SourceDeleted) and matches ErrAgentSourceSuperseded under errors.Is.
type SourceSupersededError struct{ Kind string }

func (e *SourceSupersededError) Error() string {
	return ErrAgentSourceSuperseded.Error() + ": " + e.Kind
}

func (e *SourceSupersededError) Is(target error) bool { return target == ErrAgentSourceSuperseded }

// Source supersession kinds reported by JobSourceSuperseded.
const (
	SourceEdited  = "edited"
	SourceDeleted = "deleted"
)

// Reasons persisted in agent_actions.policy_reasons when a draft is
// withdrawn because its source message changed.
const (
	ReasonSourceEdited  = "source message edited"
	ReasonSourceDeleted = "source message deleted"
)

// SourceSupersededReason maps a JobSourceSuperseded kind to the reason
// recorded on the denied action.
func SourceSupersededReason(kind string) string {
	if kind == SourceDeleted {
		return ReasonSourceDeleted
	}
	return ReasonSourceEdited
}

// jobHeadExpr resolves a job row to the head of its coalesced turn: actions
// are always written under the head job, so a member's edit or delete has to
// reach the head's drafts. coalesced_into is NULL on rows that predate turn
// coalescing and is read as 0.
const jobHeadExpr = `CASE WHEN j.coalesced_into IS NOT NULL AND j.coalesced_into <> 0
	THEN j.coalesced_into ELSE j.id END`

// sourceSupersededQuery finds a later edit or delete of any message a job's
// turn was built from. Source events are the head job's own event and the
// events of the members coalesced into it. A message is superseded once the
// account has recorded a message_edit or message_delete event for the same
// chat and message id with a higher row id than the source event: the job
// read the source version, and anything recorded after it is newer text or
// no text at all. A delete outranks an edit.
const sourceSupersededQuery = `SELECT later.kind
	  FROM agent_jobs j
	  JOIN incoming_events src
	    ON src.event_id = j.event_id AND src.user_id = j.user_id
	  JOIN incoming_events later
	    ON later.user_id = src.user_id
	   AND later.chat_tg_id = src.chat_tg_id
	   AND later.message_id = src.message_id
	   AND later.id > src.id
	   AND later.kind IN ($3, $4)
	 WHERE j.user_id = $1 AND (j.id = $2 OR j.coalesced_into = $2)
	 ORDER BY CASE WHEN later.kind = $4 THEN 0 ELSE 1 END
	 LIMIT 1`

// rowQueryer is the single-row read half shared by *sql.DB and *sql.Tx.
type rowQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func jobSourceSuperseded(ctx context.Context, q rowQueryer, userID, jobID int64) (string, error) {
	if jobID == 0 {
		return "", nil
	}
	var kind string
	err := q.QueryRowContext(ctx, sourceSupersededQuery,
		userID, jobID, EventKindMessageEdit, EventKindMessageDelete,
	).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		kind = ""
	} else if err != nil {
		return "", fmt.Errorf("check job source supersession: %w", err)
	}
	if kind == EventKindMessageDelete {
		return SourceDeleted, nil
	}
	// The messages an edit job read as turn context (#962) must be current
	// too. A delete there outranks an edit of the job's own message.
	ctxKind, err := turnContextSuperseded(ctx, q, userID, jobID)
	if err != nil {
		return "", err
	}
	if ctxKind != "" {
		return ctxKind, nil
	}
	if kind != "" {
		return SourceEdited, nil
	}
	return "", nil
}

// JobSourceSuperseded reports whether a message the job's turn was built from
// has been edited (SourceEdited) or deleted (SourceDeleted) since the job's
// source event was recorded. "" means every source message is still current.
// jobID 0 (an action not tied to a queue job) has no source set and is never
// superseded.
func (s *Store) JobSourceSuperseded(ctx context.Context, userID, jobID int64) (string, error) {
	return jobSourceSuperseded(ctx, s.DB, userID, jobID)
}

// DenyAgentActionWithReason moves one action from `from` to denied and
// records reason in policy_reasons, releasing the approval code. Returns false
// when the row was no longer in `from`.
func (s *Store) DenyAgentActionWithReason(ctx context.Context, userID, id int64, from, reason string) (bool, error) {
	if tos, ok := allowedActionTransitions[from]; !ok {
		return false, fmt.Errorf("%w: %s -> %s", ErrInvalidActionTransition, from, ActionDenied)
	} else if _, ok := tos[ActionDenied]; !ok {
		return false, fmt.Errorf("%w: %s -> %s", ErrInvalidActionTransition, from, ActionDenied)
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status = $1, approval_code = NULL, approval_code_hash = NULL,
		        approval_code_encrypted = NULL, policy_reasons = $2, updated_at = $3
		  WHERE id = $4 AND user_id = $5 AND status = $6`,
		ActionDenied, reason, time.Now().UTC(), id, userID, from,
	)
	if err != nil {
		return false, fmt.Errorf("deny agent action: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// MessageDeleteResult reports what RecordMessageDelete changed.
type MessageDeleteResult struct {
	// Recorded is the number of message_delete events written; 0 when the
	// message is not an incoming DM this account ingested, or when the delete
	// was already recorded (a gotd redelivery).
	Recorded int
	// DeniedActions counts drafts withdrawn because their turn included the
	// deleted message.
	DeniedActions int64
	// IgnoredJobs counts queued jobs closed before any worker claimed them.
	IgnoredJobs int64
}

// RecordMessageDelete handles the sender deleting an incoming private message
// (#949). Telegram's UpdateDeleteMessages carries only message ids, which are
// unique per account mailbox for private chats, so the chat is recovered from
// the events already ingested for that id. For each such chat, in one
// transaction:
//
//   - a message_delete event is recorded (event id evt:v1:<self>:<chat>:<msg>:d,
//     no body), which is what JobSourceSuperseded and the send reservation
//     consult for jobs already in flight;
//   - non-executing drafts whose turn included the message are denied with
//     ReasonSourceDeleted;
//   - pending jobs whose own event is the message are closed as ignored, so
//     no worker spends an invocation answering it.
//
// A redelivered delete collides with the existing event id and changes
// nothing. Deletes of messages the agent never ingested (the owner's own
// messages, other chats) match no event and are a no-op.
func (s *Store) RecordMessageDelete(ctx context.Context, userID, selfTGID, messageID int64) (MessageDeleteResult, error) {
	var out MessageDeleteResult
	if userID <= 0 || messageID <= 0 {
		return out, errors.New("user id and message id required")
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT DISTINCT chat_tg_id FROM incoming_events
		  WHERE user_id = $1 AND message_id = $2 AND kind IN ($3, $4)`,
		userID, messageID, EventKindPrivateMessage, EventKindMessageEdit,
	)
	if err != nil {
		return out, fmt.Errorf("find deleted message chats: %w", err)
	}
	var chats []int64
	for rows.Next() {
		var chat int64
		if err := rows.Scan(&chat); err != nil {
			_ = rows.Close()
			return out, fmt.Errorf("scan deleted message chat: %w", err)
		}
		chats = append(chats, chat)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return out, fmt.Errorf("find deleted message chats: %w", err)
	}
	_ = rows.Close()

	for _, chat := range chats {
		res, err := s.recordMessageDeleteInChat(ctx, userID, selfTGID, chat, messageID)
		if err != nil {
			return out, err
		}
		out.Recorded += res.Recorded
		out.DeniedActions += res.DeniedActions
		out.IgnoredJobs += res.IgnoredJobs
	}
	return out, nil
}

func (s *Store) recordMessageDeleteInChat(ctx context.Context, userID, selfTGID, chatTGID, messageID int64) (MessageDeleteResult, error) {
	var out MessageDeleteResult
	pg := s.isPostgres(ctx)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, fmt.Errorf("begin message delete tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Serialize with ReserveAgentActionSend, which holds the same
	// conversation row lock while it checks supersession: either the delete
	// commits first and the reservation sees it, or the reservation commits
	// first and the action is already executing (left alone below).
	if pg {
		var convID int64
		err := tx.QueryRowContext(ctx,
			`SELECT id FROM conversations WHERE user_id = $1 AND peer_tg_id = $2 FOR UPDATE`,
			userID, chatTGID,
		).Scan(&convID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return out, fmt.Errorf("lock conversation for message delete: %w", err)
		}
	}

	eventID := "evt:v1:" + strconv.FormatInt(selfTGID, 10) + ":" +
		strconv.FormatInt(chatTGID, 10) + ":" + strconv.FormatInt(messageID, 10) + ":d"
	var eventRowID int64
	err = tx.QueryRowContext(ctx,
		`INSERT INTO incoming_events
		   (event_id, user_id, kind, chat_tg_id, sender_tg_id, message_id, body_encrypted, meta)
		 VALUES($1,$2,$3,$4,$5,$6,NULL,'{}')
		 ON CONFLICT (event_id) DO NOTHING
		 RETURNING id`,
		eventID, userID, EventKindMessageDelete, chatTGID, chatTGID, messageID,
	).Scan(&eventRowID)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("insert message delete event: %w", err)
	}
	out.Recorded = 1

	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status = $1, approval_code = NULL, approval_code_hash = NULL,
		        approval_code_encrypted = NULL, policy_reasons = $2, updated_at = $3
		  WHERE user_id = $4
		    AND status IN ($5, $6, $7)
		    AND job_id IN (
		        SELECT `+jobHeadExpr+`
		          FROM agent_jobs j
		          JOIN incoming_events e
		            ON e.event_id = j.event_id AND e.user_id = j.user_id
		         WHERE j.user_id = $4 AND e.chat_tg_id = $8 AND e.message_id = $9
		    )`,
		ActionDenied, ReasonSourceDeleted, now, userID,
		ActionProposed, ActionPendingApproval, ActionApproved, chatTGID, messageID,
	)
	if err != nil {
		return out, fmt.Errorf("deny actions for deleted message: %w", err)
	}
	out.DeniedActions, _ = res.RowsAffected()

	// A first-time pending job has no coalesced members (they are attached
	// when the head is claimed). A head that went back to pending through a
	// retry or a stale requeue keeps its frozen members, and closing it here
	// closes their messages too. Running it would end the same way: the
	// propose check supersedes the whole turn (#962).
	res, err = tx.ExecContext(ctx,
		`UPDATE agent_jobs
		    SET status = $1, last_error = $2, updated_at = $3
		  WHERE user_id = $4 AND status = $5
		    AND event_id IN (
		        SELECT event_id FROM incoming_events
		         WHERE user_id = $4 AND chat_tg_id = $6 AND message_id = $7
		           AND kind IN ($8, $9)
		    )`,
		JobIgnored, ReasonSourceDeleted, now, userID, JobPending, chatTGID, messageID,
		EventKindPrivateMessage, EventKindMessageEdit,
	)
	if err != nil {
		return out, fmt.Errorf("ignore jobs for deleted message: %w", err)
	}
	out.IgnoredJobs, _ = res.RowsAffected()

	if err := tx.Commit(); err != nil {
		return out, fmt.Errorf("commit message delete: %w", err)
	}
	return out, nil
}

// LastWithdrawnDraft returns when and why the conversation's most recent
// draft was withdrawn because its source message was edited or deleted, for
// /mctl show. ok=false when no draft of the conversation was withdrawn that
// way. Only the reason and time are returned, never the draft text.
func (s *Store) LastWithdrawnDraft(ctx context.Context, userID, conversationID int64) (reason string, at time.Time, ok bool, err error) {
	err = s.DB.QueryRowContext(ctx,
		`SELECT policy_reasons, updated_at FROM agent_actions
		  WHERE user_id = $1 AND conversation_id = $2 AND status = $3
		    AND policy_reasons IN ($4, $5)
		  ORDER BY updated_at DESC, id DESC
		  LIMIT 1`,
		userID, conversationID, ActionDenied, ReasonSourceEdited, ReasonSourceDeleted,
	).Scan(&reason, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("last withdrawn draft: %w", err)
	}
	return reason, at.UTC(), true, nil
}
