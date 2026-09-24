package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// WorkItemBinding correlates one Telegram Saved Messages thread — (user_id,
// chat_tg_id, root_tg_message_id) — with a canonical mctl-api WorkItem. It
// holds only numeric Telegram identifiers plus the platform's own opaque
// ids/state; there is deliberately no column that can carry a message body,
// title, or peer handle (see the schema comment in agent_schema.go).
type WorkItemBinding struct {
	ID               int64
	UserID           int64
	ChatTGID         int64
	RootTGMessageID  int64
	WorkItemID       string
	ExternalKey      string
	LastState        string
	LastStateVersion int64
	LastExecutionID  string
	LastRequestID    string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// GetWorkItemBinding returns the binding for one exact thread. found=false
// (not an error) means the thread has never run /mctl work.
func (s *Store) GetWorkItemBinding(ctx context.Context, userID, chatTGID, rootMsgID int64) (WorkItemBinding, bool, error) {
	var b WorkItemBinding
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, user_id, chat_tg_id, root_tg_message_id, work_item_id, external_key,
		        last_state, last_state_version, last_execution_id, last_request_id,
		        created_at, updated_at
		   FROM work_item_bindings
		  WHERE user_id = $1 AND chat_tg_id = $2 AND root_tg_message_id = $3`,
		userID, chatTGID, rootMsgID,
	).Scan(&b.ID, &b.UserID, &b.ChatTGID, &b.RootTGMessageID, &b.WorkItemID, &b.ExternalKey,
		&b.LastState, &b.LastStateVersion, &b.LastExecutionID, &b.LastRequestID,
		&b.CreatedAt, &b.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return WorkItemBinding{}, false, nil
	}
	if err != nil {
		return WorkItemBinding{}, false, fmt.Errorf("get work item binding: %w", err)
	}
	return b, true, nil
}

// LatestWorkItemBinding returns the most recently updated binding for a
// user's chat — used when a caller only has the chat, not the exact root
// message id. found=false means the user has no binding in that chat yet.
func (s *Store) LatestWorkItemBinding(ctx context.Context, userID, chatTGID int64) (WorkItemBinding, bool, error) {
	var b WorkItemBinding
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, user_id, chat_tg_id, root_tg_message_id, work_item_id, external_key,
		        last_state, last_state_version, last_execution_id, last_request_id,
		        created_at, updated_at
		   FROM work_item_bindings
		  WHERE user_id = $1 AND chat_tg_id = $2
		  ORDER BY updated_at DESC
		  LIMIT 1`,
		userID, chatTGID,
	).Scan(&b.ID, &b.UserID, &b.ChatTGID, &b.RootTGMessageID, &b.WorkItemID, &b.ExternalKey,
		&b.LastState, &b.LastStateVersion, &b.LastExecutionID, &b.LastRequestID,
		&b.CreatedAt, &b.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return WorkItemBinding{}, false, nil
	}
	if err != nil {
		return WorkItemBinding{}, false, fmt.Errorf("get latest work item binding: %w", err)
	}
	return b, true, nil
}

// UpsertWorkItemBinding creates or replaces the binding row for one thread.
// The unique index on (user_id, chat_tg_id, root_tg_message_id) is what
// makes this idempotent: a retry after a crash or timeout is a no-op update
// of the same row rather than a duplicate.
func (s *Store) UpsertWorkItemBinding(ctx context.Context, b WorkItemBinding) error {
	if b.UserID <= 0 || b.ChatTGID == 0 || b.RootTGMessageID == 0 {
		return errors.New("user id, chat id and root message id are required")
	}
	if b.WorkItemID == "" || b.ExternalKey == "" {
		return errors.New("work item id and external key are required")
	}
	now := time.Now().UTC()
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO work_item_bindings(
		     user_id, chat_tg_id, root_tg_message_id, work_item_id, external_key,
		     last_state, last_state_version, last_execution_id, last_request_id,
		     created_at, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 ON CONFLICT(user_id, chat_tg_id, root_tg_message_id) DO UPDATE SET
		     work_item_id = excluded.work_item_id,
		     external_key = excluded.external_key,
		     last_state = excluded.last_state,
		     last_state_version = excluded.last_state_version,
		     last_execution_id = excluded.last_execution_id,
		     last_request_id = excluded.last_request_id,
		     updated_at = excluded.updated_at`,
		b.UserID, b.ChatTGID, b.RootTGMessageID, b.WorkItemID, b.ExternalKey,
		b.LastState, b.LastStateVersion, b.LastExecutionID, b.LastRequestID, now, now,
	); err != nil {
		return fmt.Errorf("upsert work item binding: %w", err)
	}
	return nil
}

// TouchWorkItemBindingState refreshes the item-level state (state, version,
// latest execution) on EVERY binding row a user has for a given work item —
// the work item's own state is the same regardless of which thread is
// looking at it, so a /mctl work status in one thread should not leave a
// sibling thread's cached view stale.
func (s *Store) TouchWorkItemBindingState(ctx context.Context, userID int64, workItemID, state string, version int64, execID string) error {
	if userID <= 0 || workItemID == "" {
		return errors.New("user id and work item id are required")
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE work_item_bindings
		    SET last_state = $1, last_state_version = $2, last_execution_id = $3, updated_at = $4
		  WHERE user_id = $5 AND work_item_id = $6`,
		state, version, execID, time.Now().UTC(), userID, workItemID,
	); err != nil {
		return fmt.Errorf("touch work item binding state: %w", err)
	}
	return nil
}

// SetWorkItemBindingRequest records the id of the execution request most
// recently submitted FROM one specific thread. Thread-scoped (unlike
// TouchWorkItemBindingState): a request is submitted from exactly one
// thread, and that thread's /mctl work status should show the request it
// itself submitted, not one a sibling thread submitted for the same item.
func (s *Store) SetWorkItemBindingRequest(ctx context.Context, userID, chatTGID, rootMsgID int64, requestID string) error {
	if userID <= 0 || chatTGID == 0 || rootMsgID == 0 {
		return errors.New("user id, chat id and root message id are required")
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE work_item_bindings
		    SET last_request_id = $1, updated_at = $2
		  WHERE user_id = $3 AND chat_tg_id = $4 AND root_tg_message_id = $5`,
		requestID, time.Now().UTC(), userID, chatTGID, rootMsgID,
	); err != nil {
		return fmt.Errorf("set work item binding request: %w", err)
	}
	return nil
}
