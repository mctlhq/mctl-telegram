package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// NotificationDeliveryUnknown is the owner alert queued when an agent send
// ends in delivery_unknown (#1029). Its own kind, not NotificationAlert, so
// it never counts against the autopilot-pause alert throttle
// (HasOwnerNotificationSince) and that throttle never swallows it.
const NotificationDeliveryUnknown = "delivery_unknown"

// NoteAgentActionSendAttempt counts one send RPC for an executing action and
// returns the new count. The executor calls it immediately before every
// send RPC, so the count is an upper bound on the RPCs that may have reached
// Telegram: an attempt whose stamp committed but whose RPC never left the
// process is counted, never the other way round. ok is false when the row
// is no longer executing (someone else decided it); the caller must not
// send then.
//
// updated_at is left alone: it is the stuck-recovery clock, stamped by the
// reservation, and an attempt is not progress.
func (s *Store) NoteAgentActionSendAttempt(ctx context.Context, userID, id int64) (attempts int, ok bool, err error) {
	err = s.DB.QueryRowContext(ctx,
		`UPDATE agent_actions SET send_attempts = send_attempts + 1
		  WHERE id = $1 AND user_id = $2 AND status = $3
		  RETURNING send_attempts`,
		id, userID, ActionExecuting,
	).Scan(&attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("note send attempt: %w", err)
	}
	return attempts, true, nil
}

// MarkAgentActionDeliveryUnknown moves an executing action to
// delivery_unknown, records reason as its policy_reasons, and queues
// alertBody for the owner, all in one transaction (#1029).
//
// The compare-and-set also requires no noted message id: an echo the
// listener matched in the meantime proves delivery, and the next recovery
// sweep records it executed instead.
//
// The compare-and-set on executing is the notification's dedup: only the
// caller that wins the transition queues the alert, so the owner hears about
// each action exactly once however many recovery sweeps or replicas race on
// it, and a crash cannot commit one without the other. The alert carries no
// action_id: owner_notifications is unique per action_id, and an action that
// went through /mctl approve already holds that slot with its approval
// request, which would silently swallow this alert.
//
// The send body is kept: the listener needs it to recognise the send's echo,
// should it arrive, and prove delivery (MatchUnconfirmedAgentSend). The
// retention sweep clears it later.
func (s *Store) MarkAgentActionDeliveryUnknown(ctx context.Context, userID, id int64, reason, alertBody string) (bool, error) {
	var body []byte
	if alertBody != "" {
		var err error
		body, err = s.Crypt.SealForUser([]byte(alertBody), userID)
		if err != nil {
			return false, fmt.Errorf("seal delivery-unknown alert: %w", err)
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin delivery-unknown tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status = $1, policy_reasons = $2, approval_code = NULL,
		        approval_code_hash = NULL, approval_code_encrypted = NULL, updated_at = $3
		  WHERE id = $4 AND user_id = $5 AND status = $6 AND executed_tg_message_id IS NULL`,
		ActionDeliveryUnknown, reason, time.Now().UTC(), id, userID, ActionExecuting,
	)
	if err != nil {
		return false, fmt.Errorf("mark delivery unknown: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if body != nil {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO owner_notifications(user_id, kind, action_id, body_encrypted, status)
			 VALUES($1,$2,NULL,$3,$4)`,
			userID, NotificationDeliveryUnknown, body, NotificationPending,
		); err != nil {
			return false, fmt.Errorf("queue delivery-unknown alert: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit delivery unknown: %w", err)
	}
	return true, nil
}

// MatchUnconfirmedAgentSend reports whether an outgoing message the listener
// saw without a sent marker is the echo of an agent send whose result the
// process never learned (#1029): a reply still executing (the RPC answer was
// lost, or is still in flight), one in delivery_unknown, or one recorded
// executed with an unknown message id. Such an echo is the agent's own
// message and must not be read as the owner taking over the chat.
//
// The match is on the exact send body (whitespace-trimmed, as Telegram trims
// it) in the same conversation, among actions whose last transition (the
// reservation, the delivery_unknown mark, or the executed record) is not
// older than `since`. Not created_at: a draft can wait for approval for
// as long as the approval TTL allows, and the echo follows the send. Only
// the account's own outgoing messages reach this check, so a peer cannot
// trigger it. On a match the message id is filled in where it was unknown:
// an executing row notes it for RecordAgentActionSent to pick up, a
// delivery_unknown row is proven delivered and moves to executed, and an
// executed row gets its id. Owner text that happens to equal a pending agent
// send byte for byte is indistinguishable from the echo and is treated as
// one; nothing is sent because of the match. The window is kept narrow: a
// send with no attempt stamped yet cannot have an echo, and a send whose id
// is already known has had its echo, so neither matches.
func (s *Store) MatchUnconfirmedAgentSend(ctx context.Context, userID, peerTGID, messageID int64, text string, since time.Time) (bool, error) {
	want := strings.TrimSpace(text)
	if userID <= 0 || messageID <= 0 || want == "" {
		return false, nil
	}
	conv, err := s.GetConversationByPeer(ctx, userID, peerTGID)
	if errors.Is(err, ErrConversationNotFound) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lookup conversation for echo match: %w", err)
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, status, send_body_encrypted FROM agent_actions
		  WHERE user_id = $1 AND conversation_id = $2 AND updated_at >= $3
		    AND send_random_id IS NOT NULL AND send_body_encrypted IS NOT NULL
		    AND executed_tg_message_id IS NULL
		    AND ((status IN ($4, $5) AND send_attempts > 0) OR status = $6)
		  ORDER BY id`,
		userID, conv.ID, since.UTC(), ActionExecuting, ActionDeliveryUnknown, ActionExecuted,
	)
	if err != nil {
		return false, fmt.Errorf("list unconfirmed agent sends: %w", err)
	}
	var (
		matchID     int64
		matchStatus string
		matchBody   string
	)
	for rows.Next() {
		var (
			id     int64
			status string
			sealed []byte
		)
		if err := rows.Scan(&id, &status, &sealed); err != nil {
			_ = rows.Close()
			return false, fmt.Errorf("scan unconfirmed agent send: %w", err)
		}
		pt, err := s.Crypt.OpenForUser(sealed, userID)
		if err != nil {
			slog.Warn("agent_actions: skipping unconfirmed send with undecryptable body", "action_id", id, "user_id", userID, "err", err)
			continue
		}
		if strings.TrimSpace(string(pt)) == want {
			matchID, matchStatus, matchBody = id, status, string(pt)
			break
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return false, fmt.Errorf("list unconfirmed agent sends: %w", err)
	}
	_ = rows.Close()
	if matchID == 0 {
		return false, nil
	}
	switch matchStatus {
	case ActionExecuting:
		if _, err := s.DB.ExecContext(ctx,
			`UPDATE agent_actions SET executed_tg_message_id = $1
			  WHERE id = $2 AND user_id = $3 AND status = $4 AND executed_tg_message_id IS NULL`,
			messageID, matchID, userID, ActionExecuting,
		); err != nil {
			return true, fmt.Errorf("note echoed message id: %w", err)
		}
	case ActionDeliveryUnknown:
		if _, err := s.recordAgentActionSent(ctx, ActionDeliveryUnknown, userID, matchID, conv.ID, messageID, matchBody); err != nil {
			return true, fmt.Errorf("record echoed delivery: %w", err)
		}
	case ActionExecuted:
		if _, err := s.DB.ExecContext(ctx,
			`UPDATE agent_actions SET executed_tg_message_id = $1, send_body_encrypted = NULL
			  WHERE id = $2 AND user_id = $3 AND status = $4 AND executed_tg_message_id IS NULL`,
			messageID, matchID, userID, ActionExecuted,
		); err != nil {
			return true, fmt.Errorf("fill echoed message id: %w", err)
		}
	}
	return true, nil
}
