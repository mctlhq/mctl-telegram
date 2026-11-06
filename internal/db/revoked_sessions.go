package db

import (
	"context"
	"database/sql"
	"fmt"
)

// RevokedSessionBlob is a revoked row that still holds a sealed session.
type RevokedSessionBlob struct {
	ID             int64
	UserID         int64
	TelegramUserID int64
	Reason         string
	Sealed         []byte
}

// RevokedSessionsWithBlob lists revoked rows that still hold a sealed session,
// by ascending id, starting after afterID. Every revocation path erases the
// session now, so this only finds rows revoked before that.
func (s *Store) RevokedSessionsWithBlob(ctx context.Context, afterID int64, limit int) ([]RevokedSessionBlob, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, user_id, telegram_user_id, revoked_reason, session_encrypted
		   FROM telegram_accounts
		  WHERE revoked_at IS NOT NULL AND session_encrypted IS NOT NULL AND id > $1
		  ORDER BY id LIMIT $2`, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list revoked sessions: %w", err)
	}
	defer rows.Close()
	var out []RevokedSessionBlob
	for rows.Next() {
		var r RevokedSessionBlob
		var tgID sql.NullInt64
		var reason sql.NullString
		if err := rows.Scan(&r.ID, &r.UserID, &tgID, &reason, &r.Sealed); err != nil {
			return nil, fmt.Errorf("list revoked sessions: scan: %w", err)
		}
		r.TelegramUserID, r.Reason = tgID.Int64, reason.String
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list revoked sessions: %w", err)
	}
	return out, nil
}

// OpenRevokedSession decrypts the sealed session of a revoked row.
func (s *Store) OpenRevokedSession(r RevokedSessionBlob) ([]byte, error) {
	data, err := s.Crypt.OpenForUser(r.Sealed, r.UserID)
	if err != nil {
		return nil, fmt.Errorf("open revoked session: %w", err)
	}
	return data, nil
}

// ActiveSessionsSharingAccount returns the decrypted sessions of the active
// rows of a user or a Telegram account. One unreadable row fails the whole
// call: the caller uses this to prove a logout will not end a session in use,
// and a row it could not read proves nothing.
func (s *Store) ActiveSessionsSharingAccount(ctx context.Context, userID, telegramUserID int64) ([][]byte, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT user_id, session_encrypted FROM telegram_accounts
		  WHERE revoked_at IS NULL AND session_encrypted IS NOT NULL
		    AND (user_id = $1 OR telegram_user_id = $2)`, userID, telegramUserID)
	if err != nil {
		return nil, fmt.Errorf("list active sessions: %w", err)
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var owner int64
		var sealed []byte
		if err := rows.Scan(&owner, &sealed); err != nil {
			return nil, fmt.Errorf("list active sessions: scan: %w", err)
		}
		data, err := s.Crypt.OpenForUser(sealed, owner)
		if err != nil {
			return nil, fmt.Errorf("list active sessions: open: %w", err)
		}
		out = append(out, data)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active sessions: %w", err)
	}
	return out, nil
}

// EraseRevokedSession erases the sealed session of a row. A row that is not
// revoked is left alone, so this can never remove a session in use.
func (s *Store) EraseRevokedSession(ctx context.Context, id int64) error {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET session_encrypted = NULL
		  WHERE id = $1 AND revoked_at IS NOT NULL`, id); err != nil {
		return fmt.Errorf("erase revoked session: %w", err)
	}
	return nil
}
