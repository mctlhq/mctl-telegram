package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// ConnectStep is the last connect:* audit step observed for one user, plus
// the reason (if any) their most recent telegram_accounts row was revoked.
// Used by the daily digest's onboarding-stage suffix (issue-668) — never by
// anything that needs peer_redacted or error, which this deliberately never
// selects.
type ConnectStep struct {
	// Step is the audit_logs.tool_name with the "connect:" prefix stripped,
	// e.g. "phone_submitted" or "failed:flood_wait".
	Step string
	// Status is the audit_logs.status of that row: "ok" or "error".
	Status string
	// At is the audit_logs.created_at of that row.
	At time.Time
	// RevokedReason is telegram_accounts.revoked_reason from the user's most
	// recent session row, when that row was revoked with a recorded reason.
	// Empty when the row was revoked before this column existed, revoked by
	// a path that names no reason, or the most recent row is still active.
	RevokedReason string
}

// LastConnectStepFor returns, for each supplied Telegram id, the most recent
// connect:* audit row (tool_name/status/created_at only — never
// peer_redacted or error) plus the most recent telegram_accounts.revoked_reason
// for that user. Ids with no connect:* audit row are absent from the
// returned map.
//
// Empty tgIDs short-circuits to an empty map without touching the database:
// building "IN ()" is a syntax error on both SQLite and Postgres.
func (s *Store) LastConnectStepFor(ctx context.Context, tgIDs []int64) (map[int64]ConnectStep, error) {
	out := make(map[int64]ConnectStep)
	if len(tgIDs) == 0 {
		return out, nil
	}

	placeholders := make([]string, len(tgIDs))
	args := make([]any, len(tgIDs))
	for i, id := range tgIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	inClause := "(" + strings.Join(placeholders, ",") + ")"

	// Correlated MAX(id) rather than a window function: portable across
	// SQLite and Postgres, mirroring ttlExemptClause's IN-list-building
	// precedent (store.go). Only tool_name/status/created_at cross the
	// boundary — peer_redacted and error are never selected, so no Telegram
	// peer identifier or RPC error string can reach the digest message.
	rows, err := s.DB.QueryContext(ctx,
		`SELECT u.telegram_login_id, a.tool_name, a.status, a.created_at
		   FROM audit_logs a
		   JOIN users u ON u.id = a.user_id
		  WHERE u.telegram_login_id IN `+inClause+`
		    AND a.tool_name LIKE 'connect:%'
		    AND a.id = (SELECT MAX(a2.id) FROM audit_logs a2
		                 WHERE a2.user_id = a.user_id
		                   AND a2.tool_name LIKE 'connect:%')`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("last connect step: %w", err)
	}
	func() {
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				tgID     int64
				toolName string
				status   string
				at       time.Time
			)
			if scanErr := rows.Scan(&tgID, &toolName, &status, &at); scanErr != nil {
				err = fmt.Errorf("scan connect step: %w", scanErr)
				return
			}
			out[tgID] = ConnectStep{
				Step:   strings.TrimPrefix(toolName, "connect:"),
				Status: status,
				At:     at,
			}
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			err = fmt.Errorf("last connect step: %w", rowsErr)
		}
	}()
	if err != nil {
		return nil, err
	}

	// Second statement, same method: the user's single most recent
	// telegram_accounts row (by id, the same recency proxy used above), and
	// its revoked_reason when that row was in fact revoked with one. A user
	// whose latest row is still active or was revoked with no reason simply
	// contributes nothing here — the connect-step map entry above (if any)
	// is untouched.
	revRows, err := s.DB.QueryContext(ctx,
		`SELECT u.telegram_login_id, ta.revoked_reason
		   FROM telegram_accounts ta
		   JOIN users u ON u.id = ta.user_id
		  WHERE u.telegram_login_id IN `+inClause+`
		    AND ta.revoked_reason IS NOT NULL
		    AND ta.id = (SELECT MAX(ta2.id) FROM telegram_accounts ta2
		                  WHERE ta2.user_id = ta.user_id)`,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("last revoked reason: %w", err)
	}
	defer func() { _ = revRows.Close() }()
	for revRows.Next() {
		var (
			tgID   int64
			reason sql.NullString
		)
		if err := revRows.Scan(&tgID, &reason); err != nil {
			return nil, fmt.Errorf("scan revoked reason: %w", err)
		}
		if !reason.Valid || reason.String == "" {
			continue
		}
		cs := out[tgID]
		cs.RevokedReason = reason.String
		out[tgID] = cs
	}
	if err := revRows.Err(); err != nil {
		return nil, fmt.Errorf("last revoked reason: %w", err)
	}

	return out, nil
}
