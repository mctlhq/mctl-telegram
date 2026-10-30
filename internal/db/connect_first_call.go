package db

import (
	"context"
	"fmt"
	"time"
)

// Outcomes a connect_first_call row can be classified with (issue #960).
// A NULL outcome is an open row: its grant has not been matched to a call
// yet and its window has not been judged.
const (
	ConnectOutcomeOK      = "ok"
	ConnectOutcomeNone    = "none_within_window"
	ConnectOutcomeUnknown = "unknown"
)

// InsertConnectGrant records one authorization_code grant as an open row.
// client is the bounded label (claude, chatgpt, other); clientID is kept
// only so CloseConnectGrants can match the first call to this grant.
func (s *Store) InsertConnectGrant(ctx context.Context, userID int64, clientID, client string, grantedAt time.Time) error {
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO connect_first_call (user_id, client_id, client, granted_at) VALUES ($1, $2, $3, $4)`,
		userID, clientID, client, grantedAt.UTC(),
	); err != nil {
		return fmt.Errorf("insert connect grant: %w", err)
	}
	return nil
}

// CloseConnectGrants marks as ok every open row of (userID, clientID) whose
// grant was at most window before callAt and not after it, and returns the
// client label of each row it closed. The WHERE outcome IS NULL guard is what
// makes a close exactly-once: a concurrent close or a retry of the same call
// matches no row the first one already closed, so the caller counts each row
// once by counting what this returns.
//
// A grant older than window before the call stays open: its first call came
// too late, and the reconciler classifies it as none_within_window.
func (s *Store) CloseConnectGrants(ctx context.Context, userID int64, clientID string, callAt time.Time, window time.Duration, now time.Time) ([]string, error) {
	return s.classifyConnectRows(ctx,
		`UPDATE connect_first_call SET outcome = $1, reason = '', classified_at = $2
		 WHERE outcome IS NULL AND user_id = $3 AND client_id = $4
		   AND granted_at >= $5 AND granted_at <= $6
		 RETURNING client`,
		ConnectOutcomeOK, now.UTC(), userID, clientID, callAt.Add(-window).UTC(), callAt.UTC(),
	)
}

// ClassifyOpenConnectGrants sets outcome and reason on every still-open row
// granted in [from, to) and returns the client label of each row it
// classified. The caller picks to so that only rows whose window is over are
// touched; like CloseConnectGrants, the WHERE outcome IS NULL guard makes each
// row's classification happen once.
func (s *Store) ClassifyOpenConnectGrants(ctx context.Context, from, to time.Time, outcome, reason string, now time.Time) ([]string, error) {
	return s.classifyConnectRows(ctx,
		`UPDATE connect_first_call SET outcome = $1, reason = $2, classified_at = $3
		 WHERE outcome IS NULL AND granted_at >= $4 AND granted_at < $5
		 RETURNING client`,
		outcome, reason, now.UTC(), from.UTC(), to.UTC(),
	)
}

func (s *Store) classifyConnectRows(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("classify connect grants: %w", err)
	}
	defer rows.Close()
	var clients []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, fmt.Errorf("classify connect grants: scan: %w", err)
		}
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("classify connect grants: %w", err)
	}
	return clients, nil
}

// SweepConnectGrants deletes rows classified before cutoff and returns how
// many it removed. Open rows are never deleted here, since they still owe the
// counter an outcome: their classified_at is NULL, which no comparison
// matches.
func (s *Store) SweepConnectGrants(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM connect_first_call WHERE classified_at < $1`,
		cutoff.UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("sweep connect grants: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
