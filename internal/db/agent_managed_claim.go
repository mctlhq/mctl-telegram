package db

import (
	"context"
	"fmt"
	"time"
)

// ManagedClaimCandidate is a managed account with at least one due job the
// platform pool may claim.
type ManagedClaimCandidate struct {
	UserID     int64
	TelegramID int64
}

// ListManagedClaimCandidates lists managed accounts the pool may claim for:
// runtime managed, current managed consent, at least one due pending job, a
// non-zero Telegram login id, and fewer than maxInflight jobs processing.
// Accounts are ordered by their oldest due job first. Read-only and
// lock-free: the claim itself (SKIP LOCKED plus the runtime predicate) stays
// the only authority, so a stale candidate only costs an empty claim.
func (s *Store) ListManagedClaimCandidates(ctx context.Context, now time.Time, maxInflight, limit int) ([]ManagedClaimCandidate, error) {
	if maxInflight < 1 {
		maxInflight = 1
	}
	if limit < 1 {
		limit = 1
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT ap.user_id, u.telegram_login_id
		   FROM agent_profiles ap
		   JOIN users u      ON u.id = ap.user_id
		   JOIN agent_jobs j ON j.user_id = ap.user_id AND j.status = $1 AND j.next_run_at <= $2
		  WHERE ap.runtime = $3
		    AND ap.managed_consent_version = $4
		    AND u.telegram_login_id IS NOT NULL AND u.telegram_login_id <> 0
		    AND (SELECT COUNT(*) FROM agent_jobs p
		          WHERE p.user_id = ap.user_id AND p.status = $5) < $6
		    -- budget filter (budget_paused_until, slice 4, #1092) goes here
		  GROUP BY ap.user_id, u.telegram_login_id
		  ORDER BY MIN(j.next_run_at), ap.user_id
		  LIMIT $7`,
		JobPending, now.UTC(), RuntimeManaged, ManagedConsentCurrent, JobProcessing, maxInflight, limit)
	if err != nil {
		return nil, fmt.Errorf("list managed claim candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ManagedClaimCandidate
	for rows.Next() {
		var c ManagedClaimCandidate
		if err := rows.Scan(&c.UserID, &c.TelegramID); err != nil {
			return nil, fmt.Errorf("scan managed claim candidate: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
