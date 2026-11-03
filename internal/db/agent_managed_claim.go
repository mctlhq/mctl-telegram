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

// CountManagedAccountsWithPendingJobs counts accounts on runtime managed that
// have at least one pending job. Used to surface that those jobs are paused
// while MANAGED_RUNTIME_ENABLED is off.
func (s *Store) CountManagedAccountsWithPendingJobs(ctx context.Context) (int, error) {
	var n int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT ap.user_id)
		   FROM agent_profiles ap
		   JOIN agent_jobs j ON j.user_id = ap.user_id AND j.status = $1
		  WHERE ap.runtime = $2`,
		JobPending, RuntimeManaged).Scan(&n); err != nil {
		return 0, fmt.Errorf("count managed accounts with pending jobs: %w", err)
	}
	return n, nil
}

// ListManagedClaimCandidates lists managed accounts the pool may claim for:
// runtime managed, current managed consent, at least one due pending job the
// claim could actually take (the claim's per-conversation predicate: no
// earlier job of the conversation pending or processing), a non-zero
// Telegram login id, and fewer than maxInflight jobs processing. Accounts are
// ordered by their oldest claimable job first; offset and limit page through
// that order. Read-only and lock-free: the claim itself
// (Store.ClaimManagedAgentJobs) stays the only authority, so a stale
// candidate only costs an empty claim.
func (s *Store) ListManagedClaimCandidates(ctx context.Context, now time.Time, maxInflight, offset, limit int) ([]ManagedClaimCandidate, error) {
	if maxInflight < 1 {
		maxInflight = 1
	}
	if limit < 1 {
		limit = 1
	}
	if offset < 0 {
		offset = 0
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
		    AND NOT EXISTS (
		        SELECT 1 FROM agent_jobs b
		         WHERE b.conversation_id = j.conversation_id
		           AND (b.status = $5 OR (b.status = $1 AND b.id < j.id))
		    )
		    -- budget filter (budget_paused_until, slice 4, #1092) goes here
		  GROUP BY ap.user_id, u.telegram_login_id
		  ORDER BY MIN(j.next_run_at), ap.user_id
		  LIMIT $7 OFFSET $8`,
		JobPending, now.UTC(), RuntimeManaged, ManagedConsentCurrent, JobProcessing, maxInflight, limit, offset)
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
