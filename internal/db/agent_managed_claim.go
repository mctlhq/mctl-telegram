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
	// Cursor positions the next page after this candidate.
	Cursor ManagedClaimCursor
}

// ManagedClaimCursor is a keyset position in the candidate order
// (oldest claimable job, then user id). It is opaque: oldest holds the
// aggregate exactly as the driver returned it, so it compares in the stored
// representation of the dialect that produced it.
type ManagedClaimCursor struct {
	oldest any
	userID int64
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
// ordered by their oldest claimable job, then user id; after (nil for the
// first page) continues strictly after a candidate of a previous page. It is
// a keyset, not an offset, because the list changes while the pool walks it:
// an account served from one page drops out, and an offset would then skip
// as many accounts on the next. Read-only and lock-free: the claim itself
// (Store.ClaimManagedAgentJobs) stays the only authority, so a stale
// candidate only costs an empty claim.
func (s *Store) ListManagedClaimCandidates(ctx context.Context, now time.Time, maxInflight int, after *ManagedClaimCursor, limit int) ([]ManagedClaimCandidate, error) {
	if maxInflight < 1 {
		maxInflight = 1
	}
	if limit < 1 {
		limit = 1
	}
	args := []any{JobPending, now.UTC(), RuntimeManaged, ManagedConsentCurrent, JobProcessing, maxInflight, limit}
	having := ""
	if after != nil {
		having = `
		 HAVING MIN(j.next_run_at) > $8 OR (MIN(j.next_run_at) = $8 AND ap.user_id > $9)`
		args = append(args, after.oldest, after.userID)
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT ap.user_id, u.telegram_login_id, MIN(j.next_run_at)
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
		  GROUP BY ap.user_id, u.telegram_login_id`+having+`
		  ORDER BY MIN(j.next_run_at), ap.user_id
		  LIMIT $7`,
		args...)
	if err != nil {
		return nil, fmt.Errorf("list managed claim candidates: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ManagedClaimCandidate
	for rows.Next() {
		var c ManagedClaimCandidate
		if err := rows.Scan(&c.UserID, &c.TelegramID, &c.Cursor.oldest); err != nil {
			return nil, fmt.Errorf("scan managed claim candidate: %w", err)
		}
		c.Cursor.userID = c.UserID
		out = append(out, c)
	}
	return out, rows.Err()
}
