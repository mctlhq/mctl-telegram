package db

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Delivery states (broadcast_deliveries.status).
const (
	DeliveryPending   = "pending"
	DeliverySending   = "sending"
	DeliveryDelivered = "delivered"
	DeliverySkipped   = "skipped"
	DeliveryFailed    = "failed"
)

// Delivery reason codes the store itself assigns. The worker adds skip
// reasons and classifier reason codes on top.
const (
	// ReasonCancelled: the campaign was cancelled before this recipient
	// was sent to.
	ReasonCancelled = "cancelled"
	// ReasonOutcomeUnknown: the row was found in sending after its lease
	// expired (a crash or a hung request mid-send). Whether Telegram
	// delivered it cannot be known, and re-sending could duplicate the
	// message, so it is closed as failed instead.
	ReasonOutcomeUnknown = "outcome_unknown"
)

// ErrCampaignNotApproved is returned by StartBroadcastCampaign when the
// campaign is not (or no longer) in the approved state.
var ErrCampaignNotApproved = errors.New("broadcast campaign is not approved")

// ErrCampaignNotSending is returned by HaltBroadcastCampaign when the
// campaign is not (or no longer) sending.
var ErrCampaignNotSending = errors.New("broadcast campaign is not sending")

// BroadcastRecipient is one materialized delivery target.
type BroadcastRecipient struct {
	UserID     int64
	TelegramID int64
}

// BroadcastDelivery is one claimed row, as the worker sees it.
type BroadcastDelivery struct {
	CampaignID string
	UserID     int64
	TelegramID int64
	Attempts   int
}

// StartBroadcastCampaign moves an approved campaign to sending and queues
// one pending delivery per recipient, in one transaction. Materialization is
// idempotent twice over: the state guard lets only one caller start the
// campaign, and the (campaign_id, user_id) primary key makes a re-queued
// recipient a no-op.
func (s *Store) StartBroadcastCampaign(ctx context.Context, id string, recipients []BroadcastRecipient, now time.Time) error {
	now = now.UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("start broadcast campaign: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx,
		`UPDATE broadcast_campaigns SET state = $2, updated_at = $3 WHERE id = $1 AND state = $4`,
		id, CampaignSending, now, CampaignApproved)
	if err != nil {
		return fmt.Errorf("start broadcast campaign: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrCampaignNotApproved
	}
	for _, r := range recipients {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO broadcast_deliveries(campaign_id, user_id, telegram_id, status, next_attempt_at, created_at, updated_at)
			 VALUES($1,$2,$3,$4,$5,$5,$5)
			 ON CONFLICT (campaign_id, user_id) DO NOTHING`,
			id, r.UserID, r.TelegramID, DeliveryPending, now); err != nil {
			return fmt.Errorf("start broadcast campaign: queue recipient: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("start broadcast campaign: commit: %w", err)
	}
	return nil
}

// EndBroadcastCampaign ends an approved campaign without delivering it:
// state becomes toState (completed or cancelled) with endReason recorded.
// Used when the audience at execution time is empty or over the limit.
func (s *Store) EndBroadcastCampaign(ctx context.Context, id, toState, endReason string, now time.Time) error {
	if toState != CampaignCompleted && toState != CampaignCancelled {
		return fmt.Errorf("end broadcast campaign: invalid target state %q", toState)
	}
	now = now.UTC()
	res, err := s.DB.ExecContext(ctx,
		`UPDATE broadcast_campaigns SET state = $2, end_reason = $3, completed_at = $4, updated_at = $4
		  WHERE id = $1 AND state = $5`,
		id, toState, endReason, now, CampaignApproved)
	if err != nil {
		return fmt.Errorf("end broadcast campaign: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrCampaignNotApproved
	}
	return nil
}

// HaltBroadcastCampaign cancels a campaign that is already sending, with
// endReason recorded. Its remaining pending rows are then skipped by
// SkipCancelledBroadcastDeliveries. Used when a campaign fails its integrity
// check mid-send: nothing more of it may go out.
func (s *Store) HaltBroadcastCampaign(ctx context.Context, id, endReason string, now time.Time) error {
	now = now.UTC()
	res, err := s.DB.ExecContext(ctx,
		`UPDATE broadcast_campaigns SET state = $2, end_reason = $3, completed_at = $4, updated_at = $4
		  WHERE id = $1 AND state = $5`,
		id, CampaignCancelled, endReason, now, CampaignSending)
	if err != nil {
		return fmt.Errorf("halt broadcast campaign: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("halt broadcast campaign: %w", err)
	} else if n != 1 {
		return ErrCampaignNotSending
	}
	return nil
}

// ClaimBroadcastDeliveries claims up to limit due pending deliveries of
// campaigns that are sending, marking them sending and counting the
// attempt. Oldest first, so one campaign drains in queue order.
func (s *Store) ClaimBroadcastDeliveries(ctx context.Context, limit int, now time.Time) ([]BroadcastDelivery, error) {
	if limit <= 0 {
		limit = 1
	}
	now = now.UTC()
	lock := ""
	if s.isPostgres(ctx) {
		lock = " FOR UPDATE OF d SKIP LOCKED"
	}
	// The due rows are picked in a CTE, not an IN (subquery ... LIMIT):
	// Postgres may re-evaluate an IN subquery (it plans it as a join), and a
	// LIMIT inside it was observed claiming 3 rows for limit 2. A CTE with
	// FOR UPDATE is never inlined, so it is evaluated exactly once.
	//
	// The outer UPDATE re-checks status = pending, which is what makes a
	// concurrent double-select safe without SKIP LOCKED (SQLite): the
	// loser re-evaluates the predicate against the winner's committed row
	// and skips it.
	rows, err := s.DB.QueryContext(ctx,
		`WITH due AS (
		        SELECT d.campaign_id, d.user_id
		          FROM broadcast_deliveries d
		          JOIN broadcast_campaigns c ON c.id = d.campaign_id
		         WHERE d.status = $3 AND d.next_attempt_at <= $2 AND c.state = $4
		         ORDER BY d.next_attempt_at, d.created_at, d.user_id
		         LIMIT $5`+lock+`
		)
		UPDATE broadcast_deliveries
		    SET status = $1, attempts = attempts + 1, claimed_at = $2, updated_at = $2
		  WHERE status = $3 AND (campaign_id, user_id) IN (SELECT campaign_id, user_id FROM due)
		 RETURNING campaign_id, user_id, telegram_id, attempts`,
		DeliverySending, now, DeliveryPending, CampaignSending, limit)
	if err != nil {
		return nil, fmt.Errorf("claim broadcast deliveries: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []BroadcastDelivery
	for rows.Next() {
		var d BroadcastDelivery
		if err := rows.Scan(&d.CampaignID, &d.UserID, &d.TelegramID, &d.Attempts); err != nil {
			return nil, fmt.Errorf("claim broadcast deliveries: scan: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// FinishBroadcastDelivery closes a claimed delivery as delivered, skipped or
// failed. It only moves a row that is still sending, so a row the stale
// sweep has already closed as outcome_unknown is never overwritten.
func (s *Store) FinishBroadcastDelivery(ctx context.Context, campaignID string, userID int64, status, reason string, now time.Time) error {
	switch status {
	case DeliveryDelivered, DeliverySkipped, DeliveryFailed:
	default:
		return fmt.Errorf("finish broadcast delivery: invalid status %q", status)
	}
	now = now.UTC()
	_, err := s.DB.ExecContext(ctx,
		`UPDATE broadcast_deliveries SET status = $3, reason = $4, finished_at = $5, updated_at = $5
		  WHERE campaign_id = $1 AND user_id = $2 AND status = $6`,
		campaignID, userID, status, reason, now, DeliverySending)
	if err != nil {
		return fmt.Errorf("finish broadcast delivery: %w", err)
	}
	return nil
}

// RetryBroadcastDelivery returns a claimed delivery to pending, due at
// nextAttempt, recording the transient reason.
func (s *Store) RetryBroadcastDelivery(ctx context.Context, campaignID string, userID int64, reason string, nextAttempt, now time.Time) error {
	now = now.UTC()
	_, err := s.DB.ExecContext(ctx,
		`UPDATE broadcast_deliveries SET status = $3, reason = $4, next_attempt_at = $5, claimed_at = NULL, updated_at = $6
		  WHERE campaign_id = $1 AND user_id = $2 AND status = $7`,
		campaignID, userID, DeliveryPending, reason, nextAttempt.UTC(), now, DeliverySending)
	if err != nil {
		return fmt.Errorf("retry broadcast delivery: %w", err)
	}
	return nil
}

// ReleaseBroadcastDelivery hands a claimed row back to pending WITHOUT
// counting the attempt: for a row the worker claimed but never sent (a
// store error earlier in the batch, shutdown while waiting for the rate
// limiter, or a lease too close to expiry). Like Finish, it only moves a
// row that is still sending, so a row the stale sweep already closed
// stays closed.
func (s *Store) ReleaseBroadcastDelivery(ctx context.Context, campaignID string, userID int64, now time.Time) error {
	now = now.UTC()
	_, err := s.DB.ExecContext(ctx,
		`UPDATE broadcast_deliveries SET status = $3, attempts = attempts - 1, claimed_at = NULL, updated_at = $4
		  WHERE campaign_id = $1 AND user_id = $2 AND status = $5`,
		campaignID, userID, DeliveryPending, now, DeliverySending)
	if err != nil {
		return fmt.Errorf("release broadcast delivery: %w", err)
	}
	return nil
}

// FailStaleBroadcastDeliveries closes every delivery that has been in
// sending since before now-lease as failed/outcome_unknown. At-most-once
// by design: a message whose send may or may not have reached Telegram is
// never sent a second time.
func (s *Store) FailStaleBroadcastDeliveries(ctx context.Context, lease time.Duration, now time.Time) (int64, error) {
	now = now.UTC()
	res, err := s.DB.ExecContext(ctx,
		`UPDATE broadcast_deliveries SET status = $1, reason = $2, finished_at = $3, updated_at = $3
		  WHERE status = $4 AND claimed_at < $5`,
		DeliveryFailed, ReasonOutcomeUnknown, now, DeliverySending, now.Add(-lease))
	if err != nil {
		return 0, fmt.Errorf("fail stale broadcast deliveries: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// SkipCancelledBroadcastDeliveries closes every still-pending delivery of a
// cancelled campaign as skipped/cancelled. Rows already delivered stay
// delivered.
func (s *Store) SkipCancelledBroadcastDeliveries(ctx context.Context, now time.Time) (int64, error) {
	now = now.UTC()
	res, err := s.DB.ExecContext(ctx,
		`UPDATE broadcast_deliveries SET status = $1, reason = $2, finished_at = $3, updated_at = $3
		  WHERE status = $4 AND campaign_id IN (SELECT id FROM broadcast_campaigns WHERE state = $5)`,
		DeliverySkipped, ReasonCancelled, now, DeliveryPending, CampaignCancelled)
	if err != nil {
		return 0, fmt.Errorf("skip cancelled broadcast deliveries: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// CompleteBroadcastCampaigns marks every sending campaign with no pending or
// in-flight delivery left as completed, returning the ids it completed.
func (s *Store) CompleteBroadcastCampaigns(ctx context.Context, now time.Time) ([]string, error) {
	now = now.UTC()
	rows, err := s.DB.QueryContext(ctx,
		`UPDATE broadcast_campaigns SET state = $1, completed_at = $2, updated_at = $2
		  WHERE state = $3 AND NOT EXISTS (
		        SELECT 1 FROM broadcast_deliveries d
		         WHERE d.campaign_id = broadcast_campaigns.id AND d.status IN ($4, $5))
		 RETURNING id`,
		CampaignCompleted, now, CampaignSending, DeliveryPending, DeliverySending)
	if err != nil {
		return nil, fmt.Errorf("complete broadcast campaigns: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("complete broadcast campaigns: scan: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// DeliveryCount is one (status, reason) bucket of a campaign's deliveries.
type DeliveryCount struct {
	Status string
	Reason string
	Count  int
}

// BroadcastDeliveryCounts returns a campaign's deliveries grouped by status
// and reason, in a stable order. Aggregate only: no recipient identity.
func (s *Store) BroadcastDeliveryCounts(ctx context.Context, campaignID string) ([]DeliveryCount, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT status, reason, COUNT(*) FROM broadcast_deliveries
		  WHERE campaign_id = $1 GROUP BY status, reason ORDER BY status, reason`, campaignID)
	if err != nil {
		return nil, fmt.Errorf("broadcast delivery counts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []DeliveryCount
	for rows.Next() {
		var c DeliveryCount
		if err := rows.Scan(&c.Status, &c.Reason, &c.Count); err != nil {
			return nil, fmt.Errorf("broadcast delivery counts: scan: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
