package broadcast

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"golang.org/x/time/rate"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// Worker defaults for WorkerConfig fields left at zero.
const (
	DefaultRatePerSecond = 10 // well under Telegram's ~30 msg/s bot-wide limit
	DefaultMaxAttempts   = 5
	DefaultBaseBackoff   = 30 * time.Second
	DefaultMaxBackoff    = 30 * time.Minute
	DefaultLease         = 2 * time.Minute
	DefaultTickInterval  = 5 * time.Second
	// sendTimeout bounds one Bot API call; it must stay well inside Lease so
	// a row is never swept as outcome_unknown while its request can still
	// complete.
	sendTimeout = 15 * time.Second
	minLease    = 2 * sendTimeout
)

// Campaign end reasons recorded by the worker (broadcast_campaigns.end_reason).
const (
	EndNoEligibleRecipients = "no_eligible_recipients_at_send"
	EndRecipientLimit       = "recipient_limit_exceeded_at_send"
	EndIntegrity            = "content_or_selector_integrity_mismatch"
)

// Delivery reason codes the worker assigns beyond skip reasons and the
// classifier's own codes.
const (
	ReasonRetriesExhausted = "retries_exhausted"
	ReasonTransient        = "transient"
	ReasonRejected         = "rejected"
)

// Sender is the one outbound capability the worker needs.
type Sender interface {
	SendMessage(ctx context.Context, chatID int64, text string) error
}

// WorkerStore is the subset of *db.Store the worker uses.
type WorkerStore interface {
	ListBroadcastCampaigns(ctx context.Context, limit int, states ...string) ([]db.BroadcastCampaign, error)
	GetBroadcastCampaign(ctx context.Context, id string) (*db.BroadcastCampaign, error)
	ListBroadcastRecipientFacts(ctx context.Context, now time.Time) ([]db.BroadcastRecipientFacts, error)
	GetBroadcastRecipientFacts(ctx context.Context, userID int64, now time.Time) (*db.BroadcastRecipientFacts, error)
	StartBroadcastCampaign(ctx context.Context, id string, recipients []db.BroadcastRecipient, now time.Time) error
	EndBroadcastCampaign(ctx context.Context, id, toState, endReason string, now time.Time) error
	HaltBroadcastCampaign(ctx context.Context, id, endReason string, now time.Time) error
	ClaimBroadcastDeliveries(ctx context.Context, limit int, now time.Time) ([]db.BroadcastDelivery, error)
	FinishBroadcastDelivery(ctx context.Context, campaignID string, userID int64, status, reason string, now time.Time) error
	RetryBroadcastDelivery(ctx context.Context, campaignID string, userID int64, reason string, nextAttempt, now time.Time) error
	ReleaseBroadcastDelivery(ctx context.Context, campaignID string, userID int64, now time.Time) error
	FailStaleBroadcastDeliveries(ctx context.Context, lease time.Duration, now time.Time) (int64, error)
	SkipCancelledBroadcastDeliveries(ctx context.Context, now time.Time) (int64, error)
	CompleteBroadcastCampaigns(ctx context.Context, now time.Time) ([]string, error)
	ExpireBroadcastCampaigns(ctx context.Context, now time.Time) (int64, error)
	RecordBotReachability(ctx context.Context, userID int64, outcome notify.DeliveryOutcome, source string) error
}

// WorkerConfig tunes delivery.
type WorkerConfig struct {
	Policy        Policy
	RatePerSecond float64
	BatchSize     int
	MaxAttempts   int
	BaseBackoff   time.Duration
	MaxBackoff    time.Duration
	Lease         time.Duration
}

func (c WorkerConfig) withDefaults() WorkerConfig {
	if c.RatePerSecond <= 0 {
		c.RatePerSecond = DefaultRatePerSecond
	}
	if c.BatchSize <= 0 {
		c.BatchSize = DefaultBatchSize
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = DefaultMaxAttempts
	}
	if c.BaseBackoff <= 0 {
		c.BaseBackoff = DefaultBaseBackoff
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = DefaultMaxBackoff
	}
	if c.Lease <= 0 {
		c.Lease = DefaultLease
	}
	// deliver refuses to start a send once less than sendTimeout of the
	// lease is left, so a lease shorter than that would never send anything.
	if c.Lease < minLease {
		c.Lease = minLease
	}
	return c
}

// Worker delivers approved campaigns. It is the only code path that sends a
// broadcast message, and it only ever sends to a row it materialized from a
// campaign a human approved.
type Worker struct {
	store   WorkerStore
	sender  Sender
	cfg     WorkerConfig
	limiter *rate.Limiter
	now     func() time.Time
}

// NewWorker builds a Worker. now may be nil (time.Now).
func NewWorker(store WorkerStore, sender Sender, cfg WorkerConfig, now func() time.Time) *Worker {
	cfg = cfg.withDefaults()
	if now == nil {
		now = time.Now
	}
	return &Worker{
		store:   store,
		sender:  sender,
		cfg:     cfg,
		limiter: rate.NewLimiter(rate.Limit(cfg.RatePerSecond), 1),
		now:     now,
	}
}

// Run ticks until ctx is cancelled.
func (w *Worker) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultTickInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := w.Tick(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("broadcast: delivery tick failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Tick performs one pass: close stale in-flight rows, expire unapproved
// campaigns, start newly approved ones, drop work of cancelled ones, send one
// batch, and complete campaigns with nothing left to do.
func (w *Worker) Tick(ctx context.Context) error {
	now := w.now().UTC()
	if n, err := w.store.FailStaleBroadcastDeliveries(ctx, w.cfg.Lease, now); err != nil {
		return err
	} else if n > 0 {
		slog.Warn("broadcast: closed in-flight deliveries with unknown outcome", "count", n)
	}
	if _, err := w.store.ExpireBroadcastCampaigns(ctx, now); err != nil {
		return err
	}
	if err := w.startApproved(ctx, now); err != nil {
		return err
	}
	if _, err := w.store.SkipCancelledBroadcastDeliveries(ctx, now); err != nil {
		return err
	}
	claimed, err := w.store.ClaimBroadcastDeliveries(ctx, w.cfg.BatchSize, now)
	if err != nil {
		return err
	}
	for i, d := range claimed {
		if err := w.deliver(ctx, d, now); err != nil {
			// The rest of the batch was claimed but never attempted: hand it
			// back now instead of leaving it for the stale sweep, which
			// would close every row as outcome_unknown.
			w.release(ctx, claimed[i+1:])
			return err
		}
	}
	done, err := w.store.CompleteBroadcastCampaigns(ctx, w.now())
	if err != nil {
		return err
	}
	for _, id := range done {
		slog.Info("broadcast: campaign completed", "campaign_id", id)
	}
	return nil
}

// startApproved resolves each approved campaign's audience AGAIN, at
// execution time, and queues exactly that audience. Anyone who unsubscribed,
// was banned or became unreachable since the preview is not queued.
func (w *Worker) startApproved(ctx context.Context, now time.Time) error {
	approved, err := w.store.ListBroadcastCampaigns(ctx, 200, db.CampaignApproved)
	if err != nil {
		return err
	}
	if len(approved) == 0 {
		return nil
	}
	facts, err := w.store.ListBroadcastRecipientFacts(ctx, now)
	if err != nil {
		return err
	}
	for _, c := range approved {
		sel, err := campaignSelector(&c)
		if err != nil {
			if err := w.store.EndBroadcastCampaign(ctx, c.ID, db.CampaignCancelled, EndIntegrity, now); err != nil && !errors.Is(err, db.ErrCampaignNotApproved) {
				return err
			}
			slog.Error("broadcast: campaign failed integrity check at start; cancelled", "campaign_id", c.ID)
			continue
		}
		eligible, counts := Resolve(sel, facts, w.cfg.Policy, now)
		var endReason string
		switch {
		case counts.Eligible == 0:
			endReason = EndNoEligibleRecipients
		case counts.Eligible > c.RecipientLimit:
			endReason = EndRecipientLimit
		}
		if endReason != "" {
			to := db.CampaignCompleted
			if endReason == EndRecipientLimit {
				to = db.CampaignCancelled
			}
			if err := w.store.EndBroadcastCampaign(ctx, c.ID, to, endReason, now); err != nil && !errors.Is(err, db.ErrCampaignNotApproved) {
				return err
			}
			slog.Info("broadcast: campaign ended at start", "campaign_id", c.ID, "reason", endReason, "eligible", counts.Eligible)
			continue
		}
		recipients := make([]db.BroadcastRecipient, len(eligible))
		for i, f := range eligible {
			recipients[i] = db.BroadcastRecipient{UserID: f.UserID, TelegramID: f.TelegramID}
		}
		if err := w.store.StartBroadcastCampaign(ctx, c.ID, recipients, now); err != nil {
			if errors.Is(err, db.ErrCampaignNotApproved) {
				continue // cancelled between list and start
			}
			return err
		}
		slog.Info("broadcast: campaign started", "campaign_id", c.ID, "queued", len(recipients))
	}
	return nil
}

// campaignSelector re-verifies the stored content and selector against the
// hashes the approval was bound to and returns the selector. A mismatch
// means the row changed after approval; it is never delivered.
func campaignSelector(c *db.BroadcastCampaign) (Selector, error) {
	if Hash(c.Content) != c.ContentHash || Hash(c.SelectorJSON) != c.SelectorHash {
		return Selector{}, db.ErrCampaignMismatch
	}
	var sel Selector
	if err := json.Unmarshal([]byte(c.SelectorJSON), &sel); err != nil {
		return Selector{}, fmt.Errorf("decode selector: %w", err)
	}
	return sel.Normalize()
}

// release hands claimed-but-unattempted rows back to pending without
// counting the attempt. Best effort: a row it cannot release stays in
// sending and is closed by the stale sweep, which never re-sends.
func (w *Worker) release(ctx context.Context, rows []db.BroadcastDelivery) {
	ctx = context.WithoutCancel(ctx)
	for _, d := range rows {
		if err := w.store.ReleaseBroadcastDelivery(ctx, d.CampaignID, d.UserID, w.now()); err != nil {
			slog.Warn("broadcast: release claimed delivery", "campaign_id", d.CampaignID, "err", err)
		}
	}
}

// deliver handles one claimed row. Every check that can stop a send happens
// here, immediately before it: the campaign must still be sending and intact,
// and the recipient must still be eligible under the campaign's selector.
//
// An error before the send releases the row (nothing went out); an error
// after it leaves the row in sending for the stale sweep, because whether
// the message was delivered is then unknown.
func (w *Worker) deliver(ctx context.Context, d db.BroadcastDelivery, claimedAt time.Time) error {
	finish := func(status, reason string) error {
		return w.store.FinishBroadcastDelivery(ctx, d.CampaignID, d.UserID, status, reason, w.now())
	}
	preSend := func(err error) error {
		w.release(ctx, []db.BroadcastDelivery{d})
		return err
	}
	c, err := w.store.GetBroadcastCampaign(ctx, d.CampaignID)
	if err != nil {
		return preSend(err)
	}
	if c.State != db.CampaignSending {
		return finish(db.DeliverySkipped, db.ReasonCancelled)
	}
	sel, err := campaignSelector(c)
	if err != nil {
		// The row changed after approval. Nothing more of this campaign may
		// go out: halt it, and SkipCancelledBroadcastDeliveries closes the
		// rest of its queue on the next tick.
		slog.Error("broadcast: campaign failed integrity check mid-send; halted", "campaign_id", c.ID)
		if err := w.store.HaltBroadcastCampaign(ctx, c.ID, EndIntegrity, w.now()); err != nil && !errors.Is(err, db.ErrCampaignNotSending) {
			return preSend(err)
		}
		return finish(db.DeliverySkipped, db.ReasonCancelled)
	}
	f, err := w.store.GetBroadcastRecipientFacts(ctx, d.UserID, w.now())
	if err != nil {
		return preSend(err)
	}
	if f == nil {
		return finish(db.DeliverySkipped, string(SkipNoAccount))
	}
	if dec := Evaluate(sel, *f, w.cfg.Policy, w.now()); !dec.Eligible {
		return finish(db.DeliverySkipped, string(dec.Reason))
	}
	if err := w.limiter.Wait(ctx); err != nil {
		// Shutting down before the send: nothing went out.
		return preSend(err)
	}
	if w.now().Sub(claimedAt) > w.cfg.Lease-sendTimeout {
		// A send started now could still be in flight when the lease runs
		// out and the stale sweep closes the row as outcome_unknown. Hand it
		// back unsent; the next claim starts a fresh lease.
		w.release(ctx, []db.BroadcastDelivery{d})
		return nil
	}
	sctx, cancel := context.WithTimeout(ctx, sendTimeout)
	sendErr := w.sender.SendMessage(sctx, f.TelegramID, c.Content)
	cancel()
	return w.record(ctx, d, sendErr)
}

// record maps one send result to a delivery outcome.
//
//   - success: delivered; reachability recorded as reachable.
//   - a conclusive Telegram refusal (blocked, deactivated, cannot initiate,
//     chat not found): permanent failure; reachability updated so the next
//     campaign skips this client up front.
//   - 429 or 5xx: Telegram answered and did not deliver, so a retry cannot
//     duplicate -- bounded exponential backoff, honouring retry_after.
//   - a connection that never reached Telegram (dial failure): likewise
//     safe to retry.
//   - any other 4xx: permanent, no reachability write (not about the user).
//   - any other transport error (timeout, reset mid-response): the request
//     may have been delivered. Closed as outcome_unknown, never retried.
func (w *Worker) record(ctx context.Context, d db.BroadcastDelivery, sendErr error) error {
	ctx = context.WithoutCancel(ctx) // the send happened; its outcome must be written
	now := w.now()
	if sendErr == nil {
		if err := w.store.RecordBotReachability(ctx, d.UserID, notify.ClassifyDelivery(http.StatusOK, ""), "broadcast_delivery"); err != nil {
			slog.Warn("broadcast: record reachability", "err", err)
		}
		return w.store.FinishBroadcastDelivery(ctx, d.CampaignID, d.UserID, db.DeliveryDelivered, "", now)
	}
	var apiErr *notify.APIError
	if errors.As(sendErr, &apiErr) {
		outcome := notify.ClassifyDelivery(apiErr.StatusCode, apiErr.Description)
		if outcome.Conclusive {
			if err := w.store.RecordBotReachability(ctx, d.UserID, outcome, "broadcast_delivery"); err != nil {
				slog.Warn("broadcast: record reachability", "err", err)
			}
			return w.store.FinishBroadcastDelivery(ctx, d.CampaignID, d.UserID, db.DeliveryFailed, outcome.ReasonCode, now)
		}
		if apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500 {
			slog.Warn("broadcast: transient send failure", "campaign_id", d.CampaignID, "status", apiErr.StatusCode, "attempt", d.Attempts)
			return w.retry(ctx, d, apiErr.RetryAfter, now)
		}
		return w.store.FinishBroadcastDelivery(ctx, d.CampaignID, d.UserID, db.DeliveryFailed,
			fmt.Sprintf("%s_%d", ReasonRejected, apiErr.StatusCode), now)
	}
	var opErr *net.OpError
	if errors.As(sendErr, &opErr) && opErr.Op == "dial" {
		slog.Warn("broadcast: transient send failure", "campaign_id", d.CampaignID, "err", sendErr, "attempt", d.Attempts)
		return w.retry(ctx, d, 0, now)
	}
	slog.Warn("broadcast: send outcome unknown; not retried", "campaign_id", d.CampaignID, "err", sendErr)
	return w.store.FinishBroadcastDelivery(ctx, d.CampaignID, d.UserID, db.DeliveryFailed, db.ReasonOutcomeUnknown, now)
}

func (w *Worker) retry(ctx context.Context, d db.BroadcastDelivery, retryAfter time.Duration, now time.Time) error {
	if d.Attempts >= w.cfg.MaxAttempts {
		return w.store.FinishBroadcastDelivery(ctx, d.CampaignID, d.UserID, db.DeliveryFailed, ReasonRetriesExhausted, now)
	}
	return w.store.RetryBroadcastDelivery(ctx, d.CampaignID, d.UserID, ReasonTransient, now.Add(w.backoff(d.Attempts, retryAfter)), now)
}

// backoff is BaseBackoff * 2^(attempts-1), capped at MaxBackoff, and never
// shorter than Telegram's retry_after.
func (w *Worker) backoff(attempts int, retryAfter time.Duration) time.Duration {
	b := w.cfg.BaseBackoff
	for i := 1; i < attempts && b < w.cfg.MaxBackoff; i++ {
		b *= 2
	}
	if b > w.cfg.MaxBackoff {
		b = w.cfg.MaxBackoff
	}
	if retryAfter > b {
		b = retryAfter
	}
	return b
}
