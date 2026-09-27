package broadcast

import (
	"context"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// ReportStore is what Report reads.
type ReportStore interface {
	GetBroadcastCampaign(ctx context.Context, id string) (*db.BroadcastCampaign, error)
	BroadcastDeliveryCounts(ctx context.Context, campaignID string) ([]db.DeliveryCount, error)
}

// Report is the aggregate outcome of one campaign. It names no recipient and
// carries no message text. Delivered means the Bot API accepted the message;
// it is never a read receipt.
type Report struct {
	CampaignID string     `json:"campaign_id"`
	State      string     `json:"state"`
	EndReason  string     `json:"end_reason,omitempty"`
	Category   string     `json:"category"`
	CreatedBy  int64      `json:"created_by"`
	ApprovedBy *int64     `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	// Queued is the audience resolved at execution time (0 before the
	// campaign starts).
	Queued    int `json:"queued"`
	Delivered int `json:"delivered"`
	// Skipped counts recipients dropped by the re-check right before their
	// send, by reason (unsubscribed, unreachable, policy, no_account,
	// out_of_audience, cancelled).
	Skipped map[string]int `json:"skipped"`
	// TransientFailure: retries exhausted on 429/5xx/connection failures.
	TransientFailure int `json:"transient_failure"`
	// PermanentFailure: Telegram refused this recipient (blocked, cannot
	// initiate, rejected), by reason.
	PermanentFailure map[string]int `json:"permanent_failure"`
	// OutcomeUnknown: the request may or may not have been delivered and
	// was deliberately not retried.
	OutcomeUnknown int `json:"outcome_unknown"`
	// Pending: queued and not yet finished (including scheduled retries).
	Pending int `json:"pending"`
}

// BuildReport aggregates a campaign's delivery rows.
func BuildReport(ctx context.Context, s ReportStore, campaignID string) (*Report, error) {
	c, err := s.GetBroadcastCampaign(ctx, campaignID)
	if err != nil {
		return nil, err
	}
	counts, err := s.BroadcastDeliveryCounts(ctx, campaignID)
	if err != nil {
		return nil, err
	}
	r := &Report{
		CampaignID: c.ID, State: c.State, EndReason: c.EndReason, Category: c.Category,
		CreatedBy: c.CreatedBy, ApprovedBy: c.ApprovedBy, ApprovedAt: c.ApprovedAt,
		Skipped: map[string]int{}, PermanentFailure: map[string]int{},
	}
	for _, n := range counts {
		r.Queued += n.Count
		switch n.Status {
		case db.DeliveryDelivered:
			r.Delivered += n.Count
		case db.DeliverySkipped:
			r.Skipped[n.Reason] += n.Count
		case db.DeliveryPending, db.DeliverySending:
			r.Pending += n.Count
		case db.DeliveryFailed:
			switch n.Reason {
			case ReasonRetriesExhausted:
				r.TransientFailure += n.Count
			case db.ReasonOutcomeUnknown:
				r.OutcomeUnknown += n.Count
			default:
				r.PermanentFailure[n.Reason] += n.Count
			}
		}
	}
	return r, nil
}
