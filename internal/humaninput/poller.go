package humaninput

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/answercode"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/workctx"
)

// API is the slice of *workctx.Client the adapter uses. An interface only so
// tests can fake mctl-api; production passes the shared relay client.
type API interface {
	ListHumanInput(ctx context.Context, actorTGID int64) ([]workctx.RequestView, error)
	GetHumanInput(ctx context.Context, actorTGID int64, requestID string) (*workctx.RequestView, error)
	RespondHumanInput(ctx context.Context, actorTGID int64, requestID string, r workctx.ResponseRequest, idemKey string) (*workctx.ResponseView, error)
}

const (
	// dormantBase and dormantMax bound the exponential poll backoff applied to
	// an actor whose link mctl-api reports missing, revoked or expired.
	dormantBase = time.Minute
	dormantMax  = time.Hour
	// codeAttempts bounds retries on the (astronomically rare) answer-code
	// collision.
	codeAttempts = 5
)

// Poller discovers pending human-input requests per enrolled actor and queues
// exactly one Saved Messages notification per (user, request_id,
// request_hash). It holds no state of its own: the durable delivery rows are
// the dedup, so a restart or a repeated poll never sends a second message.
type Poller struct {
	Store   *db.Store
	API     API
	Metrics *metrics.Registry
	// GlobalKill reads the agent kill switch at call time; true skips every
	// enqueue (the notifier is silenced by the same switch).
	GlobalKill func() bool
	// Now is injectable for tests; nil means time.Now.
	Now func() time.Time
}

func (p *Poller) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Run polls every interval until ctx is cancelled.
func (p *Poller) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := p.RunOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("human input poll failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// RunOnce performs one poll over every pollable actor. A failure for one
// actor never stops the others.
func (p *Poller) RunOnce(ctx context.Context) error {
	if p.GlobalKill != nil && p.GlobalKill() {
		return nil
	}
	actors, err := p.Store.ListPollableHumanInputActors(ctx, p.now())
	if err != nil {
		return fmt.Errorf("list human input actors: %w", err)
	}
	for _, a := range actors {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := p.pollActor(ctx, a); err != nil {
			slog.Warn("human input poll actor failed", "user_id", a.UserID, "outcome", errClass(err))
		}
	}
	return nil
}

func (p *Poller) pollActor(ctx context.Context, a db.HumanInputActor) error {
	// Same fail-closed identity rule as the command path: the stored hint must
	// still match the user's Telegram login id.
	stored, found, err := p.Store.TelegramIDByUserID(ctx, a.UserID)
	if err != nil {
		return err
	}
	if !found || stored != a.TGID {
		return nil
	}
	reqs, err := p.API.ListHumanInput(ctx, a.TGID)
	if err != nil {
		if isLinkError(err) {
			// Only stops wasted polling; mctl-api still decides everything.
			if merr := p.Store.MarkHumanInputActorDormant(ctx, a.UserID, errClass(err), dormantBase, dormantMax); merr != nil {
				return merr
			}
		}
		// A failed list says nothing about the requests: never infer
		// "no longer active" from it.
		return err
	}

	listed := make(map[string]struct{}, len(reqs))
	for _, r := range reqs {
		if r.State != "" && r.State != workctx.HumanInputStatePending {
			continue
		}
		listed[r.RequestID+"\x00"+r.RequestHash] = struct{}{}
		if !deliverable(r) {
			continue
		}
		if err := p.enqueue(ctx, a.UserID, r); err != nil {
			slog.Warn("human input enqueue failed", "user_id", a.UserID, "request_id", r.RequestID, "outcome", errClass(err))
			p.Metrics.CountHumanInputEvent(metrics.HumanInputEventDeliveryAttempt, "error")
		}
	}

	open, err := p.Store.ListOpenHumanInputDeliveries(ctx, a.UserID)
	if err != nil {
		return err
	}
	for _, d := range open {
		if _, still := listed[d.RequestID+"\x00"+d.RequestHash]; still {
			continue
		}
		// A single list response can omit a still-open request; confirm
		// with a direct read before retiring a row that cannot be revived.
		if cur, gerr := p.API.GetHumanInput(ctx, a.TGID, d.RequestID); gerr != nil {
			var apiErr *workctx.APIError
			if !(errors.As(gerr, &apiErr) && apiErr.StatusCode == 404) {
				continue
			}
		} else if cur != nil && cur.RequestHash == d.RequestHash && (cur.State == "" || cur.State == workctx.HumanInputStatePending) {
			continue
		}
		wasSent := d.State == db.HumanInputSent
		changed, err := p.Store.MarkHumanInputDelivery(ctx, a.UserID, d.ID, db.HumanInputInactive, "left_pending_list")
		if err != nil {
			slog.Warn("human input mark inactive failed", "user_id", a.UserID, "delivery_id", d.ID, "outcome", errClass(err))
			continue
		}
		if changed && wasSent {
			if _, err := p.Store.InsertOwnerNotification(ctx, db.OwnerNotification{
				UserID: a.UserID,
				Kind:   db.NotificationHumanInput,
				Body:   fmt.Sprintf("%s (%s)", NoLongerActive, d.AnswerCode),
			}); err != nil {
				slog.Warn("human input follow-up enqueue failed", "user_id", a.UserID, "delivery_id", d.ID, "outcome", errClass(err))
			}
		}
	}
	return nil
}

// deliverable reports whether the adapter can render and answer r.
func deliverable(r workctx.RequestView) bool {
	if r.RequestID == "" || r.RequestHash == "" || r.Question == "" {
		return false
	}
	switch r.Kind {
	case workctx.HumanInputKindFreeText:
		return true
	case workctx.HumanInputKindSingleChoice:
		return len(optionIDs(r)) > 0
	default:
		return false
	}
}

func optionIDs(r workctx.RequestView) []string {
	var ids []string
	for i, o := range r.Options {
		if i >= maxOptions {
			break
		}
		if o.ID == "" {
			// An option without an id cannot be answered by number; the
			// whole request is not deliverable rather than misnumbered.
			return nil
		}
		ids = append(ids, o.ID)
	}
	return ids
}

func (p *Poller) enqueue(ctx context.Context, userID int64, r workctx.RequestView) error {
	if _, err := p.Store.SupersedeHumanInputDeliveries(ctx, userID, r.RequestID, r.RequestHash); err != nil {
		return err
	}
	if r.WorkItemID != "" {
		if key, ok, err := p.Store.WorkItemExternalKey(ctx, userID, r.WorkItemID); err == nil && ok {
			if ref := WorkRefFromExternalKey(key); ref != "" {
				r.WorkRef = ref
			}
		}
	}
	d := db.HumanInputDelivery{
		UserID: userID, RequestID: r.RequestID, RequestHash: r.RequestHash, RequestVersion: r.Version,
		WorkItemID: r.WorkItemID, Kind: r.Kind, OptionIDs: optionIDs(r), MaxLength: r.MaxLength,
	}
	for attempt := 0; attempt < codeAttempts; attempt++ {
		code, err := answercode.New()
		if err != nil {
			return err
		}
		d.AnswerCode = code
		inserted, err := p.Store.UpsertHumanInputDeliveryTx(ctx, d, Render(r, code))
		if errors.Is(err, db.ErrHumanInputCodeConflict) {
			continue
		}
		if err != nil {
			return err
		}
		if inserted {
			p.Metrics.CountHumanInputEvent(metrics.HumanInputEventDeliveryAttempt, "ok")
			slog.Info("human input queued", "user_id", userID, "request_id", r.RequestID, "work_item_id", r.WorkItemID, "correlation_id", r.CorrelationID)
		}
		return nil
	}
	return errors.New("answer code collision retries exhausted")
}

// isLinkError reports a missing, revoked or expired surface link.
func isLinkError(err error) bool {
	return errors.Is(err, workctx.ErrLinkNotFound) || errors.Is(err, workctx.ErrLinkRevoked) || errors.Is(err, workctx.ErrLinkExpired)
}

// errClass reduces an error to a short bounded token safe for logs and metric
// labels: never the error text, which could carry upstream detail.
func errClass(err error) string {
	var apiErr *workctx.APIError
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, workctx.ErrLinkNotFound):
		return "link_not_found"
	case errors.Is(err, workctx.ErrLinkRevoked):
		return "link_revoked"
	case errors.Is(err, workctx.ErrLinkExpired):
		return "link_expired"
	case errors.Is(err, workctx.ErrNotEligible):
		return "not_eligible"
	case errors.Is(err, workctx.ErrIncompatibleSchema):
		return "incompatible_schema"
	case errors.As(err, &apiErr):
		return fmt.Sprintf("api_%d", apiErr.StatusCode)
	default:
		return "error"
	}
}
