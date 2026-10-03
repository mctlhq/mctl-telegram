package humaninput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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
// request_hash). The durable delivery rows are the dedup, so a restart or a
// repeated poll never sends a second message.
type Poller struct {
	Store   *db.Store
	API     API
	Metrics *metrics.Registry
	// GlobalKill reads the agent kill switch at call time; true skips every
	// enqueue (the notifier is silenced by the same switch).
	GlobalKill func() bool
	// Now is injectable for tests; nil means time.Now.
	Now func() time.Time

	// undeliverableSeen only rate-limits the log line and metric for a
	// pending request this surface cannot render or answer, to once per
	// (user, request_id, request_hash) per process. It decides nothing.
	undeliverableSeen map[string]struct{}
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
			slog.Warn("human input poll failed", "outcome", errClass(err))
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
		// A failed list (including mctl-api's 503 "state could not be
		// determined") says nothing about the requests: never infer "no
		// longer active" from it.
		return err
	}

	listed := make(map[string]struct{}, len(reqs))
	for _, r := range reqs {
		if r.State != workctx.HumanInputStatePending {
			continue
		}
		listed[r.RequestID+"\x00"+r.RequestHash] = struct{}{}
		if reason := undeliverable(r); reason != "" {
			p.noteUndeliverable(a.UserID, r, reason)
			continue
		}
		if err := p.enqueue(ctx, a.UserID, r); err != nil {
			slog.Warn("human input enqueue failed", "user_id", a.UserID, "request_id", r.RequestID, "outcome", errClass(err), "correlation_id", r.CorrelationID)
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
		p.settleAbsent(ctx, a, d)
	}
	return nil
}

// settleAbsent decides what an open row's absence from one successful pending
// list means. Absence alone proves nothing (a list can omit a request for
// reasons that say nothing about it), so the row is only closed once the
// canonical GET /api/v1/human-input/{request_id} says the request is no
// longer pending for this hash, or answers 404 (gone, or no longer visible
// to this human). A failed read, an "unknown" state or a still-pending
// request leaves the row open and its code answerable.
func (p *Poller) settleAbsent(ctx context.Context, a db.HumanInputActor, d db.HumanInputDelivery) {
	logArgs := []any{"user_id", a.UserID, "delivery_id", d.ID, "request_id", d.RequestID}
	v, err := p.API.GetHumanInput(ctx, a.TGID, d.RequestID)
	var state, outcome string
	switch {
	case errors.Is(err, workctx.ErrHumanInputNotFound):
		state, outcome = db.HumanInputInactive, "not_found"
	case err != nil:
		slog.Info("human input absent from list, canonical read failed; row kept", append(logArgs, "outcome", errClass(err))...)
		return
	case v.RequestHash != d.RequestHash:
		state, outcome = db.HumanInputSuperseded, "superseded"
	default:
		switch v.State {
		case workctx.HumanInputStatePending, workctx.HumanInputStateUnknown:
			slog.Info("human input absent from list but not settled; row kept", append(logArgs, "outcome", "state_"+safeToken(v.State), "correlation_id", v.CorrelationID)...)
			return
		case workctx.HumanInputStateResolved:
			state, outcome = db.HumanInputInactive, "resolved"
			if d.State == db.HumanInputSubmitted {
				// This human's own 202-recorded answer is the one that
				// resolved it.
				state = db.HumanInputAnswered
			}
		case workctx.HumanInputStateExpired, workctx.HumanInputStateTimedOut, workctx.HumanInputStateNotPending:
			state, outcome = db.HumanInputInactive, safeToken(v.State)
		default:
			slog.Info("human input absent from list with unrecognised state; row kept", append(logArgs, "outcome", "state_"+safeToken(v.State))...)
			return
		}
	}
	wasDelivered := d.State == db.HumanInputSent || d.State == db.HumanInputSubmitted
	changed, err := p.Store.MarkHumanInputDelivery(ctx, a.UserID, d.ID, state, outcome)
	if err != nil {
		slog.Warn("human input mark delivery failed", append(logArgs, "outcome", errClass(err))...)
		return
	}
	if !changed || !wasDelivered {
		return
	}
	body := fmt.Sprintf("%s (%s)", NoLongerActive, d.AnswerCode)
	if state == db.HumanInputAnswered {
		body = fmt.Sprintf("Your answer to %s was confirmed. Agent will resume.", d.AnswerCode)
	}
	if _, err := p.Store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: a.UserID,
		Kind:   db.NotificationHumanInput,
		Body:   body,
	}); err != nil {
		slog.Warn("human input follow-up enqueue failed", append(logArgs, "outcome", errClass(err))...)
	}
}

// undeliverable returns why the adapter cannot render and answer r, or "".
func undeliverable(r workctx.RequestView) string {
	switch {
	case !workctx.ValidHumanInputRequestID(r.RequestID) || r.RequestHash == "":
		return "malformed"
	case strings.TrimSpace(r.Question) == "":
		return "empty_question"
	case !r.CanRespond:
		return "cannot_respond"
	}
	switch r.ResponseType {
	case workctx.HumanInputTypeFreeText:
		return ""
	case workctx.HumanInputTypeSingleChoice:
		if len(r.Options) == 0 {
			return "no_options"
		}
		if len(r.Options) > maxOptions {
			return "too_many_options"
		}
		for _, o := range r.Options {
			if strings.TrimSpace(o) == "" {
				return "empty_option"
			}
		}
		return ""
	default:
		return "unsupported_type"
	}
}

// noteUndeliverable makes a pending request this surface cannot deliver
// visible (one log line and one metric per request version per process)
// instead of skipping it silently while the agent stays parked.
func (p *Poller) noteUndeliverable(userID int64, r workctx.RequestView, reason string) {
	key := fmt.Sprintf("%d\x00%s\x00%s", userID, r.RequestID, r.RequestHash)
	if p.undeliverableSeen == nil {
		p.undeliverableSeen = map[string]struct{}{}
	}
	if _, seen := p.undeliverableSeen[key]; seen {
		return
	}
	p.undeliverableSeen[key] = struct{}{}
	slog.Info("human input request not deliverable on telegram", "user_id", userID, "request_id", r.RequestID,
		"work_item_id", r.WorkItemID, "outcome", reason, "response_type", safeToken(r.ResponseType), "correlation_id", r.CorrelationID)
	p.Metrics.CountHumanInputEvent(metrics.HumanInputEventDeliveryAttempt, "undeliverable")
}

// OptionDigest is the content-free digest stored per single_choice option:
// the first 16 hex characters of SHA-256 over the trimmed, lowercased option
// text. It lets the handler resolve a typed option locally and check that the
// canonical option it is about to submit is the one that was shown.
func OptionDigest(option string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(option))))
	return hex.EncodeToString(sum[:8])
}

func optionDigests(r workctx.RequestView) []string {
	if r.ResponseType != workctx.HumanInputTypeSingleChoice {
		return nil
	}
	out := make([]string, 0, len(r.Options))
	for _, o := range r.Options {
		out = append(out, OptionDigest(o))
	}
	return out
}

func (p *Poller) enqueue(ctx context.Context, userID int64, r workctx.RequestView) error {
	if _, err := p.Store.SupersedeHumanInputDeliveries(ctx, userID, r.RequestID, r.RequestHash); err != nil {
		return err
	}
	if r.WorkItemID != "" {
		key, ok, err := p.Store.WorkItemExternalKey(ctx, userID, r.WorkItemID)
		switch {
		case err != nil:
			// Best effort: the message falls back to the raw work_item_id.
			slog.Warn("human input work ref lookup failed", "user_id", userID, "request_id", r.RequestID, "work_item_id", r.WorkItemID, "outcome", errClass(err))
		case ok:
			if ref := WorkRefFromExternalKey(key); ref != "" {
				r.WorkRef = ref
			}
		}
	}
	d := db.HumanInputDelivery{
		UserID: userID, RequestID: r.RequestID, RequestHash: r.RequestHash, RequestVersion: r.RequestVersion,
		WorkItemID: r.WorkItemID, Kind: r.ResponseType, OptionDigests: optionDigests(r),
	}
	for attempt := 0; attempt < codeAttempts; attempt++ {
		code, err := newAnswerCode()
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

// reservedCodes are words /mctl input parses as a subcommand. A generated
// answer code equal to one would be unanswerable, so it is redrawn.
var reservedCodes = map[string]struct{}{"STATUS": {}}

// newAnswerCode draws an answer code that is not a reserved subcommand word.
func newAnswerCode() (string, error) {
	for {
		code, err := answercode.New()
		if err != nil {
			return "", err
		}
		if _, reserved := reservedCodes[code]; !reserved {
			return code, nil
		}
	}
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
	case errors.Is(err, workctx.ErrRequestSuperseded):
		return "superseded"
	case errors.Is(err, workctx.ErrRequestNotActive):
		return "not_active"
	case errors.Is(err, workctx.ErrAnswerInvalid):
		return "answer_invalid"
	case errors.Is(err, workctx.ErrHumanInputNotFound):
		return "not_found"
	case errors.Is(err, workctx.ErrIncompatibleSchema):
		return "incompatible_schema"
	case errors.As(err, &apiErr):
		return fmt.Sprintf("api_%d", apiErr.StatusCode)
	default:
		return "error"
	}
}
