package humaninput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
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
	// maxSettleReads and settleBudget bound the canonical reads one actor's
	// poll spends on open rows absent from the pending list. Each read can
	// take the full relay timeout, actors are polled one after another, and
	// a row whose read keeps failing stays open and is re-read every poll —
	// so without a bound a few such rows on one user would hold every other
	// actor's poll back. Rows left unread wait for a later poll, which picks
	// a fresh random subset.
	maxSettleReads = 5
	settleBudget   = 10 * time.Second
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
	// SettleBudget bounds one actor's canonical reads of absent rows per
	// poll (see maxSettleReads); 0 means the package default. Injectable
	// for tests.
	SettleBudget time.Duration

	// undeliverableMu guards undeliverableSeen. RunOnce is exported and
	// otherwise reentrant, so the map must not rely on there being a single
	// Run goroutine.
	undeliverableMu sync.Mutex
	// undeliverableSeen only rate-limits the log line and metric for a
	// pending request this surface cannot render or answer: per user, the
	// (request_id, request_hash) keys reported on that user's last successful
	// poll. Each successful poll replaces the user's set, so a key that is no
	// longer listed is dropped and the map stays bounded by what is pending.
	// It decides nothing.
	undeliverableSeen map[int64]map[string]struct{}
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
	undeliverableNow := map[string]struct{}{}
	defer p.replaceUndeliverable(a.UserID, undeliverableNow)
	for _, r := range reqs {
		if r.State != workctx.HumanInputStatePending {
			continue
		}
		listed[r.RequestID+"\x00"+r.RequestHash] = struct{}{}
		if reason := undeliverable(r); reason != "" {
			p.noteUndeliverable(a.UserID, r, reason, undeliverableNow)
			continue
		}
		closedState, err := p.enqueue(ctx, a.UserID, r)
		if err != nil {
			slog.Warn("human input enqueue failed", "user_id", a.UserID, "request_id", r.RequestID, "outcome", errClass(err), "correlation_id", r.CorrelationID)
			p.Metrics.CountHumanInputEvent(metrics.HumanInputEventDeliveryAttempt, "error")
			continue
		}
		if closedState != "" {
			// mctl-api lists the request as pending, but this exact
			// (request_id, request_hash) already has a terminal row here —
			// e.g. one closed on a 404 that a later visibility change
			// reverted. No code can answer it from Telegram any more, so it
			// is reported like any other undeliverable request rather than
			// skipped silently while the agent stays parked.
			p.noteUndeliverable(a.UserID, r, "closed_"+closedState, undeliverableNow)
		}
	}

	open, err := p.Store.ListOpenHumanInputDeliveries(ctx, a.UserID)
	if err != nil {
		return err
	}
	var absent []db.HumanInputDelivery
	for _, d := range open {
		if _, still := listed[d.RequestID+"\x00"+d.RequestHash]; !still {
			absent = append(absent, d)
		}
	}
	if len(absent) > maxSettleReads {
		rand.Shuffle(len(absent), func(i, j int) { absent[i], absent[j] = absent[j], absent[i] })
		slog.Info("human input settle reads capped", "user_id", a.UserID, "absent", len(absent), "read", maxSettleReads)
		absent = absent[:maxSettleReads]
	}
	budget := p.SettleBudget
	if budget <= 0 {
		budget = settleBudget
	}
	// One deadline for all of this actor's canonical reads; only the reads
	// use it, so a row whose read did succeed is still marked in full.
	readCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for _, d := range absent {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		p.settleAbsent(ctx, readCtx, a, d)
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
//
// readCtx bounds the canonical read only (see maxSettleReads); a read cut
// off by it is a failed read and leaves the row open.
func (p *Poller) settleAbsent(ctx, readCtx context.Context, a db.HumanInputActor, d db.HumanInputDelivery) {
	logArgs := []any{"user_id", a.UserID, "delivery_id", d.ID, "request_id", d.RequestID}
	v, err := p.API.GetHumanInput(readCtx, a.TGID, d.RequestID)
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
			switch d.State {
			case db.HumanInputSubmitted:
				// This human's own 202-recorded answer is the one that
				// resolved it.
				state = db.HumanInputAnswered
			case db.HumanInputUnconfirmed:
				// An answer whose submit outcome was unknown: it may be
				// this human's. Never report it as "no longer active".
				outcome = "resolved_unconfirmed"
			}
		case workctx.HumanInputStateExpired, workctx.HumanInputStateTimedOut, workctx.HumanInputStateNotPending:
			state, outcome = db.HumanInputInactive, safeToken(v.State)
		default:
			slog.Info("human input absent from list with unrecognised state; row kept", append(logArgs, "outcome", "state_"+safeToken(v.State))...)
			return
		}
	}
	wasDelivered := d.State == db.HumanInputSent || d.State == db.HumanInputSubmitted || d.State == db.HumanInputUnconfirmed
	changed, err := p.Store.MarkHumanInputDelivery(ctx, a.UserID, d.ID, state, outcome)
	if err != nil {
		slog.Warn("human input mark delivery failed", append(logArgs, "outcome", errClass(err))...)
		return
	}
	if !changed || !wasDelivered {
		return
	}
	body := fmt.Sprintf("%s (%s)", NoLongerActive, d.AnswerCode)
	switch {
	case state == db.HumanInputAnswered:
		body = fmt.Sprintf("Your answer to %s was confirmed. Agent will resume.", d.AnswerCode)
	case outcome == "resolved_unconfirmed":
		body = resolvedUnconfirmed(d.AnswerCode)
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
	case rendersBlank(r.Question):
		return "empty_question"
	case !r.Respondable():
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
		digests := make(map[string]struct{}, len(r.Options))
		shown := make(map[string]struct{}, len(r.Options))
		for _, o := range r.Options {
			if rendersBlank(o) {
				return "empty_option"
			}
			// Two options equal up to case or surrounding whitespace would
			// make a typed answer ambiguous (and their digests equal). Two
			// that differ only in what the renderer strips or truncates
			// (invisible code points, text past maxLabelRunes) have distinct
			// digests but read the same to the owner.
			d := OptionDigest(o)
			label := strings.ToLower(oneLine(o, maxLabelRunes))
			_, dupDigest := digests[d]
			_, dupLabel := shown[label]
			if dupDigest || dupLabel {
				return "duplicate_options"
			}
			digests[d] = struct{}{}
			shown[label] = struct{}{}
		}
		return ""
	default:
		return "unsupported_type"
	}
}

// noteUndeliverable makes a pending request this surface cannot deliver
// visible (one log line and one metric while it stays listed) instead of
// skipping it silently while the agent stays parked. now collects this poll's
// keys for replaceUndeliverable.
func (p *Poller) noteUndeliverable(userID int64, r workctx.RequestView, reason string, now map[string]struct{}) {
	key := r.RequestID + "\x00" + r.RequestHash
	now[key] = struct{}{}
	p.undeliverableMu.Lock()
	_, seen := p.undeliverableSeen[userID][key]
	p.undeliverableMu.Unlock()
	if seen {
		return
	}
	slog.Info("human input request not deliverable on telegram", "user_id", userID, "request_id", r.RequestID,
		"work_item_id", r.WorkItemID, "outcome", reason, "response_type", safeToken(r.ResponseType), "correlation_id", r.CorrelationID)
	p.Metrics.CountHumanInputEvent(metrics.HumanInputEventDeliveryAttempt, "undeliverable")
}

// replaceUndeliverable makes now the user's reported set, dropping keys that
// are no longer listed. Called only after a successful list.
func (p *Poller) replaceUndeliverable(userID int64, now map[string]struct{}) {
	p.undeliverableMu.Lock()
	defer p.undeliverableMu.Unlock()
	if len(now) == 0 {
		delete(p.undeliverableSeen, userID)
		return
	}
	if p.undeliverableSeen == nil {
		p.undeliverableSeen = map[int64]map[string]struct{}{}
	}
	p.undeliverableSeen[userID] = now
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

// enqueue queues the delivery for r. closedState is the state of a terminal
// row that already holds r's (request_id, request_hash), or "" when the row
// was inserted now or is still open.
func (p *Poller) enqueue(ctx context.Context, userID int64, r workctx.RequestView) (closedState string, err error) {
	if _, err := p.Store.SupersedeHumanInputDeliveries(ctx, userID, r.RequestID, r.RequestHash); err != nil {
		return "", err
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
			return "", err
		}
		d.AnswerCode = code
		inserted, existing, err := p.Store.UpsertHumanInputDeliveryTx(ctx, d, Render(r, code))
		if errors.Is(err, db.ErrHumanInputCodeConflict) {
			continue
		}
		if err != nil {
			return "", err
		}
		if inserted {
			p.Metrics.CountHumanInputEvent(metrics.HumanInputEventDeliveryAttempt, "ok")
			slog.Info("human input queued", "user_id", userID, "request_id", r.RequestID, "work_item_id", r.WorkItemID, "correlation_id", r.CorrelationID)
			return "", nil
		}
		if (db.HumanInputDelivery{State: existing}).Terminal() {
			return safeToken(existing), nil
		}
		return "", nil
	}
	return "", errors.New("answer code collision retries exhausted")
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
