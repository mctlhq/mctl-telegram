package bot

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Store is the durable surface the receiver needs, kept as an interface so the
// loop can be tested without reaching for a real *db.Store.
type Store interface {
	AcceptUpdate(ctx context.Context, updateID int64, kind string, chatID sql.NullInt64) (bool, error)
	NextOffset(ctx context.Context) (int64, error)
	ListPendingUpdates(ctx context.Context, limit int) ([]db.PendingUpdate, error)
	DispatchOnce(ctx context.Context, updateID int64, fn func(context.Context, *sql.Tx) (string, error)) error
	MarkUpdateFailed(ctx context.Context, updateID int64) error
}

// Counter records why an update was dropped or how it was handled. Outcomes are
// counted rather than logged with content -- an unknown chat or an unroutable
// callback is a metric, not a log line carrying whatever the sender wrote.
type Counter interface {
	CountUpdate(kind, outcome string)
}

// Receiver polls the Bot API for updates and dispatches them exactly once.
type Receiver struct {
	store    Store
	registry *Registry
	counter  Counter

	token   string
	baseURL string
	client  *http.Client

	// pollTimeout is Telegram's long-poll timeout in seconds. The HTTP client
	// deadline must exceed it or every poll would cancel itself.
	pollTimeout int
	// batchLimit caps getUpdates. Small batches mean a crash re-does less.
	batchLimit int
	// idleBackoff is how long to wait after a failed poll, so a Telegram
	// outage does not become a hot loop.
	idleBackoff time.Duration
}

// Options configure a Receiver. Zero values select the defaults.
type Options struct {
	BaseURL     string
	Client      *http.Client
	PollTimeout int
	BatchLimit  int
	IdleBackoff time.Duration
}

// NewReceiver builds a receiver. token is the Bot API token and is never
// logged, never stored, and appears only in the request URL.
func NewReceiver(store Store, registry *Registry, counter Counter, token string, opts Options) *Receiver {
	r := &Receiver{
		store:       store,
		registry:    registry,
		counter:     counter,
		token:       token,
		baseURL:     opts.BaseURL,
		client:      opts.Client,
		pollTimeout: opts.PollTimeout,
		batchLimit:  opts.BatchLimit,
		idleBackoff: opts.IdleBackoff,
	}
	if r.baseURL == "" {
		r.baseURL = "https://api.telegram.org"
	}
	if r.pollTimeout <= 0 {
		r.pollTimeout = 30
	}
	if r.batchLimit <= 0 {
		r.batchLimit = 50
	}
	if r.idleBackoff <= 0 {
		r.idleBackoff = 5 * time.Second
	}
	if r.client == nil {
		// Must outlast the long poll itself, with room for the round trip.
		r.client = &http.Client{Timeout: time.Duration(r.pollTimeout+15) * time.Second}
	}
	return r
}

// Start runs the receive loop until ctx is cancelled. It is a no-op without a
// token, mirroring the digest: an unset token disables the feature rather than
// failing startup.
//
// Single-replica only, like StartDailyDigest. getUpdates answers 409 Conflict
// if two consumers poll one token, and the deployment guarantees one pod
// (replicaCount 1, no HPA, strategy Recreate so a rollout never overlaps).
func (r *Receiver) Start(ctx context.Context) {
	if r.token == "" {
		slog.Info("bot update receiver disabled", "reason", "no bot token")
		return
	}
	go func() {
		// Recover work that was acknowledged to Telegram but whose dispatch
		// did not complete before the process died. This runs before the
		// first poll because those updates will never be redelivered: their
		// update_id is already below the offset.
		r.sweepPending(ctx)
		for {
			if ctx.Err() != nil {
				return
			}
			if err := r.pollOnce(ctx); err != nil {
				if ctx.Err() != nil {
					return
				}
				slog.Warn("bot update poll failed", "err", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(r.idleBackoff):
				}
			}
		}
	}()
	slog.Info("bot update receiver enabled", "transport", "long_poll", "poll_timeout_s", r.pollTimeout)
}

// pollOnce performs one getUpdates round and dispatches what it accepts.
func (r *Receiver) pollOnce(ctx context.Context) error {
	// The offset comes from the database, never from the previous batch. This
	// is what keeps Telegram's acknowledgement behind durable ownership: an
	// update is only confirmed once its row exists. See db/bot_updates.go.
	offset, err := r.store.NextOffset(ctx)
	if err != nil {
		return fmt.Errorf("read offset: %w", err)
	}
	updates, err := r.getUpdates(ctx, offset)
	if err != nil {
		return err
	}
	for _, u := range updates {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.accept(ctx, u)
	}
	return nil
}

// accept makes one update durable and dispatches it if this call is the one
// that accepted it.
func (r *Receiver) accept(ctx context.Context, u Update) {
	kind := u.Kind()
	chatID := u.ChatID()

	accepted, err := r.store.AcceptUpdate(ctx, u.UpdateID, kind, chatID)
	if err != nil {
		// Not fatal and not skipped: the row was not written, so the offset
		// does not move and Telegram redelivers this update on the next poll.
		slog.Warn("bot update not accepted", "update_id", u.UpdateID, "kind", kind, "err", err)
		return
	}
	if !accepted {
		// A duplicate update_id: already accepted by an earlier delivery.
		// Not dispatched again -- this is the idempotency guarantee.
		r.count(kind, OutcomeDuplicate)
		return
	}
	r.dispatch(ctx, db.PendingUpdate{UpdateID: u.UpdateID, Kind: kind, ChatID: chatID})
}

// dispatch routes one accepted update, recording the outcome on its row.
func (r *Receiver) dispatch(ctx context.Context, p db.PendingUpdate) {
	outcome, err := r.route(ctx, p)
	if err != nil {
		// The claim rolled back with the handler, so the update stays pending
		// and is retried by the next sweep. Only the error TYPE is logged --
		// never the update content, which this package never decoded.
		slog.Warn("bot update handler failed", "update_id", p.UpdateID, "kind", p.Kind, "err", err)
		r.count(p.Kind, db.OutcomeHandlerError)
		return
	}
	r.count(p.Kind, outcome)
}

// route resolves the handler and runs it inside DispatchOnce.
func (r *Receiver) route(ctx context.Context, p db.PendingUpdate) (string, error) {
	// Decisions that do not need a handler are made before claiming, and the
	// row is still marked processed so the update is not swept forever.
	if p.Kind == db.KindUnsupported {
		return r.complete(ctx, p.UpdateID, db.OutcomeUnsupported)
	}
	known, err := r.registry.isKnownChat(ctx, p.ChatID)
	if err != nil {
		return "", fmt.Errorf("resolve chat: %w", err)
	}
	if !known {
		// Dropped safely and counted. No chat id in the log, no content, no
		// error-level noise: an unknown chat is an ordinary event, since
		// anyone can message a public bot.
		return r.complete(ctx, p.UpdateID, db.OutcomeUnknownChat)
	}
	h, ok := r.registry.lookup(p.Kind)
	if !ok {
		// A kind with no owner yet -- callback_query before #571 registers
		// one, for instance. Accepted, counted, not an error.
		return r.complete(ctx, p.UpdateID, db.OutcomeNoHandler)
	}

	var outcome string
	err = r.store.DispatchOnce(ctx, p.UpdateID, func(ctx context.Context, tx *sql.Tx) (string, error) {
		o, herr := h.HandleUpdate(ctx, tx, Delivery{
			UpdateID: p.UpdateID,
			Kind:     p.Kind,
			ChatID:   p.ChatID,
		})
		outcome = o
		return o, herr
	})
	if errors.Is(err, db.ErrUpdateNotClaimable) {
		// Someone else completed it first. Not an error, and not dispatched
		// twice, which is the property that matters.
		return OutcomeDuplicate, nil
	}
	if err != nil {
		return "", err
	}
	if outcome == "" {
		outcome = db.OutcomeHandled
	}
	return outcome, nil
}

// complete marks an update processed with a terminal outcome that needed no
// handler, inside the same claim-and-mark transaction so it cannot be counted
// twice.
func (r *Receiver) complete(ctx context.Context, updateID int64, outcome string) (string, error) {
	err := r.store.DispatchOnce(ctx, updateID, func(context.Context, *sql.Tx) (string, error) {
		return outcome, nil
	})
	if errors.Is(err, db.ErrUpdateNotClaimable) {
		return OutcomeDuplicate, nil
	}
	if err != nil {
		return "", err
	}
	return outcome, nil
}

// sweepPending re-dispatches updates that were accepted but never processed.
// Without this they would be stranded: their update_id is below the offset, so
// Telegram considers them delivered and will not send them again.
func (r *Receiver) sweepPending(ctx context.Context) {
	pending, err := r.store.ListPendingUpdates(ctx, r.batchLimit)
	if err != nil {
		slog.Warn("bot update sweep failed", "err", err)
		return
	}
	if len(pending) == 0 {
		return
	}
	slog.Info("recovering accepted bot updates", "count", len(pending))
	for _, p := range pending {
		if ctx.Err() != nil {
			return
		}
		r.dispatch(ctx, p)
	}
}

// count records an outcome, tolerating a nil counter.
func (r *Receiver) count(kind, outcome string) {
	if r.counter == nil {
		return
	}
	r.counter.CountUpdate(kind, outcome)
}

// OutcomeDuplicate labels a redelivered update that was already accepted. It
// is a receiver-level counter label only and is never written to a row -- the
// row already carries the outcome of the delivery that won.
const OutcomeDuplicate = "duplicate"

// getUpdates performs one long poll.
//
// The token is in the path because the Bot API has no other way to carry it.
// It is never logged: every error below is constructed from the status code and
// the API's own description, and telegramURL's result is not put into any log
// line. redactURL exists for the cases where an underlying transport error
// embeds the URL.
func (r *Receiver) getUpdates(ctx context.Context, offset int64) ([]Update, error) {
	q := url.Values{}
	if offset > 0 {
		q.Set("offset", strconv.FormatInt(offset, 10))
	}
	q.Set("timeout", strconv.Itoa(r.pollTimeout))
	q.Set("limit", strconv.Itoa(r.batchLimit))
	// Ask Telegram for only the kinds the registry can route. This is also a
	// privacy control: updates we never requested are never transmitted to us
	// at all, so their content cannot be in a heap dump or a proxy log.
	q.Set("allowed_updates", `["message","callback_query"]`)

	endpoint := fmt.Sprintf("%s/bot%s/getUpdates?%s", r.baseURL, r.token, q.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build getUpdates request: %w", err)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getUpdates: %s", r.redact(err.Error()))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, fmt.Errorf("getUpdates: read body: %w", err)
	}
	var env getUpdatesResponse
	if err := json.Unmarshal(body, &env); err != nil {
		// Deliberately does not include the body: on a proxy error page it
		// could be anything, and on a success it is update content.
		return nil, fmt.Errorf("getUpdates: malformed response (HTTP %d)", resp.StatusCode)
	}
	if !env.OK {
		// env.Description is the API's own error text ("Conflict: terminated
		// by other getUpdates request", "Unauthorized"), which carries no user
		// content, but scrub it anyway rather than trusting that.
		return nil, fmt.Errorf("getUpdates: HTTP %d: %s", resp.StatusCode, r.redact(env.Description))
	}
	var updates []Update
	if err := json.Unmarshal(env.Result, &updates); err != nil {
		return nil, fmt.Errorf("getUpdates: malformed result array")
	}
	return updates, nil
}

// redact removes the bot token from a string. Transport errors from net/http
// embed the full request URL, which contains the token, so any error text that
// might have come from the HTTP layer goes through here before it reaches a log
// line or a wrapped error.
func (r *Receiver) redact(s string) string {
	if r.token == "" {
		return s
	}
	return strings.ReplaceAll(s, r.token, "[redacted]")
}
