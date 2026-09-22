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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Store is the durable surface the receiver needs, kept as an interface so the
// loop can be tested without reaching for a real *db.Store.
type Store interface {
	AcceptUpdate(ctx context.Context, updateID int64, kind string, chatID sql.NullInt64) (bool, error)
	NextOffset(ctx context.Context) (int64, error)
	ListPendingUpdates(ctx context.Context, afterID int64, limit int) ([]db.PendingUpdate, error)
	DispatchOnce(ctx context.Context, updateID int64, fn func(context.Context, *sql.Tx) (string, error)) error
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
		for {
			if ctx.Err() != nil {
				return
			}
			// Sweep first, on every iteration. This recovers work that was
			// acknowledged to Telegram but whose dispatch did not complete --
			// whether the process died mid-dispatch or a handler failed a
			// moment ago. Either way the update_id is already past the offset,
			// so nothing will ever redeliver it and this is the only path back.
			// Running it at the top of the loop covers the startup case too,
			// since the first iteration happens before the first poll.
			// Normally it is one indexed query returning no rows.
			r.sweepPending(ctx)
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
		if err := r.accept(ctx, u); err != nil {
			// Stop the batch here rather than continuing. Telegram sends
			// updates in ascending update_id order, so accepting a LATER
			// update would push the DB-derived offset past this one and
			// Telegram would never redeliver it -- the failure would become
			// silent data loss. Returning leaves the offset below this
			// update, so the next poll starts again from it.
			return err
		}
	}
	return nil
}

// accept makes one update durable and dispatches it if this call is the one
// that accepted it. A non-nil error means the batch must stop: see pollOnce.
//
// Note that a dispatch failure is NOT an error here. The update is already
// durable at that point, so the offset may safely advance past it and the
// pending sweep will retry it. Only a failure to make it durable is fatal to
// the batch.
func (r *Receiver) accept(ctx context.Context, u Update) error {
	kind := u.Kind()
	chatID := u.ChatID()

	accepted, err := r.store.AcceptUpdate(ctx, u.UpdateID, kind, chatID)
	if err != nil {
		return fmt.Errorf("accept update %d: %w", u.UpdateID, err)
	}
	if !accepted {
		// A duplicate update_id: already accepted by an earlier delivery.
		// Not dispatched again -- this is the idempotency guarantee.
		r.count(kind, OutcomeDuplicate)
		return nil
	}
	r.dispatch(ctx, db.PendingUpdate{UpdateID: u.UpdateID, Kind: kind, ChatID: chatID})
	return nil
}

// dispatch routes one accepted update, recording the outcome on its row.
func (r *Receiver) dispatch(ctx context.Context, p db.PendingUpdate) {
	outcome, err := r.route(ctx, p)
	if err != nil {
		// The claim rolled back with the handler, so the update stays pending
		// and is retried by the next sweep. Only the error TYPE is logged --
		// never the update content, which this package never decoded.
		var he handlerError
		if errors.As(err, &he) {
			// Scrubbed, not logged raw. This package never decodes content, but
			// a HANDLER does, and its error string is the one path by which
			// message text or a callback payload could still reach a log --
			// slog attribute redaction keys off the attribute NAME, so an
			// "err" value carrying content passes through untouched. Handlers
			// are written by other work items (#439, #571); this is the
			// transport making the no-content posture hold regardless of them.
			slog.Warn("bot update handler failed", "update_id", p.UpdateID, "kind", p.Kind,
				"err", audit.ScrubText(r.redact(err.Error())))
			r.count(p.Kind, db.OutcomeHandlerError)
		} else {
			// Routing or the database failed, not a handler. Counted apart so
			// an infrastructure problem is not read as a broken handler.
			slog.Warn("bot update dispatch failed", "update_id", p.UpdateID, "kind", p.Kind,
				"err", audit.ScrubText(r.redact(err.Error())))
			r.count(p.Kind, OutcomeDispatchError)
		}
		return
	}
	r.count(p.Kind, outcome)
}

// handlerError marks an error as coming from a registered handler rather than
// from routing or the database, so the two are counted separately. Conflating
// them hides "the database is failing" behind "some handler is broken".
type handlerError struct{ err error }

func (e handlerError) Error() string { return e.err.Error() }
func (e handlerError) Unwrap() error { return e.err }

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
		if herr != nil {
			return o, handlerError{err: herr}
		}
		return o, nil
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
	// Page through the whole backlog rather than one batch. These rows are
	// past the Telegram offset and will never be redelivered, so a truncated
	// sweep is silent loss for everything beyond the first page.
	//
	// The cursor advances even when a row fails to dispatch, which is what
	// makes this terminate: a persistently failing handler leaves its row
	// pending, but the sweep still moves past it and tries again on the next
	// loop iteration rather than spinning on it here.
	var (
		after int64
		// seen counts rows the sweep ATTEMPTED, which is not the same as rows
		// it recovered: a row whose dispatch fails is counted here and stays
		// pending. The log says "attempted" for that reason -- calling it
		// "recovered" would report a poison row as recovered on every cycle.
		seen int
	)
	for {
		if ctx.Err() != nil {
			return
		}
		pending, err := r.store.ListPendingUpdates(ctx, after, r.batchLimit)
		if err != nil {
			slog.Warn("bot update sweep failed", "err", err)
			return
		}
		if len(pending) == 0 {
			break
		}
		for _, p := range pending {
			if ctx.Err() != nil {
				return
			}
			r.dispatch(ctx, p)
			if p.UpdateID > after {
				after = p.UpdateID
			}
			seen++
		}
		if len(pending) < r.batchLimit {
			break
		}
	}
	if seen > 0 {
		slog.Info("swept accepted bot updates", "attempted", seen)
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

// OutcomeDispatchError labels a routing or database failure, as distinct from
// db.OutcomeHandlerError which is a registered handler failing. Both leave the
// update pending for the sweep; only the second one means a handler is broken.
const OutcomeDispatchError = "dispatch_error"

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
		// NOT %w. url.Parse returns a *url.Error carrying the raw URL, which
		// contains the bot token -- a token with a stray control character is
		// enough to reach this. Start logs whatever pollOnce returns, so the
		// text is scrubbed before it can become an error value at all.
		return nil, fmt.Errorf("build getUpdates request: %s", r.redact(err.Error()))
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

// botPathToken matches the token segment of a Bot API URL. Errors from
// net/url quote the raw URL with Go escaping, so a token containing a control
// character appears as "...Token\n" rather than with a real newline and a
// literal string replacement of the token misses it entirely. Masking by
// position catches every encoding of it.
var botPathToken = regexp.MustCompile(`/bot[^/]*`)

// redact removes the bot token from a string. Transport errors from net/http
// and parse errors from net/url both embed the full request URL, which contains
// the token, so any error text that might have come from either goes through
// here before it reaches a log line or a wrapped error.
//
// Both passes are needed: the positional one catches the token however it is
// escaped inside a URL, and the literal one catches it in text that is not a
// URL at all.
func (r *Receiver) redact(s string) string {
	s = botPathToken.ReplaceAllString(s, "/bot[redacted]")
	if r.token == "" {
		return s
	}
	return strings.ReplaceAll(s, r.token, "[redacted]")
}
