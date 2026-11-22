package pa

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
)

// WebhookPath is where the PA webhook is mounted, and only when PA_ENABLED is
// true (see cmd/server).
const WebhookPath = "/pa/bot/webhook"

// SecretHeader carries the secret_token Telegram was given in setWebhook.
const SecretHeader = "X-Telegram-Bot-Api-Secret-Token"

// maxUpdateBody bounds a webhook body. A legitimate update with a 4096
// character message is a few KiB; this leaves room for entities and nested
// reply objects without letting a caller stream an unbounded body.
const maxUpdateBody = 1 << 20

// Outcome labels for the HTTP-level refusals and failures.
const (
	OutcomeBadSecret    = "bad_secret"
	OutcomeBadMethod    = "bad_method"
	OutcomeTooLarge     = "too_large"
	OutcomeReadError    = "read_error"
	OutcomeDedupError   = "dedup_error"
	OutcomeHandlerError = "handler_error"
	// OutcomeGaveUp: the handler failed MaxHandlerAttempts times for this
	// update; it is acknowledged with its handler error recorded, so a
	// deterministic failure does not make Telegram redeliver it forever.
	OutcomeGaveUp = "gave_up"
)

// MaxHandlerAttempts is how many failed handlings of one update are retried
// through Telegram's redelivery before the update is acknowledged anyway.
const MaxHandlerAttempts = 5

// FailureRecorder counts handler failures outside the rolled-back update
// transaction (*db.Store implements it). Both methods return an error for
// any failed write: an uncounted failure is answered 500, never acked.
type FailureRecorder interface {
	RecordPAUpdateFailure(ctx context.Context, updateID int64) (int, error)
	AckFailedPAUpdate(ctx context.Context, updateID int64, reason string) error
}

// Deduper records an update_id durably and runs fn only for the first
// delivery, in the same transaction (*db.Store implements it). It must return
// (false, nil) only for a real duplicate; any failure to read or write the
// dedup record is an error (I9).
type Deduper interface {
	AcceptPAUpdate(ctx context.Context, updateID int64, fn func(context.Context, *sql.Tx) error) (bool, error)
}

// Handler receives each verified update at most once. The transaction is the
// one holding the dedup row: a handler that enqueues work does it in tx, so
// the run and the dedup record commit or roll back together.
type Handler interface {
	HandleUpdate(ctx context.Context, tx *sql.Tx, u VerifiedUpdate) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, tx *sql.Tx, u VerifiedUpdate) error

// HandleUpdate implements Handler.
func (f HandlerFunc) HandleUpdate(ctx context.Context, tx *sql.Tx, u VerifiedUpdate) error {
	return f(ctx, tx, u)
}

// Counter records ingress outcomes. Counted, never logged with content.
type Counter interface {
	CountPAUpdate(outcome string)
}

// WebhookConfig configures NewWebhookHandler.
type WebhookConfig struct {
	// Secret is PA_WEBHOOK_SECRET. Required.
	Secret string
	// Dedup is required; there is no in-memory fallback, because a pod
	// restart would forget it and a Telegram retry would run twice.
	Dedup   Deduper
	Handler Handler
	Counter Counter
	// Failures caps redelivery of a failing update. Required.
	Failures FailureRecorder
	// AfterCommit, if set, runs once an update's transaction committed,
	// with the update: the server starts delivering the outbox rows the
	// update queued (RunLoop.DeliverAfter, #1348) and answers a pressed
	// button (RunLoop.AnswerCallbackAfter). It must not block. It does not
	// run for a duplicate, a failed or a given-up update: only the
	// delivery whose transaction committed answers the query. Its ctx
	// carries the handler's PostCommitAction, if any.
	AfterCommit func(ctx context.Context, u VerifiedUpdate)
}

// webhook is the PA bot's webhook endpoint.
type webhook struct {
	secretSum [sha256.Size]byte
	dedup     Deduper
	handler   Handler
	counter   Counter
	failures  FailureRecorder
	after     func(context.Context, VerifiedUpdate)
}

// ErrWebhookConfig reports an unusable WebhookConfig. It never contains the
// secret.
var ErrWebhookConfig = errors.New("pa webhook: secret, deduper, handler and failure recorder are required")

// NewWebhookHandler builds the webhook endpoint.
func NewWebhookHandler(cfg WebhookConfig) (http.Handler, error) {
	if cfg.Secret == "" || cfg.Dedup == nil || cfg.Handler == nil || cfg.Failures == nil {
		return nil, ErrWebhookConfig
	}
	return &webhook{
		secretSum: sha256.Sum256([]byte(cfg.Secret)),
		dedup:     cfg.Dedup,
		handler:   cfg.Handler,
		counter:   cfg.Counter,
		failures:  cfg.Failures,
		after:     cfg.AfterCommit,
	}, nil
}

// ServeHTTP authenticates, filters, deduplicates and dispatches one update.
//
// Status codes follow Telegram's retry semantics: a non-2xx makes Telegram
// retry. Dropped updates therefore get 200 (retrying a group message will
// never make it acceptable). A dedup or handler failure gets 5xx, because the
// transaction rolled back and the retry must be processed, not lost.
func (h *webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authenticate before anything else, including the method, so an
	// unauthenticated caller learns nothing about the endpoint.
	if !h.secretOK(r.Header.Get(SecretHeader)) {
		h.count(OutcomeBadSecret)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		h.count(OutcomeBadMethod)
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxUpdateBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			h.count(OutcomeTooLarge)
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		h.count(OutcomeReadError)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	u, outcome := Filter(body)
	if outcome != OutcomeAccepted {
		h.count(outcome)
		w.WriteHeader(http.StatusOK)
		return
	}

	var handlerErr error
	// One post-commit slot per delivery: the handler records a linking
	// action in it, and AfterCommit reads it only after the commit.
	ctx := WithPostCommit(r.Context())
	accepted, err := h.dedup.AcceptPAUpdate(ctx, u.UpdateID(), func(ctx context.Context, tx *sql.Tx) error {
		handlerErr = h.handler.HandleUpdate(ctx, tx, u)
		return handlerErr
	})
	switch {
	case handlerErr != nil:
		// Only the update id: the handler's error text may carry content.
		slog.Warn("pa update handler failed", "update_id", u.UpdateID())
		h.handlerFailed(r.Context(), w, u.UpdateID())
	case err != nil:
		slog.Warn("pa update dedup failed", "update_id", u.UpdateID(), "err", err)
		h.count(OutcomeDedupError)
		w.WriteHeader(http.StatusServiceUnavailable)
	case !accepted:
		h.count(OutcomeDuplicate)
		w.WriteHeader(http.StatusOK)
	default:
		h.count(OutcomeAccepted)
		if h.after != nil {
			h.after(ctx, u)
		}
		w.WriteHeader(http.StatusOK)
	}
}

// handlerFailed counts the failure and, once the update has failed
// MaxHandlerAttempts times, acknowledges it with its handler error recorded.
// The transaction of the failed attempt is already rolled back, so nothing
// here runs inside it, and nothing is sent.
func (h *webhook) handlerFailed(ctx context.Context, w http.ResponseWriter, updateID int64) {
	n, err := h.failures.RecordPAUpdateFailure(ctx, updateID)
	if err != nil || n < MaxHandlerAttempts {
		if err != nil {
			slog.Warn("pa update failure not recorded", "update_id", updateID, "err", err)
		}
		h.count(OutcomeHandlerError)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := h.failures.AckFailedPAUpdate(ctx, updateID, OutcomeHandlerError); err != nil {
		slog.Warn("pa update ack failed", "update_id", updateID, "err", err)
		h.count(OutcomeHandlerError)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	h.count(OutcomeGaveUp)
	w.WriteHeader(http.StatusOK)
}

// secretOK compares the presented secret in constant time. Both sides are
// hashed first so that the comparison does not even leak the secret's length.
func (h *webhook) secretOK(got string) bool {
	if got == "" {
		return false
	}
	sum := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(sum[:], h.secretSum[:]) == 1
}

func (h *webhook) count(outcome string) {
	if h.counter != nil {
		h.counter.CountPAUpdate(outcome)
	}
}

// InertHandler accepts a verified update and does nothing with it: no
// model call, no tool call, no message. It was the production handler until
// the run loop was wired (#1343); the server now uses Conversations, and
// this remains for tests that need a handler with no effects.
var InertHandler Handler = HandlerFunc(func(context.Context, *sql.Tx, VerifiedUpdate) error { return nil })
