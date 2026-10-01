package bot

// bridge.go is the production ingestion path for a client's /start
// (issue-679). The login bot's updates are delivered by webhook to mctl-agent,
// which owns that webhook (and the operator channel on the same bot), so this
// service cannot long-poll them: getUpdates answers 409 while a webhook is
// set. mctl-agent therefore recognises a /start and forwards one normalised
// observation here, and this endpoint records it through the same
// RecordBotStartTx the long-poll receiver uses.
//
// The surface is deliberately narrow. It accepts exactly {update_id,
// telegram_id, observed_at}: no text, no payload, no internal user id, no
// state. The only thing a caller can cause is "a trusted /start was observed
// for this Telegram id at this time", resolved server-side, so it cannot be
// turned into arbitrary reachability mutation without a code change.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// BotStartObservationPath is the bridge route.
const BotStartObservationPath = "/internal/bot-start-observations"

// MinBridgeTokenLen is the shortest bridge token BearerTokenAuth accepts.
const MinBridgeTokenLen = 32

// maxObservationBody caps the request body; a valid one is under 100 bytes.
const maxObservationBody = 4 << 10

// maxObservationSkew bounds how far in the future observed_at may be. A future
// time would pin "reachable" above every later conclusive outbound outcome, so
// anything beyond clock skew is refused rather than stored.
const maxObservationSkew = 5 * time.Minute

// BridgeAuthenticator decides whether a request comes from the trusted webhook
// owner. It is an interface so the bearer token can be swapped for another
// service identity (for example a Kubernetes service-account token review)
// without touching the handler.
type BridgeAuthenticator interface {
	Authenticate(r *http.Request) bool
}

// BearerTokenAuth authenticates "Authorization: Bearer <token>" against one
// shared token in constant time.
type BearerTokenAuth struct{ token []byte }

// NewBearerTokenAuth returns a BearerTokenAuth, or an error when the token is
// shorter than MinBridgeTokenLen.
func NewBearerTokenAuth(token string) (*BearerTokenAuth, error) {
	if len(token) < MinBridgeTokenLen {
		return nil, errors.New("bot-start bridge token is too short")
	}
	return &BearerTokenAuth{token: []byte(token)}, nil
}

// Authenticate implements BridgeAuthenticator.
func (a *BearerTokenAuth) Authenticate(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h[len(prefix):]), a.token) == 1
}

// botStartObservation is the whole request contract.
type botStartObservation struct {
	UpdateID   int64     `json:"update_id"`
	TelegramID int64     `json:"telegram_id"`
	ObservedAt time.Time `json:"observed_at"`
}

// errRoutingMismatch aborts a dispatch whose stored row is not the /start this
// request describes, rolling the claim back.
var errRoutingMismatch = errors.New("stored update routing does not match the observation")

// OutcomeRoutingMismatch labels an observation whose update_id is already
// stored as a different kind or for a different chat. It is never dispatched
// and is answered like any other accepted observation, but counted apart from
// a benign duplicate: a non-zero rate means the caller is sending update_ids
// that collide with other updates, which a correct forwarder never does.
const OutcomeRoutingMismatch = "routing_mismatch"

// acceptedBody is the one response for every authenticated, well-formed
// observation: known, unknown, ambiguous and duplicate alike, so the caller
// learns nothing about which Telegram ids are clients.
const acceptedBody = `{"status":"accepted"}`

// bridgeStore is the part of *db.Store the bridge uses. It is an interface
// only so tests can inject failures; production passes the store itself.
type bridgeStore interface {
	AcceptUpdateAt(ctx context.Context, updateID int64, kind string, chatID sql.NullInt64, receivedAt time.Time) (bool, error)
	DispatchOnce(ctx context.Context, updateID int64, fn func(context.Context, *sql.Tx) (string, error)) error
	UpdateRoutingTx(ctx context.Context, tx *sql.Tx, updateID int64) (string, sql.NullInt64, error)
}

// recordFunc is the business rule applied inside the dispatch transaction.
type recordFunc func(ctx context.Context, tx *sql.Tx, telegramID, updateID int64) (string, error)

// Redactor is implemented by an authenticator whose secret could appear in
// error text, so the bridge can remove it before logging.
type Redactor interface {
	Redact(s string) string
}

// Redact implements Redactor.
func (a *BearerTokenAuth) Redact(s string) string {
	return strings.ReplaceAll(s, string(a.token), "[redacted]")
}

// BotStartObservationHandler records a /start forwarded by the webhook owner.
//
//   - 401 without valid authentication;
//   - 400 for anything but exactly the three fields, a non-positive id, or an
//     observed_at that is zero or in the future beyond clock skew;
//   - 413 for a body over maxObservationBody;
//   - 202 with the same body for every accepted observation, whether or not
//     the Telegram id resolves to a client and whether or not it was already
//     recorded;
//   - 503 when the store or the handler fails, so the caller may retry. A
//     retry is the only recovery (nothing sweeps a stranded bridge row) and is
//     safe: the update_id is the dedupe key, and a row whose earlier dispatch
//     failed is processed on the retry.
func BotStartObservationHandler(store *db.Store, auth BridgeAuthenticator, counter Counter) http.Handler {
	return newBotStartObservationHandler(store, func(ctx context.Context, tx *sql.Tx, telegramID, updateID int64) (string, error) {
		return RecordBotStartTx(ctx, store, tx, telegramID, updateID)
	}, auth, counter)
}

func newBotStartObservationHandler(store bridgeStore, record recordFunc, auth BridgeAuthenticator, counter Counter) http.Handler {
	count := func(outcome string) {
		if counter != nil {
			counter.CountUpdate(db.KindStartCommand, outcome)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeBridgeJSON(w, http.StatusMethodNotAllowed, `{"error":"method_not_allowed"}`)
			return
		}
		if auth == nil || !auth.Authenticate(r) {
			writeBridgeJSON(w, http.StatusUnauthorized, `{"error":"unauthorized"}`)
			return
		}
		obs, status := decodeObservation(w, r)
		if status != 0 {
			if status == http.StatusRequestEntityTooLarge {
				writeBridgeJSON(w, status, `{"error":"too_large"}`)
			} else {
				writeBridgeJSON(w, status, `{"error":"invalid_observation"}`)
			}
			return
		}
		// Every error below is scrubbed before it is logged: a store or
		// handler error string is the one path by which an id or the token
		// could still reach a log line, as in the receiver's dispatch.
		scrub := func(err error) string {
			msg := err.Error()
			if rd, ok := auth.(Redactor); ok {
				msg = rd.Redact(msg)
			}
			msg = redactID(msg, obs.TelegramID)
			msg = redactID(msg, obs.UpdateID)
			return audit.ScrubText(msg)
		}
		ctx := r.Context()
		chat := sql.NullInt64{Int64: obs.TelegramID, Valid: true}
		if _, err := store.AcceptUpdateAt(ctx, obs.UpdateID, db.KindStartCommand, chat, obs.ObservedAt); err != nil {
			count(OutcomeDispatchError)
			slog.Error("bot-start bridge: accept failed", "err", scrub(err))
			writeBridgeJSON(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		// Dispatch whether or not this call accepted the row: a row accepted by
		// an earlier attempt whose dispatch failed must be processed now, and
		// a processed row answers ErrUpdateNotClaimable without running fn.
		var outcome string
		err := store.DispatchOnce(ctx, obs.UpdateID, func(ctx context.Context, tx *sql.Tx) (string, error) {
			kind, storedChat, err := store.UpdateRoutingTx(ctx, tx, obs.UpdateID)
			if err != nil {
				return "", err
			}
			if kind != db.KindStartCommand || storedChat != chat {
				return "", errRoutingMismatch
			}
			o, err := record(ctx, tx, obs.TelegramID, obs.UpdateID)
			if err != nil {
				return "", handlerError{err: err}
			}
			outcome = o
			return o, nil
		})
		var he handlerError
		switch {
		case err == nil:
			count(outcome)
		case errors.Is(err, db.ErrUpdateNotClaimable):
			// Already recorded (a redelivery or retry): nothing to do.
			count(OutcomeDuplicate)
		case errors.Is(err, errRoutingMismatch):
			// The update_id names some other update. Not dispatched, and no
			// difference shown to the caller, but visible to the operator.
			count(OutcomeRoutingMismatch)
			slog.Warn("bot-start bridge: update_id already stored with different routing", "err", scrub(err))
		case errors.As(err, &he):
			// The business rule failed: counted as a handler failure, as in
			// the receiver.
			count(db.OutcomeHandlerError)
			slog.Error("bot-start bridge: handler failed", "err", scrub(err))
			writeBridgeJSON(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		default:
			// Routing or the database failed, not the handler. Counted apart
			// so an infrastructure problem is not read as a broken handler.
			count(OutcomeDispatchError)
			slog.Error("bot-start bridge: dispatch failed", "err", scrub(err))
			writeBridgeJSON(w, http.StatusServiceUnavailable, `{"error":"unavailable"}`)
			return
		}
		writeBridgeJSON(w, http.StatusAccepted, acceptedBody)
	})
}

// redactID removes one decimal id from s where it stands as a whole number.
// audit.ScrubText only masks runs of 7+ digits, and a Telegram id can be
// shorter.
func redactID(s string, id int64) string {
	re := regexp.MustCompile(`\b` + strconv.FormatInt(id, 10) + `\b`)
	return re.ReplaceAllString(s, "[redacted]")
}

// decodeObservation reads exactly one strict JSON object with the three
// fields, rejecting unknown fields (an internal user_id among them), trailing
// data, non-positive ids and an out-of-range observed_at. It returns a
// non-zero HTTP status on rejection: 413 when the body exceeds
// maxObservationBody (wherever the excess is), 400 otherwise.
func decodeObservation(w http.ResponseWriter, r *http.Request) (botStartObservation, int) {
	var obs botStartObservation
	// MaxBytesReader, not LimitReader: a LimitReader shows the decoder a clean
	// EOF at the limit, so a valid object followed by padding up to the limit
	// and then anything at all would pass. MaxBytesReader fails the read.
	body := http.MaxBytesReader(w, r.Body, maxObservationBody)
	raw, err := io.ReadAll(body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return obs, http.StatusRequestEntityTooLarge
		}
		return obs, http.StatusBadRequest
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&obs); err != nil {
		return obs, http.StatusBadRequest
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return obs, http.StatusBadRequest
	}
	if obs.UpdateID <= 0 || obs.TelegramID <= 0 || obs.ObservedAt.IsZero() {
		return obs, http.StatusBadRequest
	}
	if obs.ObservedAt.After(time.Now().Add(maxObservationSkew)) {
		return obs, http.StatusBadRequest
	}
	obs.ObservedAt = obs.ObservedAt.UTC()
	return obs, 0
}

func writeBridgeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
