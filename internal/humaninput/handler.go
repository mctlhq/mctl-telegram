package humaninput

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/actor"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/workctx"
)

// Replier posts a synchronous reply into the owner's Saved Messages. The
// control.Notifier satisfies it; an interface here keeps this package free of
// a dependency on internal/agent/control.
type Replier interface {
	Reply(ctx context.Context, userID int64, text string) error
}

// Meta is the per-command context the router hands over: the same facts
// control.SavedMeta carries, minus the chat id this handler does not need.
type Meta struct {
	UserID      int64
	SelfTGID    int64
	TGMessageID int64
}

// defaultMaxAnswerRunes caps a free-text answer when the request names no
// maximum of its own.
const defaultMaxAnswerRunes = 2000

// maxEchoRunes bounds how much of a free-text answer the confirmation echoes.
const maxEchoRunes = 60

// Replies. Wording for eligibility failures is deliberately neutral: policy
// belongs to mctl-api and is never explained to the surface user.
const (
	replyAlready     = "Already answered."
	replyNotLinked   = "This Telegram account is not linked to a platform identity yet. An operator needs to resolve this before /mctl input can be used."
	replyNeutral     = "This answer could not be accepted from this account."
	replyInvalid     = "That answer was not accepted. Check the question and try again."
	replyPlatformErr = "The platform did not accept that answer."
	inputUsage       = "Usage: /mctl input <code> <answer>\nAlso: /mctl input status [code]"
)

func couldNotConfirm(code string) string {
	return fmt.Sprintf("Could not confirm; check again with /mctl input status %s", code)
}

// Handler implements /mctl input <code> <value> and /mctl input status [code].
// It is wired only when HUMAN_INPUT_ENABLED is true; with it nil the router
// treats /mctl input as an unknown command.
type Handler struct {
	Store   *db.Store
	API     API
	Replier Replier
	Metrics *metrics.Registry
}

// Usage returns the usage line for a malformed /mctl input.
func (h *Handler) Usage(ctx context.Context, userID int64) error {
	return h.Replier.Reply(ctx, userID, inputUsage)
}

// Answer handles /mctl input <code> <value>.
func (h *Handler) Answer(ctx context.Context, meta Meta, code, value string) error {
	h.Metrics.CountHumanInputEvent(metrics.HumanInputEventResponseReceived, "ok")
	actorTGID, ok, err := actor.Resolve(ctx, h.Store, meta.UserID, meta.SelfTGID)
	if err != nil {
		return err
	}
	if !ok {
		return h.reply(ctx, meta.UserID, replyNotLinked)
	}
	code = normalizeCode(code)
	row, err := h.Store.GetHumanInputDeliveryByCode(ctx, meta.UserID, code)
	if errors.Is(err, db.ErrHumanInputDeliveryNotFound) {
		return h.reply(ctx, meta.UserID, NoLongerActive)
	}
	if err != nil {
		return fmt.Errorf("look up human input code: %w", err)
	}
	if row.Terminal() {
		if row.State == db.HumanInputAnswered {
			return h.reply(ctx, meta.UserID, replyAlready)
		}
		return h.reply(ctx, meta.UserID, NoLongerActive)
	}

	submit, echo, hint := h.shape(row, code, value)
	if hint != "" {
		// Shape errors never reach mctl-api.
		return h.reply(ctx, meta.UserID, hint)
	}

	req := workctx.ResponseRequest{RequestHash: row.RequestHash, Kind: row.Kind, Value: submit}
	resp, err := h.API.RespondHumanInput(ctx, actorTGID, row.RequestID, req, idemKey(row.RequestID, row.RequestHash, meta.TGMessageID))
	logArgs := []any{"request_id", row.RequestID, "work_item_id", row.WorkItemID, "delivery_id", row.ID, "tg_message_id", row.TGMessageID}
	switch {
	case err == nil:
		if resp.State != workctx.HumanInputStateAnswered {
			// Accepted without confirming the answered state: never claim
			// the agent resumed.
			slog.Info("human input response unconfirmed", append(logArgs, "outcome", "state_"+safeToken(resp.State), "correlation_id", resp.CorrelationID)...)
			h.Metrics.CountHumanInputEvent(metrics.HumanInputEventResponseSubmitted, "unconfirmed")
			return h.reply(ctx, meta.UserID, couldNotConfirm(code))
		}
		h.markAnswered(ctx, row, "answered")
		h.Metrics.CountHumanInputEvent(metrics.HumanInputEventResponseSubmitted, "ok")
		if !row.DeliveredAt.IsZero() {
			h.Metrics.ObserveHumanInputRespondLatency(time.Since(row.DeliveredAt))
		}
		slog.Info("human input response submitted", append(logArgs, "outcome", "ok", "correlation_id", resp.CorrelationID)...)
		return h.reply(ctx, meta.UserID, fmt.Sprintf("Answered by you: %s. Agent will resume.", echo))
	case errors.Is(err, workctx.ErrAlreadyAnswered):
		h.markAnswered(ctx, row, "already_answered")
		return h.rejected(ctx, meta.UserID, logArgs, err, replyAlready)
	case errors.Is(err, workctx.ErrRequestSuperseded):
		h.markTerminal(ctx, row, db.HumanInputSuperseded, "superseded")
		return h.rejected(ctx, meta.UserID, logArgs, err, NoLongerActive)
	case errors.Is(err, workctx.ErrRequestNotActive):
		h.markTerminal(ctx, row, db.HumanInputInactive, "not_active")
		return h.rejected(ctx, meta.UserID, logArgs, err, NoLongerActive)
	case errors.Is(err, workctx.ErrNotEligible), isLinkError(err):
		// 403: neutral wording, no retry, nothing about policy revealed.
		return h.rejected(ctx, meta.UserID, logArgs, err, replyNeutral)
	case errors.Is(err, workctx.ErrAnswerInvalid):
		return h.rejected(ctx, meta.UserID, logArgs, err, replyInvalid)
	}
	var apiErr *workctx.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode < 500 {
		return h.rejected(ctx, meta.UserID, logArgs, err, replyPlatformErr)
	}
	// Transport failure, timeout or 5xx: the answer may or may not have been
	// accepted. Re-read the canonical state and render that, never "success".
	slog.Warn("human input submit failed, re-reading", append(logArgs, "outcome", errClass(err))...)
	h.Metrics.CountHumanInputEvent(metrics.HumanInputEventResponseSubmitted, "error")
	return h.reply(ctx, meta.UserID, h.canonicalText(ctx, actorTGID, row, true))
}

// Status handles /mctl input status [code]. Local rows are only an index of
// codes; every state shown comes from mctl-api.
func (h *Handler) Status(ctx context.Context, meta Meta, code string) error {
	actorTGID, ok, err := actor.Resolve(ctx, h.Store, meta.UserID, meta.SelfTGID)
	if err != nil {
		return err
	}
	if !ok {
		return h.reply(ctx, meta.UserID, replyNotLinked)
	}
	if err := h.Store.UpsertHumanInputActor(ctx, meta.UserID, actorTGID); err != nil {
		slog.Warn("human input actor enroll failed", "user_id", meta.UserID, "outcome", errClass(err))
	}
	code = normalizeCode(code)
	if code != "" {
		row, err := h.Store.GetHumanInputDeliveryByCode(ctx, meta.UserID, code)
		if errors.Is(err, db.ErrHumanInputDeliveryNotFound) {
			return h.reply(ctx, meta.UserID, NoLongerActive)
		}
		if err != nil {
			return fmt.Errorf("look up human input code: %w", err)
		}
		return h.reply(ctx, meta.UserID, h.canonicalText(ctx, actorTGID, row, false))
	}
	open, err := h.Store.ListOpenHumanInputDeliveries(ctx, meta.UserID)
	if err != nil {
		return fmt.Errorf("list open human input deliveries: %w", err)
	}
	if len(open) == 0 {
		return h.reply(ctx, meta.UserID, "No open input requests.")
	}
	var sb strings.Builder
	for i, row := range open {
		if i >= 5 {
			break
		}
		fmt.Fprintf(&sb, "%s: %s\n", row.AnswerCode, h.canonicalText(ctx, actorTGID, row, false))
	}
	return h.reply(ctx, meta.UserID, strings.TrimRight(sb.String(), "\n"))
}

// shape validates the typed value against the delivered request's shape only
// (an option within range, or non-empty text within the length cap). It
// returns the value to submit, a short echo for the confirmation, and a usage
// hint when the value is unusable.
func (h *Handler) shape(row db.HumanInputDelivery, code, value string) (submit, echo, hint string) {
	value = strings.TrimSpace(value)
	switch row.Kind {
	case workctx.HumanInputKindSingleChoice:
		usage := fmt.Sprintf("Reply with an option number 1-%d: /mctl input %s <number>", len(row.OptionIDs), code)
		if value == "" {
			return "", "", usage
		}
		if n, err := strconv.Atoi(value); err == nil {
			if n < 1 || n > len(row.OptionIDs) {
				return "", "", usage
			}
			return row.OptionIDs[n-1], fmt.Sprintf("option %d", n), ""
		}
		for i, id := range row.OptionIDs {
			if strings.EqualFold(id, value) {
				return id, fmt.Sprintf("option %d", i+1), ""
			}
		}
		return "", "", usage
	case workctx.HumanInputKindFreeText:
		if value == "" {
			return "", "", fmt.Sprintf("Add your answer after the code: /mctl input %s <your answer>", code)
		}
		max := row.MaxLength
		if max <= 0 {
			max = defaultMaxAnswerRunes
		}
		r := []rune(value)
		if len(r) > max {
			r = r[:max]
		}
		echoRunes := r
		if len(echoRunes) > maxEchoRunes {
			echoRunes = append(append([]rune{}, echoRunes[:maxEchoRunes]...), []rune("...")...)
		}
		return string(r), string(echoRunes), ""
	default:
		return "", "", NoLongerActive
	}
}

// canonicalText re-reads the request from mctl-api and renders its state,
// updating the local row to match terminal states. afterSubmit selects the
// wording used when a submit's outcome is being resolved.
func (h *Handler) canonicalText(ctx context.Context, actorTGID int64, row db.HumanInputDelivery, afterSubmit bool) string {
	v, err := h.API.GetHumanInput(ctx, actorTGID, row.RequestID)
	if err != nil {
		slog.Warn("human input status read failed", "request_id", row.RequestID, "delivery_id", row.ID, "outcome", errClass(err))
		return couldNotConfirm(row.AnswerCode)
	}
	if v.RequestHash != row.RequestHash {
		h.markTerminal(ctx, row, db.HumanInputSuperseded, "superseded")
		return NoLongerActive
	}
	switch v.State {
	case workctx.HumanInputStateAnswered:
		h.markAnswered(ctx, row, "answered")
		if afterSubmit {
			return "Answered. Check /mctl work status for progress."
		}
		return "Answered."
	case workctx.HumanInputStatePending, "":
		if afterSubmit {
			return couldNotConfirm(row.AnswerCode)
		}
		return "Waiting for your answer."
	default:
		h.markTerminal(ctx, row, db.HumanInputInactive, safeToken(v.State))
		return NoLongerActive
	}
}

func (h *Handler) rejected(ctx context.Context, userID int64, logArgs []any, err error, text string) error {
	outcome := errClass(err)
	var apiErr *workctx.APIError
	if errors.As(err, &apiErr) && apiErr.Code != "" {
		outcome = safeToken(apiErr.Code)
	}
	h.Metrics.CountHumanInputEvent(metrics.HumanInputEventResponseRejected, errClass(err))
	args := append(logArgs, "outcome", outcome)
	if apiErr != nil {
		args = append(args, "correlation_id", apiErr.CorrelationID)
	}
	slog.Info("human input response rejected", args...)
	return h.reply(ctx, userID, text)
}

func (h *Handler) markAnswered(ctx context.Context, row db.HumanInputDelivery, outcome string) {
	h.markTerminal(ctx, row, db.HumanInputAnswered, outcome)
}

func (h *Handler) markTerminal(ctx context.Context, row db.HumanInputDelivery, state, outcome string) {
	if _, err := h.Store.MarkHumanInputDelivery(ctx, row.UserID, row.ID, state, outcome); err != nil {
		slog.Warn("human input mark delivery failed", "delivery_id", row.ID, "outcome", errClass(err))
	}
}

func (h *Handler) reply(ctx context.Context, userID int64, text string) error {
	return h.Replier.Reply(ctx, userID, text)
}

func normalizeCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

// idemKey derives the stable Idempotency-Key: a redelivered command (same
// request, same hash, same Telegram message) always yields the same key.
func idemKey(requestID, requestHash string, tgMessageID int64) string {
	sum := sha256.Sum256([]byte(requestID + "|" + requestHash + "|" + strconv.FormatInt(tgMessageID, 10)))
	return hex.EncodeToString(sum[:])
}

// safeToken keeps a platform-supplied state or code usable as a log value:
// lowercase letters, digits, underscore and dash only, bounded length.
func safeToken(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(s) {
		if sb.Len() >= 32 {
			break
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
