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

// maxAnswerRunes caps a free-text answer. mctl-api names no per-request
// maximum; its body limit (64 KiB) is far above this.
const maxAnswerRunes = 2000

// maxEchoRunes bounds how much of a free-text answer the confirmation echoes.
const maxEchoRunes = 60

// maxStatusRows bounds how many open requests /mctl input status (no code)
// re-reads from mctl-api; the codes of the rest are still listed.
const maxStatusRows = 5

// Replies. Wording for eligibility failures is deliberately neutral: policy
// belongs to mctl-api and is never explained to the surface user.
const (
	replyAlready      = "Already answered."
	replyNotLinked    = "This Telegram account is not linked to a platform identity yet. An operator needs to resolve this before /mctl input can be used."
	replyNeutral      = "This answer could not be accepted from this account."
	replyInvalid      = "That answer was not accepted. Check the question and try again."
	replyPlatformErr  = "The platform did not accept that answer."
	replyNotSubmitted = "Could not reach the platform; nothing was submitted. Try again."
	inputUsage        = "Usage: /mctl input <code> <answer>\nAlso: /mctl input status [code]"
)

func couldNotConfirm(code string) string {
	return fmt.Sprintf("Could not confirm; check again with /mctl input status %s", code)
}

func unconfirmedWaiting(code string) string {
	return fmt.Sprintf("Your answer to %s could not be confirmed, and the question is still waiting. Sending the same answer again is safe: /mctl input %s <answer>", code, code)
}

func resolvedUnconfirmed(code string) string {
	return fmt.Sprintf("Question %s was answered. Whether it was your answer could not be confirmed; check /mctl work status.", code)
}

func submittedUnconfirmed(echo, code string) string {
	return fmt.Sprintf("Submitted: %s. The platform has not confirmed it yet; check with /mctl input status %s", echo, code)
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
	logArgs := []any{"request_id", row.RequestID, "work_item_id", row.WorkItemID, "delivery_id", row.ID, "tg_message_id", row.TGMessageID}

	var submit, echo string
	switch row.Kind {
	case workctx.HumanInputTypeSingleChoice:
		idx, hint := h.optionIndex(row, code, value)
		if hint != "" {
			// Shape errors never reach mctl-api.
			return h.reply(ctx, meta.UserID, hint)
		}
		// The option text is not stored locally (content-free rows), so
		// read the canonical request and take option idx from it. The same
		// request_hash guarantees the same options as delivered; the digest
		// check is defence in depth.
		v, err := h.API.GetHumanInput(ctx, actorTGID, row.RequestID)
		if err != nil {
			if errors.Is(err, workctx.ErrHumanInputNotFound) {
				h.markTerminal(ctx, row, db.HumanInputInactive, "not_found")
				return h.reply(ctx, meta.UserID, NoLongerActive)
			}
			slog.Warn("human input pre-submit read failed", append(logArgs, "outcome", errClass(err))...)
			return h.reply(ctx, meta.UserID, replyNotSubmitted)
		}
		if v.RequestHash != row.RequestHash {
			h.markTerminal(ctx, row, db.HumanInputSuperseded, "superseded")
			return h.reply(ctx, meta.UserID, NoLongerActive)
		}
		if v.State != workctx.HumanInputStatePending {
			return h.reply(ctx, meta.UserID, h.settle(ctx, row, v, false))
		}
		if idx >= len(v.Options) || OptionDigest(v.Options[idx]) != row.OptionDigests[idx] {
			slog.Warn("human input options differ from delivery", append(logArgs, "outcome", "option_mismatch")...)
			return h.reply(ctx, meta.UserID, replyPlatformErr)
		}
		submit, echo = v.Options[idx], fmt.Sprintf("option %d", idx+1)
	case workctx.HumanInputTypeFreeText:
		var hint string
		submit, echo, hint = freeText(code, value)
		if hint != "" {
			return h.reply(ctx, meta.UserID, hint)
		}
	default:
		return h.reply(ctx, meta.UserID, NoLongerActive)
	}

	req := workctx.ResponseRequest{RequestHash: row.RequestHash, Value: submit}
	resp, err := h.API.RespondHumanInput(ctx, actorTGID, row.RequestID, req, idemKey(row.RequestID, row.RequestHash, meta.TGMessageID))
	switch {
	case err == nil && resp.Status == workctx.HumanInputStatusAccepted:
		h.markAnswered(ctx, row, "accepted")
		h.Metrics.CountHumanInputEvent(metrics.HumanInputEventResponseSubmitted, "ok")
		if !row.DeliveredAt.IsZero() {
			h.Metrics.ObserveHumanInputRespondLatency(time.Since(row.DeliveredAt))
		}
		slog.Info("human input response submitted", append(logArgs, "outcome", "accepted", "correlation_id", resp.CorrelationID)...)
		if resp.Detail == workctx.DetailAlreadyAccepted {
			// mctl-api's replay of this human's identical, already
			// accepted answer.
			return h.reply(ctx, meta.UserID, replyAlready)
		}
		return h.reply(ctx, meta.UserID, fmt.Sprintf("Answered by you: %s. Agent will resume.", echo))
	case err == nil:
		// 202 pending_delivery: recorded and signalled, not confirmed by
		// the workflow. Never claim the agent resumed. The row stays open
		// (submitted) so a status read or a resubmission of the same answer
		// can settle it.
		h.markTerminal(ctx, row, db.HumanInputSubmitted, "pending_delivery")
		h.Metrics.CountHumanInputEvent(metrics.HumanInputEventResponseSubmitted, "unconfirmed")
		slog.Info("human input response unconfirmed", append(logArgs, "outcome", "pending_delivery", "correlation_id", resp.CorrelationID)...)
		return h.reply(ctx, meta.UserID, submittedUnconfirmed(echo, code))
	case errors.Is(err, workctx.ErrRequestSuperseded):
		h.markTerminal(ctx, row, db.HumanInputSuperseded, "superseded")
		return h.rejected(ctx, meta.UserID, logArgs, err, NoLongerActive)
	case errors.Is(err, workctx.ErrRequestNotActive):
		h.markTerminal(ctx, row, db.HumanInputInactive, rejectionOutcome(err))
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
	// Transport failure, timeout or 5xx (including mctl-api's 503 "recorded,
	// resubmit to retry delivery"): the answer may or may not have been
	// taken. Re-read the canonical state and render that, never "success".
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
		if i >= maxStatusRows {
			break
		}
		fmt.Fprintf(&sb, "%s: %s\n", row.AnswerCode, h.canonicalText(ctx, actorTGID, row, false))
	}
	if len(open) > maxStatusRows {
		rest := make([]string, 0, len(open)-maxStatusRows)
		for _, row := range open[maxStatusRows:] {
			rest = append(rest, row.AnswerCode)
		}
		fmt.Fprintf(&sb, "%d more open, not checked here: %s. Use /mctl input status <code>.\n", len(rest), strings.Join(rest, ", "))
	}
	return h.reply(ctx, meta.UserID, strings.TrimRight(sb.String(), "\n"))
}

// optionIndex resolves a single_choice answer to a 0-based option index
// using only the delivered row: an option number in range, or the option's
// text (case-insensitive), matched by digest. Anything else returns a usage
// hint and never reaches mctl-api.
func (h *Handler) optionIndex(row db.HumanInputDelivery, code, value string) (int, string) {
	value = strings.TrimSpace(value)
	usage := fmt.Sprintf("Reply with an option number 1-%d: /mctl input %s <number>", len(row.OptionDigests), code)
	if value == "" || len(row.OptionDigests) == 0 {
		return 0, usage
	}
	if n, err := strconv.Atoi(value); err == nil {
		if n < 1 || n > len(row.OptionDigests) {
			return 0, usage
		}
		return n - 1, ""
	}
	want := OptionDigest(value)
	for i, d := range row.OptionDigests {
		if d == want {
			return i, ""
		}
	}
	return 0, usage
}

// freeText validates a free-text answer: non-empty after trimming and at most
// maxAnswerRunes. A longer answer is refused, never truncated: submitting a
// value the human did not write would break the binding between what they
// said and what the agent resumes on. It returns the value to submit, a short
// echo for the confirmation, and a usage hint when the value is unusable.
func freeText(code, value string) (submit, echo, hint string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", fmt.Sprintf("Add your answer after the code: /mctl input %s <your answer>", code)
	}
	r := []rune(value)
	if len(r) > maxAnswerRunes {
		return "", "", fmt.Sprintf("Answer is too long (%d characters max). Shorten it and send again: /mctl input %s <your answer>", maxAnswerRunes, code)
	}
	echoRunes := r
	if len(echoRunes) > maxEchoRunes {
		echoRunes = append(append([]rune{}, echoRunes[:maxEchoRunes]...), []rune("...")...)
	}
	return string(r), oneLine(string(echoRunes), maxEchoRunes+3), ""
}

// canonicalText re-reads the request from mctl-api and renders its state,
// updating the local row to match. afterSubmit selects the wording used when
// a submit's outcome is being resolved.
func (h *Handler) canonicalText(ctx context.Context, actorTGID int64, row db.HumanInputDelivery, afterSubmit bool) string {
	v, err := h.API.GetHumanInput(ctx, actorTGID, row.RequestID)
	if errors.Is(err, workctx.ErrHumanInputNotFound) {
		h.markTerminal(ctx, row, db.HumanInputInactive, "not_found")
		return NoLongerActive
	}
	if err != nil {
		slog.Warn("human input status read failed", "request_id", row.RequestID, "delivery_id", row.ID, "outcome", errClass(err))
		if afterSubmit {
			h.markUnconfirmed(ctx, row)
		}
		return couldNotConfirm(row.AnswerCode)
	}
	if v.RequestHash != row.RequestHash {
		h.markTerminal(ctx, row, db.HumanInputSuperseded, "superseded")
		return NoLongerActive
	}
	return h.settle(ctx, row, v, afterSubmit)
}

// settle maps a canonical view of the row's own request version onto a reply
// and the row's state. Only mctl-api's states decide; "unknown" (the owning
// workflow did not answer) changes nothing.
func (h *Handler) settle(ctx context.Context, row db.HumanInputDelivery, v *workctx.RequestView, afterSubmit bool) string {
	switch v.State {
	case workctx.HumanInputStateResolved:
		if row.State == db.HumanInputUnconfirmed && !afterSubmit {
			h.markTerminal(ctx, row, db.HumanInputInactive, "resolved_unconfirmed")
			return resolvedUnconfirmed(row.AnswerCode)
		}
		if afterSubmit || row.State == db.HumanInputSubmitted {
			h.markAnswered(ctx, row, "resolved")
			if afterSubmit {
				return "Answered. Check /mctl work status for progress."
			}
			return "Answered. Agent will resume."
		}
		// Resolved by an answer that is not known to be this human's.
		h.markTerminal(ctx, row, db.HumanInputInactive, "resolved")
		return "Answered."
	case workctx.HumanInputStatePending:
		if afterSubmit {
			// The submit's outcome is unknown and mctl-api still shows the
			// question waiting: the answer may sit in its ledger
			// unconfirmed. Never "not answered" from here on.
			h.markUnconfirmed(ctx, row)
			return couldNotConfirm(row.AnswerCode)
		}
		switch row.State {
		case db.HumanInputSubmitted:
			return "Submitted; waiting for the platform to confirm."
		case db.HumanInputUnconfirmed:
			return unconfirmedWaiting(row.AnswerCode)
		}
		return "Waiting for your answer."
	case workctx.HumanInputStateExpired, workctx.HumanInputStateTimedOut, workctx.HumanInputStateNotPending:
		h.markTerminal(ctx, row, db.HumanInputInactive, safeToken(v.State))
		return NoLongerActive
	default:
		if afterSubmit {
			h.markUnconfirmed(ctx, row)
		}
		return couldNotConfirm(row.AnswerCode)
	}
}

// markUnconfirmed records that a submit's outcome is unknown. A row already
// submitted (mctl-api confirmed it recorded an answer) keeps that stronger
// state.
func (h *Handler) markUnconfirmed(ctx context.Context, row db.HumanInputDelivery) {
	if row.State == db.HumanInputSubmitted {
		return
	}
	h.markTerminal(ctx, row, db.HumanInputUnconfirmed, "submit_unconfirmed")
}

// rejectionOutcome is the rejection state carried by a typed human-input
// error, as a log/row outcome token.
func rejectionOutcome(err error) string {
	var apiErr *workctx.APIError
	if errors.As(err, &apiErr) && apiErr.Code != "" {
		return safeToken(apiErr.Code)
	}
	return errClass(err)
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
