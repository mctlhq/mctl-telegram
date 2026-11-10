// Package executor turns a parsed bridge command and a permit answer into a
// result, using the in-process fakestore. Every mapping from a situation to an
// outcome lives in the single Table below; the runbook is tested against it.
package executor

import (
	"errors"
	"fmt"
	"strings"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridgeclient"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

// Situation names one row of the outcome map.
type Situation string

const (
	SitReadOK            Situation = "read_ok"
	SitApplied           Situation = "applied"
	SitAppliedPriorLease Situation = "applied_prior_lease"
	SitSchemaInvalid     Situation = "schema_invalid"
	SitCancelRequested   Situation = "cancel_requested"
	SitUnavailable       Situation = "unavailable"
	SitStoreTransient    Situation = "store_transient"
	SitStoreRejected     Situation = "store_rejected"
	SitAmbiguousWrite    Situation = "ambiguous_write"
	SitPermitRefused     Situation = "permit_write_fence_refused"
	SitPermitFenceDown   Situation = "permit_write_fence_unavailable"
	SitPermitAlready     Situation = "permit_already_issued"
	SitPermitNotMutating Situation = "permit_not_mutating"
	SitPermit429         Situation = "permit_429"
	SitPermitTransient   Situation = "permit_transient"
	SitStop              Situation = "stop"
	SitNotFound          Situation = "not_found"
	SitResultReplayed    Situation = "result_replayed"
	SitResultAlreadyDone Situation = "result_already_completed"
	SitResultConflict    Situation = "result_conflict"
	SitResultBug         Situation = "result_rejected"
	SitResultRetry       Situation = "result_retry"
	SitClaim429          Situation = "claim_429"
	SitUnauthorized      Situation = "unauthorized"
	SitUnmapped          Situation = "unmapped"
)

// Action is what the poller does next.
type Action string

const (
	ActSubmit           Action = "submit"
	ActSubmitNoPm       Action = "submit, no permit"
	ActDropOrSub        Action = "submit if envelope valid, else drop"
	ActSubmitNeverRetry Action = "submit, never retry"
	ActStop             Action = "stop, no result"
	ActStopMetric       Action = "stop, metric"
	ActDone             Action = "done"
	ActLogNoSend        Action = "log code + metric, no resend"
	ActLogBug           Action = "log code + metric (bug), no resend"
	ActResend           Action = "resend the same bytes, backoff 250ms..8s (429: at least Retry-After), until expires_at"
	ActBackoff          Action = "back off at least Retry-After"
	ActStopReady        Action = "stop the command, readiness fails, claim backs off at cap"
	ActFailClosed       Action = "fail closed: no effect, no new body, metric unmapped_responses_total{route}"
)

// Row is one line of the outcome map. A row with an empty Outcome sends no
// result of its own.
type Row struct {
	Situation   Situation
	Description string
	Outcome     string
	ErrorCode   string
	Effect      string
	Detail      string // default error_detail
	Next        Action
}

// Table is the outcome map. It is final within the frozen result.schema.json
// enums (mctl-api#957).
var Table = []Row{
	{SitReadOK, "quote / read_status ok", v1alpha1.OutcomeSucceeded, v1alpha1.ErrNone, v1alpha1.EffectNone, "", ActSubmit},
	{SitApplied, "mutation applied under this lease's permit", v1alpha1.OutcomeSucceeded, v1alpha1.ErrNone, v1alpha1.EffectApplied, "", ActSubmit},
	{SitAppliedPriorLease, "mutation re-delivered after reclaim, local effect record exists", v1alpha1.OutcomeFailedTerminal, v1alpha1.ErrInternal, v1alpha1.EffectUnknown, "applied_prior_lease", ActSubmitNoPm},
	{SitSchemaInvalid, "schema-invalid / audience mismatch", v1alpha1.OutcomeFailedTerminal, v1alpha1.ErrProviderRejected, v1alpha1.EffectNone, "schema_invalid", ActDropOrSub},
	{SitCancelRequested, "cancel_requested=true (unreachable on mctl-api a9ca5814; defence)", v1alpha1.OutcomeCancelled, v1alpha1.ErrNone, v1alpha1.EffectNone, "", ActSubmit},
	{SitUnavailable, "kill switch / breaker open / tenant busy", v1alpha1.OutcomeFailedRetryable, v1alpha1.ErrProviderUnavailable, v1alpha1.EffectNone, "", ActSubmit},
	{SitStoreTransient, "fakestore 429 / transient read failure", v1alpha1.OutcomeFailedRetryable, v1alpha1.ErrProviderUnavailable, v1alpha1.EffectNone, "", ActSubmit},
	{SitStoreRejected, "unknown or revoked fake session, item unavailable, no order to cancel", v1alpha1.OutcomeFailedTerminal, v1alpha1.ErrProviderRejected, v1alpha1.EffectNone, "", ActSubmit},
	{SitAmbiguousWrite, "ambiguous write", v1alpha1.OutcomeFailedTerminal, v1alpha1.ErrProviderUnavailable, v1alpha1.EffectUnknown, "", ActSubmitNeverRetry},
	{SitPermitRefused, "permit write_fence_refused (403)", v1alpha1.OutcomeApprovalRefused, v1alpha1.ErrApprovalRefused, v1alpha1.EffectNone, "", ActSubmit},
	{SitPermitFenceDown, "permit write_fence_unavailable (503)", v1alpha1.OutcomeFailedRetryable, v1alpha1.ErrInternal, v1alpha1.EffectNone, "write_fence_unavailable", ActSubmit},
	{SitPermitAlready, "permit permit_already_issued (409; owner decision 2026-11-09)", v1alpha1.OutcomeFailedTerminal, v1alpha1.ErrInternal, v1alpha1.EffectUnknown, "permit_already_issued", ActSubmit},
	{SitPermitNotMutating, "permit not_mutating (409)", v1alpha1.OutcomeFailedTerminal, v1alpha1.ErrInternal, v1alpha1.EffectNone, "not_mutating", ActSubmit},
	{SitPermit429, "permit 429", v1alpha1.OutcomeFailedRetryable, v1alpha1.ErrProviderUnavailable, v1alpha1.EffectNone, "", ActSubmit},
	{SitPermitTransient, "permit 5xx (not the 503 fence) / transport", v1alpha1.OutcomeFailedRetryable, v1alpha1.ErrProviderUnavailable, v1alpha1.EffectNone, "", ActSubmit},
	{SitStop, "any call lease_stale / command_expired / command_cancelled", "", "", "", "", ActStop},
	{SitNotFound, "any call command_not_found (404)", "", "", "", "", ActStopMetric},
	{SitResultReplayed, "result replayed:true", "", "", "", "", ActDone},
	{SitResultAlreadyDone, "result already_completed (unreachable on a9ca5814; defence only)", "", "", "", "", ActDone},
	{SitResultConflict, "result result_conflict", "", "", "", "", ActLogNoSend},
	{SitResultBug, "result invalid_document / binding_mismatch / result_inconsistent", "", "", "", "", ActLogBug},
	{SitResultRetry, "result 5xx / 429 / transport", "", "", "", "", ActResend},
	{SitClaim429, "claim 429", "", "", "", "", ActBackoff},
	{SitUnauthorized, "any call 401 (no code)", "", "", "", "", ActStopReady},
	{SitUnmapped, "any other status/code, or unparseable body", "", "", "", "", ActFailClosed},
}

// RowFor returns the table row of a situation.
func RowFor(s Situation) (Row, bool) {
	for _, r := range Table {
		if r.Situation == s {
			return r, true
		}
	}
	return Row{}, false
}

// MarkdownTable renders Table for the runbook.
func MarkdownTable() string {
	var b strings.Builder
	b.WriteString("| Situation | outcome | error_code | provider_effect | Next step |\n|---|---|---|---|---|\n")
	for _, r := range Table {
		dash := func(s string) string {
			if s == "" {
				return "-"
			}
			return s
		}
		code := dash(r.ErrorCode)
		if r.Detail != "" && r.ErrorCode != "" {
			code += " (`error_detail=" + r.Detail + "`)"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", r.Description, dash(r.Outcome), code, dash(r.Effect), r.Next)
	}
	return b.String()
}

func apiErr(err error) (*bridgeclient.APIError, bool) {
	var ae *bridgeclient.APIError
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}

func isTransport(err error) bool {
	if err == nil || errors.Is(err, bridgeclient.ErrMalformed) || errors.Is(err, bridgeclient.ErrOrigin) || errors.Is(err, bridgeclient.ErrCredential) {
		return false
	}
	_, isAPI := apiErr(err)
	return !isAPI
}

// common maps the statuses every route shares.
func common(ae *bridgeclient.APIError) (Situation, bool) {
	switch {
	case ae.Status == 404 && ae.Code == "command_not_found":
		return SitNotFound, true
	case ae.Status == 409 && (ae.Code == "lease_stale" || ae.Code == "command_expired" || ae.Code == "command_cancelled"):
		return SitStop, true
	case ae.Status == 401 && ae.Code == "":
		return SitUnauthorized, true
	}
	return "", false
}

// ClassifyPermit maps a WritePermit error. A nil error means granted and is
// not classified here.
func ClassifyPermit(err error) Situation {
	if ae, ok := apiErr(err); ok {
		if s, ok := common(ae); ok {
			return s
		}
		switch {
		case ae.Status == 403 && ae.Code == "write_fence_refused":
			return SitPermitRefused
		case ae.Status == 503 && ae.Code == "write_fence_unavailable":
			return SitPermitFenceDown
		case ae.Status == 409 && ae.Code == "permit_already_issued":
			return SitPermitAlready
		case ae.Status == 409 && ae.Code == "not_mutating":
			return SitPermitNotMutating
		case ae.Status == 429:
			return SitPermit429
		case ae.Status >= 500 && ae.Status <= 599:
			return SitPermitTransient
		}
		return SitUnmapped
	}
	if isTransport(err) {
		return SitPermitTransient
	}
	return SitUnmapped
}

// ClassifyResult maps a SubmitResult error; nil is SitResultReplayed-or-done
// and is handled by the caller from the ack.
func ClassifyResult(err error) Situation {
	if ae, ok := apiErr(err); ok {
		if s, ok := common(ae); ok {
			return s
		}
		switch {
		case ae.Status == 409 && ae.Code == "already_completed":
			return SitResultAlreadyDone
		case ae.Status == 409 && ae.Code == "result_conflict":
			return SitResultConflict
		case (ae.Status == 400 && ae.Code == "invalid_document") ||
			(ae.Status == 409 && ae.Code == "binding_mismatch") ||
			(ae.Status == 422 && ae.Code == "result_inconsistent"):
			return SitResultBug
		case ae.Status == 429 || (ae.Status >= 500 && ae.Status <= 599):
			return SitResultRetry
		}
		return SitUnmapped
	}
	if isTransport(err) {
		return SitResultRetry
	}
	return SitUnmapped
}

// ClassifyClaim maps a Claim error: 429 backs off at least Retry-After; 404,
// 401 and 403 (bridge disabled or provider refused) keep readiness failing.
func ClassifyClaim(err error) (s Situation, notReady bool) {
	if ae, ok := apiErr(err); ok {
		switch ae.Status {
		case 429:
			return SitClaim429, false
		case 401, 403, 404:
			return SitUnauthorized, true
		}
	}
	return SitUnmapped, false
}
