package workctx

import (
	"errors"
	"fmt"
)

// Sentinel errors the router renders as owner-facing text, following the
// approverErrText precedent in internal/agent/control/router.go. Each one
// corresponds to a typed error code mctl-api returns on the surface relay
// routes — see docs/contracts/mctl-api-work-context.md.
var (
	// ErrLinkNotFound means the calling Telegram id has no SurfaceIdentityLink
	// yet — the owner has not run the one-time /mctl link flow.
	ErrLinkNotFound = errors.New("workctx: telegram account is not linked")
	// ErrLinkRevoked means a link existed but was revoked by the human.
	ErrLinkRevoked = errors.New("workctx: link was revoked")
	// ErrLinkExpired means the link challenge or link itself expired.
	ErrLinkExpired = errors.New("workctx: link expired")
	// ErrRelayRequired means the call was missing X-MCTL-Surface-Actor on a
	// relay route — a programming defect in this package, never something a
	// caller can retry around.
	ErrRelayRequired = errors.New("workctx: relay header required")
	// ErrChallengeInvalid means the /mctl link <code> code is wrong or
	// already used.
	ErrChallengeInvalid = errors.New("workctx: link code is invalid or already used")
	// ErrLinkConflict means the human already has a link for this surface.
	ErrLinkConflict = errors.New("workctx: link already exists")
	// ErrActorNotAccepted means the request body carried an actor-naming
	// field mctl-api refused. Request structs in this package are built to
	// make this unreachable by construction; seeing it live is a defect.
	ErrActorNotAccepted = errors.New("workctx: request was rejected by the platform (actor_not_accepted)")
	// ErrStateVersionConflict means expected_state_version was stale.
	ErrStateVersionConflict = errors.New("workctx: work item state changed")
	// ErrExternalKeyInUse means another (invisible-to-the-owner) open work
	// item already claims this issue's external_key.
	ErrExternalKeyInUse = errors.New("workctx: issue already has work you cannot access")
	// ErrIncompatibleSchema means a response's schema_version was not
	// workitem/v1 — the response is rejected outright, no state changes.
	ErrIncompatibleSchema = errors.New("workctx: incompatible platform schema version")
	// ErrExecutionRequestOpen means the work item already has an open
	// execution request (409 execution_request_open).
	ErrExecutionRequestOpen = errors.New("workctx: an execution request is already open")
	// ErrExecutionActive means an execution for the work item is already
	// running (409 execution_active).
	ErrExecutionActive = errors.New("workctx: an execution is already active")
	// ErrInvalidTransition means the work item cannot take the requested
	// transition — a terminal item, or a start on an item that already ran
	// (409 invalid_transition).
	ErrInvalidTransition = errors.New("workctx: work item cannot take that transition")
	// ErrRequestNotActive means a human-input request no longer takes an
	// answer: mctl-api rejected the response with state expired, timed_out,
	// not_pending or resolved, or with state answered (another response
	// already holds the request — from another eligible human, or a
	// different value). 409.
	ErrRequestNotActive = errors.New("workctx: human-input request is no longer active")
	// ErrRequestSuperseded means the request_hash the answer named is not
	// the current one (409, state superseded).
	ErrRequestSuperseded = errors.New("workctx: human-input request was superseded")
	// ErrNotEligible means mctl-api refused the relayed human as a
	// respondent (403, state not_eligible). It is rendered neutrally:
	// eligibility policy is mctl-api's and is never revealed to the surface
	// user.
	ErrNotEligible = errors.New("workctx: actor is not eligible to answer")
	// ErrAnswerInvalid means the answer was refused as a value: 422
	// invalid_value (not one of the options, empty text), or 409 with state
	// pending (the workflow refused this payload but still waits, so a
	// corrected answer may be submitted).
	ErrAnswerInvalid = errors.New("workctx: human-input answer was rejected as invalid")
	// ErrHumanInputNotFound means GET /api/v1/human-input/{id} answered 404:
	// the request does not exist, or the human may not see it. mctl-api
	// reports both the same way, by design.
	ErrHumanInputNotFound = errors.New("workctx: human-input request not found")
)

// codeToErr maps mctl-api's typed error codes (the JSON "error" field) onto
// the sentinels above. Codes not in this table are not silently swallowed —
// APIError.Error() still carries the raw code and status for logging, but
// errors.Is against any sentinel here will correctly report false so a
// caller falls through to a generic "rejected by the platform" reply
// instead of misrepresenting an unrecognised code as a known one.
var codeToErr = map[string]error{
	"link_not_found":         ErrLinkNotFound,
	"link_revoked":           ErrLinkRevoked,
	"link_expired":           ErrLinkExpired,
	"relay_required":         ErrRelayRequired,
	"challenge_invalid":      ErrChallengeInvalid,
	"link_conflict":          ErrLinkConflict,
	"actor_not_accepted":     ErrActorNotAccepted,
	"state_version_conflict": ErrStateVersionConflict,
	"external_key_in_use":    ErrExternalKeyInUse,
	"execution_request_open": ErrExecutionRequestOpen,
	"execution_active":       ErrExecutionActive,
	"invalid_transition":     ErrInvalidTransition,
}

// humanInputRejectionToErr maps the state of a human-input response
// rejection ({"status":"rejected","state":...}, mctl-api
// handlers_human_input_response.go) onto the sentinels above. It is applied
// only to bodies carrying status "rejected", so these generic words can never
// be confused with a work-item error code.
var humanInputRejectionToErr = map[string]error{
	"superseded":    ErrRequestSuperseded,
	"invalid_value": ErrAnswerInvalid,
	"not_eligible":  ErrNotEligible,
	"answered":      ErrRequestNotActive,
	"expired":       ErrRequestNotActive,
	"timed_out":     ErrRequestNotActive,
	"not_pending":   ErrRequestNotActive,
	"resolved":      ErrRequestNotActive,
	// The workflow refused this payload while still waiting on the request.
	"pending": ErrAnswerInvalid,
}

// APIError is returned for any non-2xx response from mctl-api that this
// package does not map onto one of the sentinels above. StatusCode and Code
// let a caller branch on machine-readable facts without string-matching
// Error(); Message is mctl-api's free-text detail, kept for logs only — it
// must never reach an owner-facing reply (see /mctl work status's rendering
// rule for unrecognised reasons).
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	// CorrelationID identifies the relay call (see Client.relay): mctl-api's
	// X-Request-ID response header when it sends one, otherwise the id this
	// client sent as X-Request-Id. Kept for log correlation only.
	CorrelationID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("mctl-api: %d %s: %s", e.StatusCode, e.Code, e.Message)
}

// wrapAPIError builds the error a relay call returns for a non-2xx
// response: a known code is wrapped so errors.Is(err, ErrLinkNotFound) (etc)
// works, still carrying the *APIError beneath via errors.Unwrap-compatible
// wrapping; an unknown code surfaces as a bare *APIError.
func wrapAPIError(status int, code, message, correlationID string) error {
	apiErr := &APIError{StatusCode: status, Code: code, Message: message, CorrelationID: correlationID}
	if sentinel, ok := codeToErr[code]; ok {
		// Two %w verbs: errors.Is matches the sentinel and errors.As still
		// reaches the *APIError (status, code, correlation id). The rendered
		// text is unchanged from the single-%w form.
		return fmt.Errorf("%w: %w", sentinel, apiErr)
	}
	return apiErr
}

// wrapHumanInputRejection builds the error for a human-input response
// rejection. Code is the rejection state; Message stays empty on purpose:
// the body's detail can list the question's options and its respondent is
// the human's GitHub login, and neither may reach a log line through
// APIError.Error(). An unrecognised state is a bare *APIError, rendered
// generically by the caller.
func wrapHumanInputRejection(status int, state, correlationID string) error {
	apiErr := &APIError{StatusCode: status, Code: state, CorrelationID: correlationID}
	if sentinel, ok := humanInputRejectionToErr[state]; ok {
		// Two %w verbs: errors.Is matches the sentinel and errors.As still
		// reaches the *APIError (status, code, correlation id). The rendered
		// text is unchanged from the single-%w form.
		return fmt.Errorf("%w: %w", sentinel, apiErr)
	}
	return apiErr
}
