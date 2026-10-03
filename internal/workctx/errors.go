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
	// ErrRequestNotActive means a human-input request is no longer open for
	// an answer: expired, cancelled, or already resolved elsewhere (409/410).
	ErrRequestNotActive = errors.New("workctx: human-input request is no longer active")
	// ErrRequestSuperseded means the request_hash the answer named is stale:
	// a newer version of the request replaced it (409 request_superseded /
	// request_hash_mismatch).
	ErrRequestSuperseded = errors.New("workctx: human-input request was superseded")
	// ErrAlreadyAnswered means the same actor already answered this request
	// (409 already_answered).
	ErrAlreadyAnswered = errors.New("workctx: human-input request already answered")
	// ErrNotEligible means the platform refused the actor as an eligible
	// responder (403 not_eligible). It is rendered neutrally: eligibility
	// policy is mctl-api's and is never revealed to the surface user.
	ErrNotEligible = errors.New("workctx: actor is not eligible to answer")
	// ErrAnswerInvalid means the platform rejected the shape of the answer
	// (400/422).
	ErrAnswerInvalid = errors.New("workctx: human-input answer was rejected as invalid")
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
	// Human-input relay (issue-571), docs/contracts/mctl-api-human-input.md.
	"request_not_active":    ErrRequestNotActive,
	"request_expired":       ErrRequestNotActive,
	"request_cancelled":     ErrRequestNotActive,
	"request_superseded":    ErrRequestSuperseded,
	"request_hash_mismatch": ErrRequestSuperseded,
	"already_answered":      ErrAlreadyAnswered,
	"not_eligible":          ErrNotEligible,
	"answer_invalid":        ErrAnswerInvalid,
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
	// CorrelationID is mctl-api's X-Request-ID response header, kept for
	// log correlation only. Empty when the response carried none.
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
