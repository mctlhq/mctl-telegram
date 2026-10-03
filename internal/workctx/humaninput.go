package workctx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
)

// Human-input response types this adapter can deliver and answer
// (docs/contracts/mctl-api-human-input.md). mctl-api also knows
// multi_choice and structured; those are not rendered or answered here.
const (
	HumanInputTypeSingleChoice = "single_choice"
	HumanInputTypeFreeText     = "free_text"
)

// Human-input read-model states as mctl-api reports them on GET
// /api/v1/human-input[/{request_id}]. "pending" is the only state a response
// can be accepted in. "unknown" means mctl-api could not determine the state
// (the owning workflow did not answer): it is never read as terminal.
const (
	HumanInputStatePending    = "pending"
	HumanInputStateExpired    = "expired"
	HumanInputStateTimedOut   = "timed_out"
	HumanInputStateResolved   = "resolved"
	HumanInputStateNotPending = "not_pending"
	HumanInputStateUnknown    = "unknown"
)

// Response statuses of POST /api/v1/human-input/{request_id}/response.
// accepted (200) means the workflow took the answer. pending_delivery (202)
// means mctl-api recorded and signalled it, but the workflow has not
// confirmed it yet: it is NOT an accepted answer. rejected comes with a
// non-2xx status and is turned into a typed error by relay.
const (
	HumanInputStatusAccepted        = "accepted"
	HumanInputStatusPendingDelivery = "pending_delivery"
	HumanInputStatusRejected        = "rejected"
)

// routeRespondHumanInput is the relay route name of the response call, the
// only route whose rejections are {status: rejected, state} result objects.
const routeRespondHumanInput = "respond_human_input"

// humanInputIDPattern is mctl-api's request_id shape. A request_id is put
// into a URL path, so anything else is refused as an incompatible response
// rather than relayed.
var humanInputIDPattern = regexp.MustCompile(`^hir-[0-9a-f]{16}$`)

// ValidHumanInputRequestID reports whether id has mctl-api's request_id shape.
func ValidHumanInputRequestID(id string) bool { return humanInputIDPattern.MatchString(id) }

// RequestView is the human-input read model mctl-api returns
// (humanInputView in mctl-api internal/api/handlers_human_input.go). Only
// fields this surface uses are decoded. Everything else mctl-api sends is
// ignored by construction because it has no field here: workflow_id, agent,
// audience and eligible_actors (the latter is never sent to a relayed human
// anyway), and anything a future revision might add (prompt, reasoning,
// logs, ...).
type RequestView struct {
	RequestID      string   `json:"request_id"`
	RequestHash    string   `json:"request_hash"`
	RequestVersion int64    `json:"request_version"`
	Round          int64    `json:"round"`
	WorkItemID     string   `json:"work_item_id"`
	Service        string   `json:"service"`
	Proposal       string   `json:"proposal"`
	Question       string   `json:"question"`
	Reason         string   `json:"reason"`
	ResponseType   string   `json:"response_type"`
	Options        []string `json:"options,omitempty"`
	ContextRefs    []string `json:"context_refs"`
	// CanRespond is a pointer so an absent field is a malformed read
	// (validate refuses it), never an implicit false that would silently
	// stop every delivery.
	CanRespond  *bool  `json:"can_respond"`
	CreatedAt   string `json:"created_at"`
	ExpiresAt   string `json:"expires_at"`
	State       string `json:"state"`
	StateDetail string `json:"state_detail,omitempty"`

	// WorkRef is a display ref ("owner/repo#n") the adapter derives from its
	// own work_item_bindings row. Never decoded from mctl-api.
	WorkRef string `json:"-"`
	// CorrelationID identifies the relay call that returned this view (see
	// Client.relay). Never decoded from the body.
	CorrelationID string `json:"-"`
}

func (v *RequestView) setCorrelationID(id string) { v.CorrelationID = id }

// validate refuses a view this adapter cannot safely correlate: a missing or
// malformed request_id, a missing request_hash or a missing state. A view
// failing it is a malformed response, never "no request".
func (v *RequestView) validate() error {
	if !ValidHumanInputRequestID(v.RequestID) {
		return fmt.Errorf("%w: human-input request_id missing or malformed", ErrIncompatibleSchema)
	}
	if v.RequestHash == "" || v.State == "" {
		return fmt.Errorf("%w: human-input request missing request_hash or state", ErrIncompatibleSchema)
	}
	if v.CanRespond == nil {
		return fmt.Errorf("%w: human-input request missing can_respond", ErrIncompatibleSchema)
	}
	return nil
}

// Respondable reports can_respond; false when absent (validate refuses an
// absent field on every decoded view, so this only matters for hand-built
// values).
func (v *RequestView) Respondable() bool { return v.CanRespond != nil && *v.CanRespond }

// humanInputListEnvelope is the wire shape of GET /api/v1/human-input:
// {"items": [...], "count": N}. It carries no schema_version. count is
// required and must equal len(items): a body without it, or a short list, is
// a malformed read and must not be mistaken for "nothing is pending".
type humanInputListEnvelope struct {
	Items         []RequestView `json:"items"`
	Count         *int          `json:"count"`
	CorrelationID string        `json:"-"`
}

func (v *humanInputListEnvelope) setCorrelationID(id string) { v.CorrelationID = id }

func (v *humanInputListEnvelope) validate() error {
	if v.Count == nil {
		return fmt.Errorf("%w: human-input list missing count", ErrIncompatibleSchema)
	}
	if *v.Count != len(v.Items) {
		return fmt.Errorf("%w: human-input list count %d does not match %d items", ErrIncompatibleSchema, *v.Count, len(v.Items))
	}
	for i := range v.Items {
		if err := v.Items[i].validate(); err != nil {
			return err
		}
	}
	return nil
}

// ResponseRequest is what a caller supplies for RespondHumanInput. There is
// no actor or respondent field and no approval field: mctl-api derives the
// respondent from the relayed link, and a clarification answer can never
// carry an approval. Value is the answer: the exact option string for
// single_choice, the text for free_text.
type ResponseRequest struct {
	RequestHash string
	Value       string
}

// humanInputResponseWire is the exact body mctl-api decodes with
// DisallowUnknownFields: {request_hash, value, surface}. surface is always
// "telegram" (mctl-api forces a relayed answer's surface to the relaying
// surface and refuses a different claim with 400).
type humanInputResponseWire struct {
	RequestHash string `json:"request_hash"`
	Value       string `json:"value"`
	Surface     string `json:"surface"`
}

// ResponseView is mctl-api's 2xx answer to a response: status accepted (200)
// or pending_delivery (202). respondent is deliberately not decoded (it is
// the human's GitHub login), and detail is decoded only to recognise the
// fixed "already accepted" replay text; neither is ever logged.
type ResponseView struct {
	RequestID     string `json:"request_id"`
	Status        string `json:"status"`
	State         string `json:"state"`
	Detail        string `json:"detail"`
	CorrelationID string `json:"-"`
}

// DetailAlreadyAccepted is mctl-api's detail on a 200 replay of the same
// respondent's identical answer.
const DetailAlreadyAccepted = "already accepted"

func (v *ResponseView) setCorrelationID(id string) { v.CorrelationID = id }

func (v *ResponseView) validate() error {
	if v.RequestID == "" {
		return fmt.Errorf("%w: human-input response missing request_id", ErrIncompatibleSchema)
	}
	switch v.Status {
	case HumanInputStatusAccepted, HumanInputStatusPendingDelivery:
		return nil
	default:
		return fmt.Errorf("%w: human-input response status %q on a 2xx", ErrIncompatibleSchema, v.Status)
	}
}

// ListHumanInput calls GET /api/v1/human-input as the actor and returns the
// requests mctl-api lists as pending for that human. mctl-api answers 503,
// never a short list, when it cannot determine a request's state; that
// arrives here as an error, never as an empty slice.
func (c *Client) ListHumanInput(ctx context.Context, actorTGID int64) ([]RequestView, error) {
	var out humanInputListEnvelope
	if err := c.relay(ctx, "list_human_input", http.MethodGet, "/api/v1/human-input", actorTGID, "", nil, &out); err != nil {
		return nil, err
	}
	for i := range out.Items {
		out.Items[i].CorrelationID = out.CorrelationID
	}
	return out.Items, nil
}

// GetHumanInput calls GET /api/v1/human-input/{request_id}: the canonical
// state of one request, in any state. A request the human may not see is a
// 404 (ErrHumanInputNotFound), not a 403.
func (c *Client) GetHumanInput(ctx context.Context, actorTGID int64, requestID string) (*RequestView, error) {
	if !ValidHumanInputRequestID(requestID) {
		return nil, fmt.Errorf("workctx: malformed human-input request id")
	}
	var out RequestView
	path := "/api/v1/human-input/" + url.PathEscape(requestID)
	if err := c.relay(ctx, "get_human_input", http.MethodGet, path, actorTGID, "", nil, &out); err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound && !isRelayRefusal(err) {
			return nil, fmt.Errorf("%w: %w", ErrHumanInputNotFound, err)
		}
		return nil, err
	}
	return &out, nil
}

// RespondHumanInput calls POST /api/v1/human-input/{request_id}/response.
//
// idemKey is sent as Idempotency-Key. mctl-api at the pinned revision does
// not read that header on this route; deduplication is its delivery ledger,
// keyed on (request_id, respondent, request_hash, value hash): the same
// human resubmitting the same answer gets the same result. The header is
// kept because it is harmless and lets the call be correlated.
//
// A rejection (403/409/422 with status "rejected") is returned as a typed
// error (ErrRequestSuperseded, ErrRequestNotActive, ErrAnswerInvalid,
// ErrNotEligible, ...). A 2xx is returned as a ResponseView whose Status is
// accepted or pending_delivery; only accepted means the workflow took it.
func (c *Client) RespondHumanInput(ctx context.Context, actorTGID int64, requestID string, r ResponseRequest, idemKey string) (*ResponseView, error) {
	if !ValidHumanInputRequestID(requestID) {
		return nil, fmt.Errorf("workctx: malformed human-input request id")
	}
	var out ResponseView
	wire := humanInputResponseWire{RequestHash: r.RequestHash, Value: r.Value, Surface: "telegram"}
	path := "/api/v1/human-input/" + url.PathEscape(requestID) + "/response"
	if err := c.relay(ctx, routeRespondHumanInput, http.MethodPost, path, actorTGID, idemKey, wire, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// isRelayRefusal reports a surface-relay refusal (link_* or relay_required),
// which is never a statement about the request itself.
func isRelayRefusal(err error) bool {
	return errors.Is(err, ErrLinkNotFound) || errors.Is(err, ErrLinkRevoked) ||
		errors.Is(err, ErrLinkExpired) || errors.Is(err, ErrRelayRequired)
}
