package workctx

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Human-input request kinds this adapter can deliver and answer. Any other
// kind a future mctl-api revision adds is not rendered or answered here.
const (
	HumanInputKindSingleChoice = "single_choice"
	HumanInputKindFreeText     = "free_text"
)

// Human-input request states as reported by mctl-api.
const (
	HumanInputStatePending    = "pending"
	HumanInputStateAnswered   = "answered"
	HumanInputStateRejected   = "rejected"
	HumanInputStateExpired    = "expired"
	HumanInputStateCancelled  = "cancelled"
	HumanInputStateSuperseded = "superseded"
)

// HumanInputOption is one answer option of a single_choice request.
type HumanInputOption struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// RequestView is the safe-field human-input request DTO
// (docs/contracts/mctl-api-human-input.md). Only fields the surface may show
// are decoded; anything else mctl-api sends (prompt, reasoning, logs, ...) is
// ignored by construction because it has no field here.
type RequestView struct {
	SchemaVersionField string             `json:"schema_version"`
	RequestID          string             `json:"request_id"`
	RequestHash        string             `json:"request_hash"`
	Version            int64              `json:"version"`
	Kind               string             `json:"kind"`
	State              string             `json:"state"`
	Question           string             `json:"question"`
	Why                string             `json:"why,omitempty"`
	Options            []HumanInputOption `json:"options,omitempty"`
	Deadline           string             `json:"deadline,omitempty"`
	WorkItemID         string             `json:"work_item_id,omitempty"`
	WorkRef            string             `json:"work_ref,omitempty"`
	Links              []string           `json:"links,omitempty"`
	MaxLength          int                `json:"max_length,omitempty"`

	// CorrelationID is mctl-api's X-Request-ID; never decoded from the body.
	CorrelationID string `json:"-"`
}

func (v *RequestView) schemaVersion() string      { return v.SchemaVersionField }
func (v *RequestView) setCorrelationID(id string) { v.CorrelationID = id }

func (v *RequestView) validate() error {
	if v.RequestID == "" || v.RequestHash == "" {
		return fmt.Errorf("%w: human-input request missing request_id or request_hash", ErrIncompatibleSchema)
	}
	return nil
}

// humanInputListEnvelope is the wire shape of GET /api/v1/human-input.
type humanInputListEnvelope struct {
	SchemaVersionField string        `json:"schema_version"`
	Requests           []RequestView `json:"requests"`
	CorrelationID      string        `json:"-"`
}

func (v *humanInputListEnvelope) schemaVersion() string      { return v.SchemaVersionField }
func (v *humanInputListEnvelope) setCorrelationID(id string) { v.CorrelationID = id }
func (v *humanInputListEnvelope) emptyBodyMeansNone()        {}

func (v *humanInputListEnvelope) validate() error {
	for i := range v.Requests {
		if err := v.Requests[i].validate(); err != nil {
			return err
		}
	}
	return nil
}

// ResponseRequest is the body of RespondHumanInput. There is no actor field
// and no approval field: the platform derives the human from the relay header
// and a clarification answer can never carry an approval.
type ResponseRequest struct {
	RequestHash string `json:"request_hash"`
	Kind        string `json:"kind"`
	Value       string `json:"value"`
}

// ResponseView is the platform's answer to an accepted response.
type ResponseView struct {
	SchemaVersionField string `json:"schema_version"`
	RequestID          string `json:"request_id"`
	State              string `json:"state"`
	CorrelationID      string `json:"-"`
}

func (v *ResponseView) schemaVersion() string      { return v.SchemaVersionField }
func (v *ResponseView) setCorrelationID(id string) { v.CorrelationID = id }

func (v *ResponseView) validate() error {
	if v.RequestID == "" || v.State == "" {
		return fmt.Errorf("%w: human-input response missing request_id or state", ErrIncompatibleSchema)
	}
	return nil
}

// ListHumanInput calls GET /api/v1/human-input as the actor and returns the
// requests mctl-api lists as pending for that human.
func (c *Client) ListHumanInput(ctx context.Context, actorTGID int64) ([]RequestView, error) {
	var out humanInputListEnvelope
	if err := c.relay(ctx, "list_human_input", http.MethodGet, "/api/v1/human-input", actorTGID, "", nil, &out); err != nil {
		return nil, err
	}
	return out.Requests, nil
}

// GetHumanInput calls GET /api/v1/human-input/{request_id}: the canonical
// state of one request.
func (c *Client) GetHumanInput(ctx context.Context, actorTGID int64, requestID string) (*RequestView, error) {
	var out RequestView
	path := "/api/v1/human-input/" + url.PathEscape(requestID)
	if err := c.relay(ctx, "get_human_input", http.MethodGet, path, actorTGID, "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RespondHumanInput calls POST /api/v1/human-input/{request_id}/response.
// idemKey is sent as Idempotency-Key so a redelivered command is deduped by
// mctl-api.
func (c *Client) RespondHumanInput(ctx context.Context, actorTGID int64, requestID string, r ResponseRequest, idemKey string) (*ResponseView, error) {
	var out ResponseView
	path := "/api/v1/human-input/" + url.PathEscape(requestID) + "/response"
	if err := c.relay(ctx, "respond_human_input", http.MethodPost, path, actorTGID, idemKey, r, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
