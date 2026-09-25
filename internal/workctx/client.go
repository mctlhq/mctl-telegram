// Package workctx is the outbound mctl-api work-context client (issue-443):
// the surface adapter that lets Telegram bind a Saved Messages thread to a
// canonical mctl-api WorkItem, record intent, and request execution — never
// declare it. Modelled directly on internal/agentworker/client.go, but
// talking to the platform (api.mctl.ai) instead of this repo's own
// /api/agent/v1.
//
// Every method here maps one-to-one onto a route on mctl-api's surface
// relay allowlist (docs/contracts/mctl-api-work-context.md) and nothing
// else. No method builds a path containing "executions", "snapshot",
// "snapshots", "events" or "approvals"; none calls the bare work-item list
// route, PATCH, or POST .../resume. Request structs never carry an
// actor-shaped field (actor, actor_subject, created_by, principal,
// on_behalf_of) or an execution-identity field (engine, engine_ref,
// execution_id) — TestNoActorField and TestRouteAllowlist in this package
// assert both by reflection.
package workctx

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// relayTimeout bounds every outbound mctl-api call from this package. The
// inbound context here carries no deadline of its own (HandleSavedText runs
// inline under listener.persist's RunFor), so without this a hung
// api.mctl.ai connection stalls that account's update processing
// indefinitely — see internal/agentworker/client.go's pollEventsDeadline for
// the same hazard on the sibling client.
const relayTimeout = 20 * time.Second

// maxResponseBytes caps how much of a response body relay reads. Every
// workitem/v1 envelope is a few KiB at most; the cap keeps a misbehaving
// upstream from making the listener goroutine allocate without bound, and
// also bounds the error-body text that can land in APIError.Message. A body
// over the cap is rejected as ErrIncompatibleSchema.
const maxResponseBytes = 1 << 20

// Client is a thin HTTP client for mctl-api's surface-relay routes,
// authenticating every request as the surface:telegram principal and
// relaying the acting human via X-MCTL-Surface-Actor.
type Client struct {
	baseURL string // MCTL_API_BASE_URL, default https://api.mctl.ai
	token   string // MCTL_SURFACE_TELEGRAM_TOKEN
	tenant  string // MCTL_WORK_ITEM_TENANT
	http    *http.Client

	// Metrics is optional (nil-safe via metrics.Registry's Count* methods) so
	// existing callers/tests that construct a Client directly keep compiling.
	Metrics *metrics.Registry
}

// NewClient builds a Client. hc may be nil to use http.DefaultClient. A
// trailing slash on baseURL is trimmed, matching agentworker.NewClient's
// rationale: every path built in this package already starts with "/".
func NewClient(baseURL, token, tenant string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, tenant: tenant, http: hc}
}

// relay performs one request as surface:telegram on behalf of actorTGID. It
// sets exactly three headers: Authorization (the surface bearer token),
// X-MCTL-Surface-Actor (digits-only, actorTGID) and, when idemKey is
// non-empty, Idempotency-Key. No other header is ever set by this package —
// in particular, nothing here can carry an actor subject, since the only
// actor-identifying value it ever sends is this one numeric header.
func (c *Client) relay(ctx context.Context, route, method, path string, actorTGID int64, idemKey string, body, out any) (err error) {
	defer func() {
		outcome := "ok"
		if err != nil {
			outcome = "error"
		}
		c.Metrics.CountWorkContextRequest(route, outcome)
	}()
	if actorTGID <= 0 {
		return fmt.Errorf("workctx: relay actor telegram id must be positive, got %d", actorTGID)
	}
	ctx, cancel := context.WithTimeout(ctx, relayTimeout)
	defer cancel()
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("workctx: marshal request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("workctx: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-MCTL-Surface-Actor", strconv.FormatInt(actorTGID, 10))
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("workctx: do request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("workctx: read response: %w", err)
	}
	if len(respBody) > maxResponseBytes {
		return fmt.Errorf("%w: response body exceeds %d bytes", ErrIncompatibleSchema, maxResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(respBody, &errBody)
		code := errBody.Error
		msg := errBody.Message
		if msg == "" {
			msg = string(respBody)
		}
		return wrapAPIError(resp.StatusCode, code, msg)
	}
	if out == nil {
		return nil
	}
	// An empty 2xx body is NOT treated as success here: out is left at its
	// zero value, which then fails the schemaVersion/validate checks below
	// instead of silently reporting success with a blank result (see
	// validatedEnvelope's doc on the poison-pill hazard this closes).
	if len(respBody) == 0 {
		if _, ok := out.(emptyBodyTolerant); ok {
			return nil
		}
	} else {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("workctx: decode response: %w", err)
		}
	}
	if env, ok := out.(versionedEnvelope); ok {
		if env.schemaVersion() != SchemaVersion {
			return fmt.Errorf("%w: got %q, want %q", ErrIncompatibleSchema, env.schemaVersion(), SchemaVersion)
		}
	}
	if v, ok := out.(validatedEnvelope); ok {
		if err := v.validate(); err != nil {
			return err
		}
	}
	return nil
}

// RedeemLink calls POST /api/v1/surface-identities/redeem to complete the
// owner's one-time /mctl link <code> flow. The code is passed exactly once
// and never logged or echoed by this package.
func (c *Client) RedeemLink(ctx context.Context, actorTGID int64, code string) error {
	body := map[string]string{"code": code}
	return c.relay(ctx, "redeem_link", http.MethodPost, "/api/v1/surface-identities/redeem", actorTGID, "", body, nil)
}

// CreateRequest is the body for CreateWorkItem. ExternalKey is the only
// caller-settable field — no actor-shaped field, and no origin_surface
// setter: relay always hardcodes "telegram" and the configured tenant.
type CreateRequest struct {
	ExternalKey    string
	IdempotencyKey string
}

// CreateWorkItem calls POST /api/v1/work-items with origin_surface forced
// to "telegram" and tenant forced to the client's configured
// MCTL_WORK_ITEM_TENANT. Title is derived from ExternalKey (the normalised
// issue URL), never from Telegram message content — the pilot never
// guesses a runnable target. A 200 response (mctl-api's open-work dedupe on
// external_key) and a 201 (freshly created) are both success; the caller
// distinguishes by comparing the returned WorkItem.ID against any existing
// binding, not by status code.
func (c *Client) CreateWorkItem(ctx context.Context, actorTGID int64, r CreateRequest) (*ItemView, error) {
	wireBody := map[string]any{
		"tenant":         c.tenant,
		"title":          r.ExternalKey,
		"origin_surface": "telegram",
		"external_key":   r.ExternalKey,
	}
	if r.IdempotencyKey != "" {
		wireBody["idempotency_key"] = r.IdempotencyKey
	}
	var out ItemView
	if err := c.relay(ctx, "create_work_item", http.MethodPost, "/api/v1/work-items", actorTGID, r.IdempotencyKey, wireBody, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetWorkItem calls GET /api/v1/work-items/{id}.
func (c *Client) GetWorkItem(ctx context.Context, actorTGID int64, id string) (*ItemView, error) {
	var out ItemView
	path := "/api/v1/work-items/" + url.PathEscape(id)
	if err := c.relay(ctx, "get_work_item", http.MethodGet, path, actorTGID, "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// IntentRequest is the body for AppendIntent. Text is the owner's /mctl
// work note <text> content — the only user content this package ever
// forwards, and never mirrored anywhere else (no transcript, no title).
type IntentRequest struct {
	Text           string
	IdempotencyKey string
}

// AppendIntent calls POST /api/v1/work-items/{id}/intents.
func (c *Client) AppendIntent(ctx context.Context, actorTGID int64, id string, r IntentRequest) error {
	wireBody := map[string]any{"text": r.Text, "surface": "telegram"}
	if r.IdempotencyKey != "" {
		wireBody["idempotency_key"] = r.IdempotencyKey
	}
	path := "/api/v1/work-items/" + url.PathEscape(id) + "/intents"
	return c.relay(ctx, "append_intent", http.MethodPost, path, actorTGID, r.IdempotencyKey, wireBody, nil)
}

// ExecutionRequest is the body for RequestExecution. There is deliberately
// no engine, engine_ref or execution_id field: a surface requests
// execution, it never declares execution identity (mctl-api#368,
// mctl-agents#461) — the platform supplies all three.
type ExecutionRequest struct {
	// Kind is ExecutionKindStart or ExecutionKindResume.
	Kind                   string
	ExpectedStateVersion   int64
	ResumedFromExecutionID string
	IntentID               string
	IdempotencyKey         string
}

// RequestExecution calls POST /api/v1/work-items/{id}/execution-requests.
func (c *Client) RequestExecution(ctx context.Context, actorTGID int64, id string, r ExecutionRequest) (*ExecutionRequestView, error) {
	wireBody := map[string]any{
		"kind":                   r.Kind,
		"expected_state_version": r.ExpectedStateVersion,
		"surface":                "telegram",
	}
	if r.ResumedFromExecutionID != "" {
		wireBody["resumed_from_execution_id"] = r.ResumedFromExecutionID
	}
	if r.IntentID != "" {
		wireBody["intent_id"] = r.IntentID
	}
	if r.IdempotencyKey != "" {
		wireBody["idempotency_key"] = r.IdempotencyKey
	}
	var out ExecutionRequestView
	path := "/api/v1/work-items/" + url.PathEscape(id) + "/execution-requests"
	if err := c.relay(ctx, "request_execution", http.MethodPost, path, actorTGID, r.IdempotencyKey, wireBody, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetExecutionRequest calls
// GET /api/v1/work-items/{id}/execution-requests/{request_id}.
func (c *Client) GetExecutionRequest(ctx context.Context, actorTGID int64, id, requestID string) (*ExecutionRequestView, error) {
	var out ExecutionRequestView
	path := "/api/v1/work-items/" + url.PathEscape(id) + "/execution-requests/" + url.PathEscape(requestID)
	if err := c.relay(ctx, "get_execution_request", http.MethodGet, path, actorTGID, "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListExecutionRequests calls
// GET /api/v1/work-items/{id}/execution-requests (no id) — newest first per
// docs/contracts/mctl-api-work-context.md. Used when a binding has no
// recorded last_request_id (an older or lost row).
func (c *Client) ListExecutionRequests(ctx context.Context, actorTGID int64, id string) ([]ExecutionRequestView, error) {
	var out executionRequestListEnvelope
	path := "/api/v1/work-items/" + url.PathEscape(id) + "/execution-requests"
	if err := c.relay(ctx, "list_execution_requests", http.MethodGet, path, actorTGID, "", nil, &out); err != nil {
		return nil, err
	}
	return out.ExecutionRequests, nil
}

// SurfaceRefRequest is the body for AddSurfaceRef — correlation metadata
// only (chat + root message id), never identity. ChatTGID and
// RootTGMessageID are folded into the wire external_id; there is no
// caller-settable actor_external_id, since this package never sends an
// actor-shaped value anywhere.
type SurfaceRefRequest struct {
	ChatTGID        int64
	RootTGMessageID int64
}

// AddSurfaceRef calls POST /api/v1/work-items/{id}/surface-refs to register
// the Telegram thread as correlation metadata on the work item.
func (c *Client) AddSurfaceRef(ctx context.Context, actorTGID int64, id string, r SurfaceRefRequest) error {
	externalID := fmt.Sprintf("telegram:%d:%d", r.ChatTGID, r.RootTGMessageID)
	wireBody := map[string]any{"external_id": externalID}
	path := "/api/v1/work-items/" + url.PathEscape(id) + "/surface-refs"
	return c.relay(ctx, "add_surface_ref", http.MethodPost, path, actorTGID, "", wireBody, nil)
}
