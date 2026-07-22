// Package agentworker is the production (Option C) transport for the
// communication agent: a headless worker that long-polls
// /api/agent/v1/events for the next due job and invokes `claude -p` with a
// restricted MCP tool surface that proxies 1:1 onto the same JSON API a
// human bridge daemon or the experimental Channels adapter (A-PR8b) would
// use. See mctlhq/mctl-telegram#298 and the transport decision in the
// Communication Agent plan.
package agentworker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// APIError is returned for any non-2xx response from the agent API. Callers
// that need to distinguish e.g. 409 (job already completed under a stale
// attempt) from a real failure should check StatusCode rather than string-
// matching Error().
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("agent api: %d: %s", e.StatusCode, e.Message)
}

// Client is a thin HTTP client for /api/agent/v1, authenticating every
// request with a long-lived worker bearer token (see agentapi's
// NewAgentTokenHandler doc comment — this is a deployment-provisioned
// credential, not something the worker mints itself).
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient builds a Client. baseURL is the full /api/agent/v1 root (e.g.
// "https://labs-mctl-telegram.labs.svc:8080/api/agent/v1"); hc may be nil to
// use http.DefaultClient.
func NewClient(baseURL, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{baseURL: baseURL, token: token, http: hc}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errBody)
		msg := errBody.Error
		if msg == "" {
			msg = string(respBody)
		}
		return &APIError{StatusCode: resp.StatusCode, Message: msg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// JobEnvelope mirrors agentapi's jobEnvelope wire shape.
type JobEnvelope struct {
	JobID          int64  `json:"job_id"`
	EventID        string `json:"event_id"`
	ConversationID int64  `json:"conversation_id,omitempty"`
	Attempt        int    `json:"attempt"`
	Deadline       string `json:"deadline"`
}

// ParsedDeadline parses Deadline, falling back to a short fixed window from
// now if the field is missing or malformed rather than erroring — a bad
// deadline should degrade the worker's local timeout, not abort the job.
func (j JobEnvelope) ParsedDeadline(fallback time.Duration) time.Time {
	if t, err := time.Parse(time.RFC3339, j.Deadline); err == nil {
		return t
	}
	return time.Now().Add(fallback)
}

// pollEventsDeadline bounds one PollEvents call. The server itself holds
// the connection for up to ~20s (agentapi's defaultLongPollTimeout) before
// responding with an empty result — this is deliberately longer than that,
// not shorter, so it never races the server's own timeout. Without it, a
// network partition that accepts the TCP connection but never sends bytes
// would hang the call (and the worker's whole poll loop) indefinitely: the
// caller's own lifetime context (signal.NotifyContext with no deadline, see
// cmd/agent-worker) never expires on its own, and http.DefaultClient has no
// request timeout either.
const pollEventsDeadline = 30 * time.Second

// PollEvents is GET /events?limit=N — a long-poll claim of due jobs.
func (c *Client) PollEvents(ctx context.Context, limit int) ([]JobEnvelope, error) {
	if limit <= 0 {
		limit = 1
	}
	ctx, cancel := context.WithTimeout(ctx, pollEventsDeadline)
	defer cancel()
	var out struct {
		Jobs []JobEnvelope `json:"jobs"`
	}
	path := "/events?limit=" + strconv.Itoa(limit)
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Jobs, nil
}

// EventDTO mirrors agentapi's eventResponse.
type EventDTO struct {
	EventID    string `json:"event_id"`
	Kind       string `json:"kind"`
	ChatTGID   int64  `json:"chat_tg_id"`
	SenderTGID int64  `json:"sender_tg_id"`
	MessageID  int64  `json:"message_id"`
	Body       string `json:"body"`
	Meta       string `json:"meta"`
	CreatedAt  string `json:"created_at"`
}

func (c *Client) GetEvent(ctx context.Context, eventID string) (*EventDTO, error) {
	var out EventDTO
	if err := c.do(ctx, http.MethodGet, "/event/"+url.PathEscape(eventID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type ConversationDTO struct {
	ID              int64  `json:"id"`
	PeerTGID        int64  `json:"peer_tg_id"`
	PeerUsername    string `json:"peer_username,omitempty"`
	PeerDisplayName string `json:"peer_display_name,omitempty"`
	State           string `json:"state"`
	AutonomousTurns int    `json:"autonomous_turns"`
}

type ConversationMessageDTO struct {
	Direction string `json:"direction"`
	Body      string `json:"body"`
	CreatedAt string `json:"created_at"`
}

type LeadDTO struct {
	ID            int64  `json:"id"`
	Company       string `json:"company,omitempty"`
	Role          string `json:"role,omitempty"`
	RecruiterName string `json:"recruiter_name,omitempty"`
	RecruiterTGID int64  `json:"recruiter_tg_id,omitempty"`
	Compensation  string `json:"compensation,omitempty"`
	Status        string `json:"status"`
	Detail        string `json:"detail"`
}

type ConversationContext struct {
	Conversation ConversationDTO          `json:"conversation"`
	Messages     []ConversationMessageDTO `json:"messages"`
	Lead         *LeadDTO                 `json:"lead"`
}

func (c *Client) GetConversationContext(ctx context.Context, conversationID int64, limit int) (*ConversationContext, error) {
	path := "/conversations/" + strconv.FormatInt(conversationID, 10) + "/context"
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	var out ConversationContext
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetRecruiterProfile returns the owner's public profile as a raw map — the
// field set is caller-defined (internal/agent/profile, see A-PR7) and not
// something this transport-layer client should assume a fixed shape for.
func (c *Client) GetRecruiterProfile(ctx context.Context, peerTGID int64) (map[string]any, error) {
	var out map[string]any
	if err := c.do(ctx, http.MethodGet, "/recruiters/"+strconv.FormatInt(peerTGID, 10), nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetLead(ctx context.Context, leadID int64) (*LeadDTO, error) {
	var out LeadDTO
	if err := c.do(ctx, http.MethodGet, "/leads/"+strconv.FormatInt(leadID, 10), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type PolicyDTO struct {
	Mode               string `json:"mode"`
	AutopilotPaused    bool   `json:"autopilot_paused"`
	MaxAutonomousTurns int    `json:"max_autonomous_turns"`
	MaxMsgsPerMinute   int    `json:"max_msgs_per_minute"`
	MaxReplyChars      int    `json:"max_reply_chars"`
	IntentAllowlist    string `json:"intent_allowlist"`
	GlobalKill         bool   `json:"global_kill"`
}

func (c *Client) GetPolicy(ctx context.Context) (*PolicyDTO, error) {
	var out PolicyDTO
	if err := c.do(ctx, http.MethodGet, "/policy", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type ActionResult struct {
	ActionID     int64    `json:"action_id"`
	Decision     string   `json:"decision"`
	Reasons      []string `json:"reasons,omitempty"`
	Status       string   `json:"status,omitempty"`
	ApprovalCode string   `json:"approval_code,omitempty"`
}

// ProposeReply calls POST /actions/propose_reply. Deliberately no peer
// parameter (see agentapi.handleProposeReply's doc comment) — conversationID
// pins the send target server-side.
func (c *Client) ProposeReply(ctx context.Context, conversationID, jobID int64, intent, text string) (*ActionResult, error) {
	req := map[string]any{
		"conversation_id": conversationID,
		"intent":          intent,
		"text":            text,
	}
	if jobID != 0 {
		req["job_id"] = jobID
	}
	var out ActionResult
	if err := c.do(ctx, http.MethodPost, "/actions/propose_reply", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type SaveLeadRequest struct {
	ConversationID int64
	JobID          int64
	Company        string
	Role           string
	RecruiterName  string
	RecruiterTGID  int64
	Compensation   string
	Status         string
	Detail         string
}

func (c *Client) SaveLead(ctx context.Context, req SaveLeadRequest) (int64, error) {
	body := map[string]any{
		"conversation_id": req.ConversationID,
		"company":         req.Company,
		"role":            req.Role,
		"recruiter_name":  req.RecruiterName,
		"recruiter_tg_id": req.RecruiterTGID,
		"compensation":    req.Compensation,
		"status":          req.Status,
		"detail":          req.Detail,
	}
	if req.JobID != 0 {
		body["job_id"] = req.JobID
	}
	var out struct {
		LeadID int64 `json:"lead_id"`
	}
	if err := c.do(ctx, http.MethodPost, "/leads", body, &out); err != nil {
		return 0, err
	}
	return out.LeadID, nil
}

type OwnerFacingResult struct {
	ActionID       int64    `json:"action_id"`
	NotificationID int64    `json:"notification_id,omitempty"`
	Decision       string   `json:"decision,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
}

func (c *Client) ownerFacing(ctx context.Context, path string, conversationID, jobID int64, intent, text string) (*OwnerFacingResult, error) {
	body := map[string]any{"text": text}
	if conversationID != 0 {
		body["conversation_id"] = conversationID
	}
	if jobID != 0 {
		body["job_id"] = jobID
	}
	if intent != "" {
		body["intent"] = intent
	}
	var out OwnerFacingResult
	if err := c.do(ctx, http.MethodPost, path, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) RequestOwnerApproval(ctx context.Context, conversationID, jobID int64, intent, text string) (*OwnerFacingResult, error) {
	return c.ownerFacing(ctx, "/actions/request_owner_approval", conversationID, jobID, intent, text)
}

func (c *Client) SendOwnerSummary(ctx context.Context, conversationID, jobID int64, intent, text string) (*OwnerFacingResult, error) {
	return c.ownerFacing(ctx, "/notify/summary", conversationID, jobID, intent, text)
}

func (c *Client) PauseAutopilot(ctx context.Context, paused bool) (bool, error) {
	var out struct {
		AutopilotPaused bool `json:"autopilot_paused"`
	}
	if err := c.do(ctx, http.MethodPost, "/autopilot/pause", map[string]any{"paused": paused}, &out); err != nil {
		return false, err
	}
	return out.AutopilotPaused, nil
}

// CompleteJob calls POST /jobs/{id}/complete. status must be "completed",
// "failed", or "ignored" (see db.JobCompleted/JobFailed/JobIgnored). A
// "completed" call fails server-side with 409 unless a durable result
// (an agent_actions row or job_lead) was already persisted for this job —
// see agentapi.handleJobComplete's doc comment. That check is the actual
// crash-safety guarantee; this client makes no attempt to duplicate it
// locally.
func (c *Client) CompleteJob(ctx context.Context, jobID int64, attempt int, status, note string) error {
	body := map[string]any{"attempt": attempt, "status": status, "note": note}
	return c.do(ctx, http.MethodPost, "/jobs/"+strconv.FormatInt(jobID, 10)+"/complete", body, nil)
}
