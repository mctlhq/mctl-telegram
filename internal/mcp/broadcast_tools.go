package mcp

// Broadcast operator tools (issue-439). An assistant with the admin:broadcast
// scope can PREPARE a broadcast (a preview recorded as a campaign), inspect
// campaigns and cancel one. There is deliberately no approve or send tool:
// approval is a human act on the web page at /telegram/connect/broadcasts,
// which accepts only a token minted by the browser Telegram login (see
// internal/web/broadcasts.go). Nothing reachable over MCP can release a
// campaign for delivery.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/broadcast"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// BroadcastScope gates every broadcast tool. It is granted by membership in
// BROADCAST_OPERATORS (on top of platform-admin membership), never
// negotiable, and never minted into worker or device credentials.
const BroadcastScope = "admin:broadcast"

// WithBroadcast enables the broadcast tools. approvalURL is the web page a
// human operator approves prepared campaigns on; prepare_broadcast returns
// it so the assistant can hand it over. Without this the tools stay
// registered (so the tool list is stable) and refuse every call.
func (s *Server) WithBroadcast(svc *broadcast.Service, approvalURL string) *Server {
	s.Broadcast = svc
	s.BroadcastApprovalURL = approvalURL
	return s
}

var errBroadcastDisabled = errors.New("broadcasts are not enabled on this server (no BROADCAST_OPERATORS configured)")

// broadcastActor turns an identity that already passed the admin:broadcast
// scope gate into a service actor, refusing when the workflow is disabled or
// the caller is no longer an operator. The scope proves membership at mint
// time only; removing an id from BROADCAST_OPERATORS must cut off a
// still-live token for every tool, reads included.
// The scope check itself stays in each handler as a literal requireScope
// call: portal_allowlist_test derives every tool's upstream gate from exactly
// that call, so hiding it in a helper would make the gate invisible to it.
func (s *Server) broadcastActor(id *auth.Identity) (broadcast.Actor, error) {
	if s.Broadcast == nil || !s.Broadcast.Enabled() {
		return broadcast.Actor{}, errBroadcastDisabled
	}
	if !s.Broadcast.IsOperator(id.TelegramID) {
		return broadcast.Actor{}, broadcast.ErrNotBroadcastAdmin
	}
	surface := "mcp"
	if id.ClientID != "" {
		surface = "mcp:" + id.ClientID
	}
	return broadcast.Actor{UserID: id.UserID, TelegramID: id.TelegramID, Surface: surface}, nil
}

func validCampaignState(st string) bool {
	switch st {
	case db.CampaignPrepared, db.CampaignApproved, db.CampaignSending, db.CampaignCompleted, db.CampaignCancelled, db.CampaignExpired:
		return true
	}
	return false
}

type prepareBroadcastResult struct {
	broadcast.Preview
	ApprovalURL string `json:"approval_url"`
	Note        string `json:"note"`
}

type broadcastSummary struct {
	CampaignID string     `json:"campaign_id"`
	State      string     `json:"state"`
	EndReason  string     `json:"end_reason,omitempty"`
	Category   string     `json:"category"`
	Selector   string     `json:"selector"`
	Text       string     `json:"text"`
	Format     string     `json:"format"`
	Preview    string     `json:"preview_counts"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	// SourceRef names the frozen product-update digest this campaign was
	// prepared from (issue-683); null/omitted for a manual campaign. Read
	// only -- there is no tool that sets it.
	SourceRef *db.CampaignSourceRef `json:"source_ref,omitempty"`
}

type listBroadcastsResult struct {
	Campaigns []broadcastSummary `json:"campaigns"`
	Count     int                `json:"count"`
}

type getBroadcastResult struct {
	Campaign broadcastSummary `json:"campaign"`
	Report   broadcast.Report `json:"report"`
}

type cancelBroadcastResult struct {
	CampaignID string `json:"campaign_id"`
	State      string `json:"state"`
}

func summarize(c db.BroadcastCampaign) broadcastSummary {
	format := c.ContentFormat
	if format == "" {
		format = string(broadcast.FormatPlain)
	}
	return broadcastSummary{
		Format:     format,
		CampaignID: c.ID, State: c.State, EndReason: c.EndReason, Category: c.Category,
		Selector: c.SelectorJSON, Text: c.Content, Preview: c.PreviewCounts,
		CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt, ApprovedAt: c.ApprovedAt,
		SourceRef: c.SourceRef,
	}
}

// formatArg reads the optional message format strictly: absent or null means
// plain, but a present value of the wrong type or an unknown name is an error
// rather than a silent fall back to plain.
func formatArg(args map[string]any, key string) (broadcast.Format, error) {
	raw, ok := args[key]
	if !ok || raw == nil {
		return broadcast.FormatPlain, nil
	}
	str, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string (\"plain\" or \"html\")", key)
	}
	return broadcast.ParseFormat(str)
}

func stringListArg(args map[string]any, key string) ([]string, error) {
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array of strings", key)
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		sv, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s must be an array of strings", key)
		}
		out = append(out, sv)
	}
	return out, nil
}

// telegramIDListArg reads an optional array of whole, positive numbers. A
// non-array, a non-integer or a non-numeric element is an error, never a
// silently shorter list: dropping an id (or the whole list) would widen the audience relative to
// what the operator typed.
func telegramIDListArg(args map[string]any, key string) ([]int64, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array of numbers", key)
	}
	if len(arr) == 0 {
		// A present-but-empty list would read as "no restriction" and hand
		// back the whole audience to a caller that meant to narrow it.
		return nil, fmt.Errorf("%s must not be empty when given; omit it for no restriction", key)
	}
	out := make([]int64, 0, len(arr))
	for _, el := range arr {
		f, ok := el.(float64)
		if !ok || f != math.Trunc(f) || f <= 0 || f > 1<<53 {
			return nil, fmt.Errorf("%s entries must be positive whole numbers", key)
		}
		out = append(out, int64(f))
	}
	return out, nil
}

func (s *Server) toolPrepareBroadcast() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("prepare_broadcast",
		mcplib.WithTitleAnnotation("Prepare a client broadcast (preview only)"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[prepareBroadcastResult](),
		mcplib.WithDescription(`Broadcast operators only (requires the admin:broadcast scope). Prepares a broadcast to opted-in clients through the login bot and returns a PREVIEW. It sends nothing.

The audience is computed by the server from the selector below. You cannot add recipients: only_telegram_ids can only narrow the computed audience, for a dry-run on a test account. A client is eligible only with a live account, an effective tier inside the selector, consent for the category, and a bot that can reach them.

Inputs:
  category           — string, required. "product_updates" (opt-in only), "maintenance" or "security".
  text               — string, required. At most 4096 UTF-16 units of visible text. Sent exactly as normalized here.
  format             — string, optional. "plain" (default): sent as is, no formatting. "html": Telegram HTML subset, validated now. Allowed: <b>, <i>, <u>, <s>, <code>, <pre>, <blockquote> and <a href="https://...">; write &lt; &gt; &amp; for literal < > &. Anything else is refused. The format is part of what the operator approves.
  tiers              — array, optional. ["client"] (default) and/or "admin".
  connected_via      — array, optional. Only clients with a live grant for one of these OAuth client names (e.g. "Claude", "ChatGPT").
  active_within_days — number, optional. Only clients seen within this many days.
  only_telegram_ids  — array of numbers, optional, at most 5. Narrows the audience to these Telegram ids. An id that fails any eligibility rule is skipped, not sent.

Output: campaign_id, the normalized text and its hash, the canonical selector and its hash, eligible and skipped counts by reason, a redacted sample, estimated batches, expires_at, and approval_url.

Approval is NOT possible through this or any other tool. A human operator must approve the campaign on approval_url, signed in with Telegram in a browser, before expires_at. Hand the URL to the operator. The server re-checks consent and eligibility at send time, so the delivered count can be lower than the preview.`),
		mcplib.WithString("category", mcplib.Required(), mcplib.Description(`"product_updates", "maintenance" or "security" (required).`)),
		mcplib.WithString("text", mcplib.Required(), mcplib.Description("The message text (required). Plain text, or the HTML subset when format is html.")),
		mcplib.WithString("format", mcplib.Description(`"plain" (default) or "html" (Telegram HTML subset: b, i, u, s, code, pre, blockquote, a with an https href). Bound into the approval.`)),
		mcplib.WithArray("tiers", mcplib.Description(`Effective tiers to target: "client" (default), "admin".`)),
		mcplib.WithArray("connected_via", mcplib.Description("OAuth client names; restricts the audience to clients connected through one of them.")),
		mcplib.WithNumber("active_within_days", mcplib.Description("Restrict to clients seen within this many days.")),
		mcplib.WithArray("only_telegram_ids", mcplib.Description("Narrow the audience to these Telegram ids (at most 5). Never adds recipients: every eligibility rule still applies.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "admin:broadcast"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		actor, err := s.broadcastActor(id)
		if err != nil {
			s.audit(ctx, id, "prepare_broadcast", "", err, startedAt)
			return mcplib.NewToolResultError(err.Error()), nil
		}
		args := req.GetArguments()
		tiers, err := stringListArg(args, "tiers")
		if err != nil {
			s.audit(ctx, id, "prepare_broadcast", "", err, startedAt)
			return mcplib.NewToolResultError(err.Error()), nil
		}
		via, err := stringListArg(args, "connected_via")
		if err != nil {
			s.audit(ctx, id, "prepare_broadcast", "", err, startedAt)
			return mcplib.NewToolResultError(err.Error()), nil
		}
		only, err := telegramIDListArg(args, "only_telegram_ids")
		if err != nil {
			s.audit(ctx, id, "prepare_broadcast", "", err, startedAt)
			return mcplib.NewToolResultError(err.Error()), nil
		}
		format, err := formatArg(args, "format")
		if err != nil {
			s.audit(ctx, id, "prepare_broadcast", "", err, startedAt)
			return mcplib.NewToolResultError(err.Error()), nil
		}
		preview, err := s.Broadcast.Prepare(ctx, actor, broadcast.PrepareRequest{
			Selector: broadcast.Selector{
				Category:         stringArg(args, "category", ""),
				Tiers:            tiers,
				ConnectedVia:     via,
				ActiveWithinDays: intArg(args, "active_within_days", 0),
				OnlyTelegramIDs:  only,
			},
			Text:   stringArg(args, "text", ""),
			Format: format,
		})
		s.audit(ctx, id, "prepare_broadcast", "", err, startedAt)
		if err != nil {
			return toolErr("prepare_broadcast: %v", err), nil
		}
		return jsonResult(prepareBroadcastResult{
			Preview:     *preview,
			ApprovalURL: s.BroadcastApprovalURL,
			Note:        "Nothing has been sent. A human operator must approve this campaign at approval_url (browser Telegram sign-in) before expires_at; no tool can approve it.",
		})
	}
	return tool, handler
}

func (s *Server) toolListBroadcasts() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("list_broadcasts",
		mcplib.WithTitleAnnotation("List broadcast campaigns"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[listBroadcastsResult](),
		mcplib.WithDescription(`Broadcast operators only (requires the admin:broadcast scope). Lists broadcast campaigns, newest first (up to 50).

Inputs:
  state — string, optional. One of prepared, approved, sending, completed, cancelled, expired. Omit to list all states.`),
		mcplib.WithString("state", mcplib.Description("Filter by campaign state.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "admin:broadcast"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		if _, err := s.broadcastActor(id); err != nil {
			s.audit(ctx, id, "list_broadcasts", "", err, startedAt)
			return mcplib.NewToolResultError(err.Error()), nil
		}
		var states []string
		if st := stringArg(req.GetArguments(), "state", ""); st != "" {
			if !validCampaignState(st) {
				err := fmt.Errorf("unknown state %q: use one of prepared, approved, sending, completed, cancelled, expired", st)
				s.audit(ctx, id, "list_broadcasts", "", err, startedAt)
				return mcplib.NewToolResultError(err.Error()), nil
			}
			states = []string{st}
		}
		list, err := s.Store.ListBroadcastCampaigns(ctx, 50, states...)
		s.audit(ctx, id, "list_broadcasts", "", err, startedAt)
		if err != nil {
			return s.storeErr(ctx, "list_broadcasts", err), nil
		}
		out := listBroadcastsResult{Campaigns: make([]broadcastSummary, 0, len(list))}
		for _, c := range list {
			out.Campaigns = append(out.Campaigns, summarize(c))
		}
		out.Count = len(out.Campaigns)
		return jsonResult(out)
	}
	return tool, handler
}

func (s *Server) toolGetBroadcast() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("get_broadcast",
		mcplib.WithTitleAnnotation("Get a broadcast campaign and its delivery report"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[getBroadcastResult](),
		mcplib.WithDescription(`Broadcast operators only (requires the admin:broadcast scope). Returns one campaign and its aggregate delivery report.

The report gives delivered, skipped by reason, transient failures, permanent failures by reason, outcome unknown and pending, plus who approved. It names no recipient. "delivered" means the Bot API accepted the message, not that it was read.

Inputs:
  campaign_id — string, required.`),
		mcplib.WithString("campaign_id", mcplib.Required(), mcplib.Description("Campaign id from prepare_broadcast or list_broadcasts.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "admin:broadcast"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		if _, err := s.broadcastActor(id); err != nil {
			s.audit(ctx, id, "get_broadcast", "", err, startedAt)
			return mcplib.NewToolResultError(err.Error()), nil
		}
		cid := stringArg(req.GetArguments(), "campaign_id", "")
		c, err := s.Store.GetBroadcastCampaign(ctx, cid)
		var report *broadcast.Report
		if err == nil {
			report, err = broadcast.BuildReport(ctx, s.Store, cid)
		}
		s.audit(ctx, id, "get_broadcast", "", err, startedAt)
		if err != nil {
			return s.storeErr(ctx, "get_broadcast", err), nil
		}
		return jsonResult(getBroadcastResult{Campaign: summarize(*c), Report: *report})
	}
	return tool, handler
}

func (s *Server) toolCancelBroadcast() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("cancel_broadcast",
		mcplib.WithTitleAnnotation("Cancel a broadcast campaign"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[cancelBroadcastResult](),
		mcplib.WithDescription(`Broadcast operators only (requires the admin:broadcast scope). Cancels a campaign that has not finished: a preview, an approved campaign, or one being sent. Messages not yet sent are skipped. Messages already delivered stay delivered.

Inputs:
  campaign_id — string, required.`),
		mcplib.WithString("campaign_id", mcplib.Required(), mcplib.Description("Campaign id to cancel.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "admin:broadcast"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		actor, err := s.broadcastActor(id)
		if err != nil {
			s.audit(ctx, id, "cancel_broadcast", "", err, startedAt)
			return mcplib.NewToolResultError(err.Error()), nil
		}
		cid := stringArg(req.GetArguments(), "campaign_id", "")
		err = s.Broadcast.Cancel(ctx, actor, cid)
		s.audit(ctx, id, "cancel_broadcast", "", err, startedAt)
		if err != nil {
			return toolErr("cancel_broadcast: %v", err), nil
		}
		return jsonResult(cancelBroadcastResult{CampaignID: cid, State: db.CampaignCancelled})
	}
	return tool, handler
}
