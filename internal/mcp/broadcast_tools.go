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
// scope gate into a service actor, refusing when the workflow is disabled.
// The scope check itself stays in each handler as a literal requireScope
// call: portal_allowlist_test derives every tool's upstream gate from exactly
// that call, so hiding it in a helper would make the gate invisible to it.
func (s *Server) broadcastActor(id *auth.Identity) (broadcast.Actor, error) {
	if s.Broadcast == nil || !s.Broadcast.Enabled() {
		return broadcast.Actor{}, errBroadcastDisabled
	}
	surface := "mcp"
	if id.ClientID != "" {
		surface = "mcp:" + id.ClientID
	}
	return broadcast.Actor{UserID: id.UserID, TelegramID: id.TelegramID, Surface: surface}, nil
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
	Preview    string     `json:"preview_counts"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
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
	return broadcastSummary{
		CampaignID: c.ID, State: c.State, EndReason: c.EndReason, Category: c.Category,
		Selector: c.SelectorJSON, Text: c.Content, Preview: c.PreviewCounts,
		CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt, ApprovedAt: c.ApprovedAt,
	}
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

func (s *Server) toolPrepareBroadcast() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("prepare_broadcast",
		mcplib.WithTitleAnnotation("Prepare a client broadcast (preview only)"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[prepareBroadcastResult](),
		mcplib.WithDescription(`Broadcast operators only (requires the admin:broadcast scope). Prepares a broadcast to opted-in clients through the login bot and returns a PREVIEW. It sends nothing.

The audience is computed by the server from the selector below. There is no way to name recipients. A client is eligible only with a live account, an effective tier inside the selector, consent for the category, and a bot that can reach them.

Inputs:
  category           — string, required. "product_updates" (opt-in only), "maintenance" or "security".
  text               — string, required. Plain text, at most 4096 UTF-16 units. Sent exactly as normalized here.
  tiers              — array, optional. ["client"] (default) and/or "admin".
  connected_via      — array, optional. Only clients with a live grant for one of these OAuth client names (e.g. "Claude", "ChatGPT").
  active_within_days — number, optional. Only clients seen within this many days.

Output: campaign_id, the normalized text and its hash, the canonical selector and its hash, eligible and skipped counts by reason, a redacted sample, estimated batches, expires_at, and approval_url.

Approval is NOT possible through this or any other tool. A human operator must approve the campaign on approval_url, signed in with Telegram in a browser, before expires_at. Hand the URL to the operator. The server re-checks consent and eligibility at send time, so the delivered count can be lower than the preview.`),
		mcplib.WithString("category", mcplib.Required(), mcplib.Description(`"product_updates", "maintenance" or "security" (required).`)),
		mcplib.WithString("text", mcplib.Required(), mcplib.Description("The message text (required, plain text).")),
		mcplib.WithArray("tiers", mcplib.Description(`Effective tiers to target: "client" (default), "admin".`)),
		mcplib.WithArray("connected_via", mcplib.Description("OAuth client names; restricts the audience to clients connected through one of them.")),
		mcplib.WithNumber("active_within_days", mcplib.Description("Restrict to clients seen within this many days.")),
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
			return mcplib.NewToolResultError(err.Error()), nil
		}
		via, err := stringListArg(args, "connected_via")
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		preview, err := s.Broadcast.Prepare(ctx, actor, broadcast.PrepareRequest{
			Selector: broadcast.Selector{
				Category:         stringArg(args, "category", ""),
				Tiers:            tiers,
				ConnectedVia:     via,
				ActiveWithinDays: intArg(args, "active_within_days", 0),
			},
			Text: stringArg(args, "text", ""),
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
			return mcplib.NewToolResultError(err.Error()), nil
		}
		var states []string
		if st := stringArg(req.GetArguments(), "state", ""); st != "" {
			states = []string{st}
		}
		list, err := s.Store.ListBroadcastCampaigns(ctx, 50, states...)
		s.audit(ctx, id, "list_broadcasts", "", err, startedAt)
		if err != nil {
			return toolErr("list_broadcasts: %v", err), nil
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
			return toolErr("get_broadcast: %v", err), nil
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
