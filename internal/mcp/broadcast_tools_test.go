package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/broadcast"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

const bcOperatorTG = int64(888000111)

func newBroadcastToolServer(t *testing.T, enabled bool) (*Server, *db.Store, int64) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(conn, nil)
	now := time.Now().UTC()
	opUID, err := store.EnsureUserByTelegramCapture(ctx, db.TelegramIdentityCapture{TelegramID: bcOperatorTG, Username: "op", Source: "telegram_oidc", CapturedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureUserByTelegramCapture(ctx, db.TelegramIdentityCapture{TelegramID: 888000222, Username: "c", Source: "telegram_oidc", CapturedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetAccessTier(ctx, 888000222, db.TierClient); err != nil {
		t.Fatal(err)
	}
	ops := map[int64]bool{}
	if enabled {
		ops[bcOperatorTG] = true
	}
	svc := broadcast.NewService(store, broadcast.Config{Operators: ops, Policy: broadcast.Policy{AdminTelegramIDs: map[int64]bool{bcOperatorTG: true}}}, nil)
	srv := (&Server{Store: store}).WithBroadcast(svc, "https://tg.mctl.ai/telegram/connect/broadcasts")
	return srv, store, opUID
}

func callBroadcastTool(t *testing.T, build func() (mcplib.Tool, mcpserver.ToolHandlerFunc), id *auth.Identity, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	tool, handler := build()
	res, err := handler(auth.With(context.Background(), id), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: tool.Name, Arguments: args}})
	if err != nil {
		t.Fatalf("%s: %v", tool.Name, err)
	}
	return res
}

func resultText(r *mcplib.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(mcplib.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// No MCP tool can approve or send a broadcast: that is a human act on the
// web page. A future "approve_broadcast" tool fails this test.
func TestBroadcastTools_NoApprovalOverMCP(t *testing.T) {
	for _, tool := range (&Server{ToolFilter: ""}).newMCPServer().ListTools() {
		name := tool.Tool.Name
		if strings.Contains(name, "broadcast") && (strings.Contains(name, "approve") || strings.Contains(name, "send") || strings.Contains(name, "confirm")) {
			t.Errorf("tool %q would let an MCP client release a broadcast", name)
		}
	}
}

func TestBroadcastTools_ScopeGate(t *testing.T) {
	srv, _, opUID := newBroadcastToolServer(t, true)
	builds := map[string]func() (mcplib.Tool, mcpserver.ToolHandlerFunc){
		"prepare_broadcast": srv.toolPrepareBroadcast, "list_broadcasts": srv.toolListBroadcasts,
		"get_broadcast": srv.toolGetBroadcast, "cancel_broadcast": srv.toolCancelBroadcast,
	}
	for name, build := range builds {
		for _, scopes := range [][]string{nil, {"admin:users"}, {"admin:users:read"}, {"telegram:messages:send", "account:manage"}} {
			id := &auth.Identity{UserID: opUID, TelegramID: bcOperatorTG, Scopes: scopes}
			res := callBroadcastTool(t, build, id, map[string]any{"category": "maintenance", "text": "x", "campaign_id": "bc_x"})
			if !res.IsError || !strings.Contains(resultText(res), "missing scope") {
				t.Errorf("%s with %v: not refused by the scope gate: %s", name, scopes, resultText(res))
			}
		}
	}
}

func TestBroadcastTools_DisabledRefuses(t *testing.T) {
	srv, _, opUID := newBroadcastToolServer(t, false)
	id := &auth.Identity{UserID: opUID, TelegramID: bcOperatorTG, Scopes: []string{BroadcastScope}}
	res := callBroadcastTool(t, srv.toolPrepareBroadcast, id, map[string]any{"category": "maintenance", "text": "x"})
	if !res.IsError || !strings.Contains(resultText(res), "not enabled") {
		t.Fatalf("disabled prepare = %s", resultText(res))
	}
}

// prepare_broadcast records a campaign that is only prepared -- nothing is
// approved or sent -- and hands back the human approval URL.
func TestBroadcastTools_PrepareIsPreviewOnly(t *testing.T) {
	srv, store, opUID := newBroadcastToolServer(t, true)
	id := &auth.Identity{UserID: opUID, TelegramID: bcOperatorTG, Scopes: []string{BroadcastScope}, ClientID: "tgmcp_abc"}
	res := callBroadcastTool(t, srv.toolPrepareBroadcast, id, map[string]any{"category": "maintenance", "text": "Maintenance tonight."})
	if res.IsError {
		t.Fatalf("prepare: %s", resultText(res))
	}
	var out struct {
		CampaignID  string `json:"campaign_id"`
		ApprovalURL string `json:"approval_url"`
		Eligible    int    `json:"eligible"`
	}
	if err := json.Unmarshal([]byte(resultText(res)), &out); err != nil {
		t.Fatalf("decode %s: %v", resultText(res), err)
	}
	if out.ApprovalURL != "https://tg.mctl.ai/telegram/connect/broadcasts" || out.CampaignID == "" {
		t.Fatalf("result = %+v", out)
	}
	c, err := store.GetBroadcastCampaign(context.Background(), out.CampaignID)
	if err != nil || c.State != db.CampaignPrepared || c.ApprovedAt != nil {
		t.Fatalf("campaign after prepare = %+v %v", c, err)
	}

	// cancel_broadcast works for the operator.
	res = callBroadcastTool(t, srv.toolCancelBroadcast, id, map[string]any{"campaign_id": out.CampaignID})
	if res.IsError {
		t.Fatalf("cancel: %s", resultText(res))
	}
	if c, _ := store.GetBroadcastCampaign(context.Background(), out.CampaignID); c.State != db.CampaignCancelled {
		t.Fatalf("state after cancel = %s", c.State)
	}
}

// list_broadcasts and get_broadcast return the campaign and its aggregate
// report: who prepared it, who approved it, and counts -- no recipients.
func TestBroadcastTools_ListAndGetReport(t *testing.T) {
	srv, _, opUID := newBroadcastToolServer(t, true)
	id := &auth.Identity{UserID: opUID, TelegramID: bcOperatorTG, Scopes: []string{BroadcastScope}}
	res := callBroadcastTool(t, srv.toolPrepareBroadcast, id, map[string]any{"category": "maintenance", "text": "Maintenance tonight."})
	var prep struct {
		CampaignID   string `json:"campaign_id"`
		ContentHash  string `json:"content_hash"`
		SelectorHash string `json:"selector_hash"`
	}
	if err := json.Unmarshal([]byte(resultText(res)), &prep); err != nil {
		t.Fatal(err)
	}
	if err := srv.Broadcast.Approve(context.Background(), broadcast.Actor{UserID: opUID, TelegramID: bcOperatorTG, Surface: "web"}, prep.CampaignID, prep.ContentHash, prep.SelectorHash); err != nil {
		t.Fatal(err)
	}

	res = callBroadcastTool(t, srv.toolListBroadcasts, id, map[string]any{"state": "approved"})
	var list struct {
		Count     int `json:"count"`
		Campaigns []struct {
			CampaignID string `json:"campaign_id"`
			Text       string `json:"text"`
		} `json:"campaigns"`
	}
	if err := json.Unmarshal([]byte(resultText(res)), &list); err != nil || res.IsError {
		t.Fatalf("list: %s %v", resultText(res), err)
	}
	if list.Count != 1 || list.Campaigns[0].CampaignID != prep.CampaignID || list.Campaigns[0].Text != "Maintenance tonight." {
		t.Fatalf("list = %+v", list)
	}

	res = callBroadcastTool(t, srv.toolGetBroadcast, id, map[string]any{"campaign_id": prep.CampaignID})
	if res.IsError {
		t.Fatalf("get: %s", resultText(res))
	}
	var got struct {
		Campaign struct {
			State string `json:"state"`
		} `json:"campaign"`
		Report struct {
			CreatedBy  int64  `json:"created_by"`
			ApprovedBy *int64 `json:"approved_by"`
		} `json:"report"`
	}
	if err := json.Unmarshal([]byte(resultText(res)), &got); err != nil {
		t.Fatal(err)
	}
	if got.Campaign.State != db.CampaignApproved || got.Report.CreatedBy != opUID || got.Report.ApprovedBy == nil || *got.Report.ApprovedBy != opUID {
		t.Fatalf("get = %+v", got)
	}
	if strings.Contains(resultText(res), "888000222") {
		t.Fatal("the report names a recipient")
	}
}
