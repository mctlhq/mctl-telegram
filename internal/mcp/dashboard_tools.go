package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/dashboard"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// dashboardDraftText is the text a save_draft confirmation is bound to.
// Whitespace-only text clears the draft, matching toolSaveDraft.
func dashboardDraftText(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	return text
}

// rejectDashboardConfirmation consumes a prepare_dashboard_action id when
// the caller supplied one. An empty id leaves the tool on its previous
// path. A bad id is an error and does not reach Telegram. A good id is not
// permission: the caller still has to pass the tool's own gate.
func (s *Server) rejectDashboardConfirmation(ctx context.Context, id *auth.Identity, tool, peer, confID, payloadHash string, startedAt time.Time) *mcplib.CallToolResult {
	confID = strings.TrimSpace(confID)
	if confID == "" {
		return nil
	}
	if s.Confirms == nil {
		return mcplib.NewToolResultError("confirmation_id cannot be checked")
	}
	uid := int64(0)
	if id != nil {
		uid = id.UserID
	}
	if _, err := s.Confirms.Consume(confID, uid, payloadHash); err != nil {
		s.audit(ctx, id, tool+":confirmation_rejected", telegram.RedactPeer(peer), err, startedAt)
		switch {
		case errors.Is(err, ErrConfirmationMismatch):
			return mcplib.NewToolResultError("confirmation_id was issued for a different action — re-run prepare_dashboard_action")
		case errors.Is(err, ErrConfirmationWrongUser):
			return mcplib.NewToolResultError("confirmation_id belongs to another identity")
		default:
			return mcplib.NewToolResultError("confirmation_id not found, expired, or already used")
		}
	}
	return nil
}

type dashboardTemplateSummary struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Builtin bool   `json:"builtin"`
}

type listDashboardTemplatesResult struct {
	Templates []dashboardTemplateSummary `json:"templates"`
	Quota     struct {
		Used int `json:"used"`
		Max  int `json:"max"`
	} `json:"quota"`
}

func (s *Server) toolListDashboardTemplates() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("list_dashboard_templates",
		mcplib.WithTitleAnnotation("List dashboard templates"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[listDashboardTemplatesResult](),
		mcplib.WithDescription(`List Telegram dashboard templates for this account.

Built-in templates come first. Custom templates are the ones this account saved with save_dashboard_template. Nothing here reads Telegram.

Output: {templates: [{id, title, builtin}], quota: {used, max}}.`),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "telegram:dialogs:read"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		custom, err := s.customDashboardTemplates(ctx, id.UserID)
		if err != nil {
			s.audit(ctx, id, "list_dashboard_templates", "", err, startedAt)
			return s.storeErr(ctx, "list_dashboard_templates", err), nil
		}
		out := listDashboardTemplatesResult{}
		for _, row := range dashboard.Summaries(custom) {
			out.Templates = append(out.Templates, dashboardTemplateSummary{ID: row.ID, Title: row.Title, Builtin: row.Builtin})
		}
		out.Quota.Used = len(custom)
		out.Quota.Max = dashboard.MaxCustomTemplates
		s.audit(ctx, id, "list_dashboard_templates", "", nil, startedAt)
		return jsonResult(out)
	}
	return tool, handler
}

type getDashboardTemplateResult struct {
	Builtin  bool `json:"builtin"`
	Template any  `json:"template"`
}

func (s *Server) toolGetDashboardTemplate() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("get_dashboard_template",
		mcplib.WithTitleAnnotation("Get a dashboard template"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[getDashboardTemplateResult](),
		mcplib.WithDescription(`Return one Telegram dashboard template document (tg-dashboard/v1).

Pass a built-in id (unread_pulse, groups_tiles, folders_board, forum_topics, watchlist_digest) or a custom id from list_dashboard_templates. The document is what the dashboard App renders. It is not Telegram content.

Inputs (required): id.`),
		mcplib.WithString("id", mcplib.Required(), mcplib.Description("Template id.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "telegram:dialogs:read"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		name := strings.TrimSpace(stringArg(req.GetArguments(), "id", ""))
		if name == "" {
			return mcplib.NewToolResultError("id is required"), nil
		}
		raw, builtin, err := s.dashboardTemplateBody(ctx, id.UserID, name)
		if err != nil {
			s.audit(ctx, id, "get_dashboard_template", "", err, startedAt)
			if errors.Is(err, db.ErrDashboardTemplateNotFound) {
				return mcplib.NewToolResultError("dashboard template not found"), nil
			}
			return s.storeErr(ctx, "get_dashboard_template", err), nil
		}
		var body any
		if err := json.Unmarshal(raw, &body); err != nil {
			return mcplib.NewToolResultError("stored template is not valid JSON"), nil
		}
		s.audit(ctx, id, "get_dashboard_template", "", nil, startedAt)
		return jsonResult(getDashboardTemplateResult{Builtin: builtin, Template: body})
	}
	return tool, handler
}

type saveDashboardTemplateResult struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Saved  bool   `json:"saved"`
	DryRun bool   `json:"dry_run,omitempty"`
	Valid  bool   `json:"valid"`
}

func (s *Server) toolSaveDashboardTemplate() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("save_dashboard_template",
		mcplib.WithTitleAnnotation("Save a dashboard template"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[saveDashboardTemplateResult](),
		mcplib.WithDescription(`Validate and store a custom Telegram dashboard template for this account.

The document must be schema tg-dashboard/v1. Data sources may name only list_dialogs, list_folders, list_topics, get_unread_messages, get_messages, and search_messages. Actions may name only mark_read and save_draft. send_message, delete_messages, and every other write are rejected. Built-in ids cannot be overwritten. An account may store `+itoa(dashboard.MaxCustomTemplates)+` custom templates, each at most 24 KiB.

Pass dry_run=true to validate and return without writing. That is how the dashboard editor checks a document.

This writes this server's template table only. It does not call Telegram.

Inputs (required): template — the document object.
Inputs (optional): dry_run — validate only.`),
		mcplib.WithObject("template", mcplib.Required(), mcplib.Description("tg-dashboard/v1 document.")),
		mcplib.WithBoolean("dry_run", mcplib.Description("Validate and do not write.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "telegram:dialogs:read"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		raw, err := templateArg(req.GetArguments())
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		var peek struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &peek) == nil && dashboard.IsBuiltin(peek.ID) {
			return mcplib.NewToolResultError("built-in template " + peek.ID + " cannot be overwritten"), nil
		}
		tpl, err := dashboard.Parse(raw)
		if err != nil {
			s.audit(ctx, id, "save_dashboard_template", "", err, startedAt)
			return mcplib.NewToolResultError(err.Error()), nil
		}
		if dashboard.IsBuiltin(tpl.ID) {
			return mcplib.NewToolResultError("built-in template " + tpl.ID + " cannot be overwritten"), nil
		}
		body, err := tpl.Canonical()
		if err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		dry := boolArg(req.GetArguments(), "dry_run", false)
		if dry {
			s.audit(ctx, id, "save_dashboard_template", "", nil, startedAt)
			return jsonResult(saveDashboardTemplateResult{ID: tpl.ID, Title: tpl.Title, Saved: false, DryRun: true, Valid: true})
		}
		if s.Store == nil {
			return mcplib.NewToolResultError("dashboard templates are not available"), nil
		}
		if err := s.Store.SaveDashboardTemplate(ctx, id.UserID, tpl.ID, tpl.Title, string(body), dashboard.MaxCustomTemplates); err != nil {
			s.audit(ctx, id, "save_dashboard_template", "", err, startedAt)
			if errors.Is(err, db.ErrDashboardTemplateQuota) {
				return mcplib.NewToolResultError("dashboard template quota reached"), nil
			}
			return s.storeErr(ctx, "save_dashboard_template", err), nil
		}
		s.audit(ctx, id, "save_dashboard_template", "", nil, startedAt)
		return jsonResult(saveDashboardTemplateResult{ID: tpl.ID, Title: tpl.Title, Saved: true, Valid: true})
	}
	return tool, handler
}

type deleteDashboardTemplateResult struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

func (s *Server) toolDeleteDashboardTemplate() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("delete_dashboard_template",
		mcplib.WithTitleAnnotation("Delete a dashboard template"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[deleteDashboardTemplateResult](),
		mcplib.WithDescription(`Delete one custom Telegram dashboard template from this account.

Built-in templates cannot be deleted. This does not call Telegram.

Inputs (required): id.`),
		mcplib.WithString("id", mcplib.Required(), mcplib.Description("Custom template id.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "telegram:dialogs:read"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		name := strings.TrimSpace(stringArg(req.GetArguments(), "id", ""))
		if name == "" {
			return mcplib.NewToolResultError("id is required"), nil
		}
		if dashboard.IsBuiltin(name) {
			return mcplib.NewToolResultError("built-in template " + name + " cannot be deleted"), nil
		}
		if s.Store == nil {
			return mcplib.NewToolResultError("dashboard templates are not available"), nil
		}
		if err := s.Store.DeleteDashboardTemplate(ctx, id.UserID, name); err != nil {
			s.audit(ctx, id, "delete_dashboard_template", "", err, startedAt)
			if errors.Is(err, db.ErrDashboardTemplateNotFound) {
				return mcplib.NewToolResultError("dashboard template not found"), nil
			}
			return s.storeErr(ctx, "delete_dashboard_template", err), nil
		}
		s.audit(ctx, id, "delete_dashboard_template", "", nil, startedAt)
		return jsonResult(deleteDashboardTemplateResult{ID: name, Deleted: true})
	}
	return tool, handler
}

type prepareDashboardActionResult struct {
	ConfirmationID string    `json:"confirmation_id"`
	Action         string    `json:"action"`
	PeerRedacted   string    `json:"peer_redacted"`
	Text           string    `json:"text,omitempty"`
	MaxID          int       `json:"max_id,omitempty"`
	TopicID        int       `json:"topic_id,omitempty"`
	Overwrite      bool      `json:"overwrite,omitempty"`
	WillApply      bool      `json:"will_apply"`
	DryReason      string    `json:"dry_reason,omitempty"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (s *Server) toolPrepareDashboardAction() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("prepare_dashboard_action",
		mcplib.WithTitleAnnotation("Prepare a dashboard action"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[prepareDashboardActionResult](),
		mcplib.WithDescription(`Snapshot a dashboard mark_read or save_draft the caller intends to confirm.

Returns a one-shot confirmation_id valid for 10m. mark_read or save_draft may echo it back as confirmation_id. The id is bound to the exact arguments: changing peer, text, max_id, topic_id, or overwrite between prepare and the write invalidates it. This call makes no Telegram request.

action must be mark_read or save_draft. send_message, delete_messages, and every other write are rejected here. The verdict (will_apply, dry_reason) is the same gate the write tool will run, reported rather than enforced. The write tool's own evaluation is authoritative, and a confirmation never replaces it.

mark_read requires peer and max_id. save_draft requires peer and text (empty text clears). topic_id and overwrite are optional.

A local-bridge account is still refused by mark_read and save_draft themselves; this prepare step does not speak for that check.`),
		mcplib.WithString("action", mcplib.Required(), mcplib.Description("mark_read or save_draft.")),
		mcplib.WithString("peer", mcplib.Required(), mcplib.Description("Chat the action names.")),
		mcplib.WithString("text", mcplib.Description("Draft text for save_draft. Empty clears. Required for save_draft.")),
		mcplib.WithNumber("max_id", mcplib.Description("Newest message id for mark_read.")),
		mcplib.WithNumber("topic_id", mcplib.Description("Forum topic, when the action names one.")),
		mcplib.WithBoolean("overwrite", mcplib.Description("Replace an existing draft. save_draft only.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "telegram:messages:send"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		args := req.GetArguments()
		action := strings.TrimSpace(stringArg(args, "action", ""))
		peer := strings.TrimSpace(stringArg(args, "peer", ""))
		if peer == "" {
			return mcplib.NewToolResultError("peer is required"), nil
		}
		topicID, bad := optionalTopicArg(args)
		if bad != nil {
			return bad, nil
		}
		var (
			text      string
			maxID     int
			overwrite bool
			hash      string
			will      bool
			reason    string
		)
		switch action {
		case "mark_read":
			var ok bool
			maxID, ok = messageIDArg(args, "max_id")
			if !ok {
				return mcplib.NewToolResultError("mark_read requires a positive integer max_id"), nil
			}
			hash = HashDashboardAction("mark_read", peer, "", maxID, topicID, false)
			// Reported, not enforced. mark_read runs evaluateSendGate again.
			will, reason = evaluateSendGate(ctx, s.Store, id, s.AllowSend, s.reviewerGateFor("mark_read", peer))
		case "save_draft":
			if _, ok := args["text"].(string); !ok {
				return mcplib.NewToolResultError("save_draft requires text (pass an empty string to clear)"), nil
			}
			text = dashboardDraftText(stringArg(args, "text", ""))
			overwrite = boolArg(args, "overwrite", false)
			hash = HashDashboardAction("save_draft", peer, text, 0, topicID, overwrite)
			// Reported, not enforced. save_draft runs the same helper again
			// and does not consult per-account send_enabled.
			if decided, _, why := evaluateWriteGateBeforeAccount(id, s.AllowSend, s.reviewerGateFor("save_draft", peer), "telegram:messages:send"); decided {
				will, reason = false, why
			} else {
				will = true
			}
		default:
			return mcplib.NewToolResultError("action must be mark_read or save_draft"), nil
		}
		c, err := s.Confirms.Issue(id.UserID, "dash:"+action, hash)
		if err != nil {
			return toolErr("prepare_dashboard_action: %v", err), nil
		}
		s.audit(ctx, id, "prepare_dashboard_action", telegram.RedactPeer(peer), nil, startedAt)
		return jsonResult(prepareDashboardActionResult{
			ConfirmationID: c.ID,
			Action:         action,
			PeerRedacted:   telegram.RedactPeer(peer),
			Text:           text,
			MaxID:          maxID,
			TopicID:        topicID,
			Overwrite:      overwrite,
			WillApply:      will,
			DryReason:      reason,
			ExpiresAt:      c.ExpiresAt.UTC(),
		})
	}
	return tool, handler
}

func (s *Server) customDashboardTemplates(ctx context.Context, userID int64) ([]dashboard.Template, error) {
	if s.Store == nil {
		return nil, nil
	}
	rows, err := s.Store.ListDashboardTemplates(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]dashboard.Template, 0, len(rows))
	for _, row := range rows {
		tpl, err := dashboard.Parse([]byte(row.Body))
		if err != nil {
			return nil, fmt.Errorf("dashboard template %s: %w", row.ID, err)
		}
		out = append(out, *tpl)
	}
	return out, nil
}

func (s *Server) dashboardTemplateBody(ctx context.Context, userID int64, name string) ([]byte, bool, error) {
	if tpl, ok := dashboard.Builtin(name); ok {
		raw, err := tpl.Canonical()
		return raw, true, err
	}
	if s.Store == nil {
		return nil, false, db.ErrDashboardTemplateNotFound
	}
	row, err := s.Store.GetDashboardTemplate(ctx, userID, name)
	if err != nil {
		return nil, false, err
	}
	return []byte(row.Body), false, nil
}

func templateArg(args map[string]any) ([]byte, error) {
	v, ok := args["template"]
	if !ok || v == nil {
		return nil, errors.New("template is required")
	}
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) == "" {
			return nil, errors.New("template is required")
		}
		return []byte(t), nil
	default:
		raw, err := json.Marshal(t)
		if err != nil {
			return nil, errors.New("template must be an object")
		}
		return raw, nil
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
