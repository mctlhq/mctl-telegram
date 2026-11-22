package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Admin tools for the Personal Assistant's per-principal disable (threat
// model T11, S1-F4; #1318 slice A1). The disable is read inside every PA
// update at ingress and at every run-loop step, so it takes effect at the
// principal's next update or step without a restart.

// paPrincipalDisableResult is the success payload of
// set_pa_principal_disabled and get_pa_principal_status.
type paPrincipalDisableResult struct {
	TelegramID int64 `json:"telegram_id"`
	Disabled   bool  `json:"disabled"`
}

// toolSetPAPrincipalDisabled disables or re-enables one principal's PA.
func (s *Server) toolSetPAPrincipalDisabled() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("set_pa_principal_disabled",
		mcplib.WithTitleAnnotation("Disable or re-enable one user's Personal Assistant"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[paPrincipalDisableResult](),
		mcplib.WithDescription(fmt.Sprintf(`Admin only (requires the admin:users scope). Disable or re-enable the Personal Assistant bot for one Telegram user.

Inputs:
  telegram_id — int, required. The Telegram user id of the assistant's user.
  disabled    — bool, required. true disables, false re-enables.
  reason      — string, required when disabling: why, one line, at most %d characters. Recorded with the disable; ignored when re-enabling.

A disabled user gets a fixed "not available" reply to every message and nothing they send is stored or queued; their running request is stopped at its next step. /forget and /consent withdraw still work. The disable survives the account's deletion; only this tool with disabled=false clears it.`, db.MaxPAPrincipalDisableReason)),
		mcplib.WithNumber("telegram_id",
			mcplib.Required(),
			mcplib.Description("Telegram user id (required).")),
		mcplib.WithBoolean("disabled",
			mcplib.Required(),
			mcplib.Description("true disables, false re-enables (required).")),
		mcplib.WithString("reason",
			mcplib.Description(fmt.Sprintf("Why the user is disabled: one line, at most %d characters. Required when disabled is true.", db.MaxPAPrincipalDisableReason))),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "admin:users"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		args := req.GetArguments()
		tgID := int64(intArg(args, "telegram_id", 0))
		if tgID <= 0 {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("telegram_id is required and must be a positive integer"), nil
		}
		disabled, ok := args["disabled"].(bool)
		if !ok {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("disabled is required and must be true or false"), nil
		}
		if id.UserID <= 0 {
			return mcplib.NewToolResultError("set_pa_principal_disabled: the caller has no user id to record"), nil
		}
		var err error
		if disabled {
			reason := strings.TrimSpace(stringArg(args, "reason", ""))
			if reason == "" || utf8.RuneCountInString(reason) > db.MaxPAPrincipalDisableReason || strings.ContainsAny(reason, "\r\n") {
				hintReason(ctx, ReasonInvalidArgument)
				return mcplib.NewToolResultError(fmt.Sprintf("reason is required when disabling: one line, 1-%d characters", db.MaxPAPrincipalDisableReason)), nil
			}
			err = s.Store.SetPAPrincipalDisabled(ctx, tgID, id.UserID, reason, time.Now())
		} else {
			err = s.Store.ClearPAPrincipalDisabled(ctx, tgID)
		}
		s.audit(ctx, id, "set_pa_principal_disabled", "", err, startedAt)
		if err != nil {
			return s.storeErr(ctx, "set_pa_principal_disabled", err), nil
		}
		return jsonResult(paPrincipalDisableResult{TelegramID: tgID, Disabled: disabled})
	}
	return tool, handler
}

// toolGetPAPrincipalStatus reads whether one principal's PA is disabled.
func (s *Server) toolGetPAPrincipalStatus() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("get_pa_principal_status",
		mcplib.WithTitleAnnotation("Read whether one user's Personal Assistant is disabled"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[paPrincipalDisableResult](),
		mcplib.WithDescription(`Admin only (requires the admin:users or admin:users:read scope). Read whether the Personal Assistant bot is disabled for one Telegram user (see set_pa_principal_disabled).

Inputs:
  telegram_id — int, required. The Telegram user id.

A status that cannot be read is an error, never "not disabled".`),
		mcplib.WithNumber("telegram_id",
			mcplib.Required(),
			mcplib.Description("Telegram user id (required).")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := auth.From(ctx)
		if err := requireAnyScope(id, "admin:users", "admin:users:read"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		tgID := int64(intArg(req.GetArguments(), "telegram_id", 0))
		if tgID <= 0 {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("telegram_id is required and must be a positive integer"), nil
		}
		disabled, err := s.Store.PAPrincipalDisabledState(ctx, tgID)
		if err != nil {
			return s.storeErr(ctx, "get_pa_principal_status", err), nil
		}
		return jsonResult(paPrincipalDisableResult{TelegramID: tgID, Disabled: disabled})
	}
	return tool, handler
}
