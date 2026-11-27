package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

const workspaceDialogLimit = 30

type workspaceAuditEntry struct {
	Time   time.Time `json:"time"`
	Tool   string    `json:"tool"`
	Status string    `json:"status"`
}

type workspaceSnapshot struct {
	Schema      string                `json:"schema"`
	UpdatedAt   time.Time             `json:"updated_at"`
	ReadScopes  []string              `json:"read_scopes"`
	DialogLimit int                   `json:"dialog_limit"`
	Dialogs     *listDialogsResult    `json:"dialogs,omitempty"`
	Folders     *listFoldersResult    `json:"folders,omitempty"`
	Identity    *myIdentityResult     `json:"identity,omitempty"`
	Send        *sendStatusResult     `json:"send,omitempty"`
	Audit       []workspaceAuditEntry `json:"audit,omitempty"`
	Unavailable []string              `json:"unavailable,omitempty"`
}

func (s *Server) toolTelegramDashboard() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("telegram_dashboard",
		mcplib.WithTitleAnnotation("Telegram Workspace"),
		mcplib.WithDescription("Open or refresh a read-only snapshot of your Telegram workspace. Shows recent dialogs, unread activity, folders and your account status. Launch with empty arguments. The text response summarizes the snapshot for clients without a view."),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(true),
		outputSchema[workspaceSnapshot](),
	)
	dialogTool, dialogs := s.toolListDialogs()
	folderTool, folders := s.toolListFolders()
	identityTool, identity := s.toolGetMyIdentity()
	sendTool, send := s.toolGetMySendStatus()
	return tool, func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		id := auth.From(ctx)
		if err := requireScope(id, "telegram:dialogs:read"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		if len(req.GetArguments()) != 0 {
			return mcplib.NewToolResultError("telegram_dashboard takes no arguments"), nil
		}
		out := workspaceSnapshot{
			Schema: "telegram-workspace/v1", DialogLimit: workspaceDialogLimit,
			ReadScopes: []string{"telegram:dialogs:read"},
		}
		if id.HasScope("telegram:messages:read") {
			out.ReadScopes = append(out.ReadScopes, "telegram:messages:read")
		}
		readCtx, cancel := context.WithTimeout(withRecorder(ctx, nil), 12*time.Second)
		defer cancel()
		// The constituent reads keep their original permission and hidden-chat
		// policy, including post-filtering bridge responses. Never dispatch a
		// caller-selected name, peer, argument or identity from this snapshot.
		out.Identity = workspaceSection[myIdentityResult](readCtx, id, identityTool.Name, identity, nil)
		out.Send = workspaceSection[sendStatusResult](readCtx, id, sendTool.Name, send, nil)
		if s.Pool != nil || s.Hub != nil {
			out.Dialogs = workspaceSection[listDialogsResult](readCtx, id, dialogTool.Name, s.hiddenScopeGuard(dialogs), map[string]any{"limit": float64(workspaceDialogLimit)})
			out.Folders = workspaceSection[listFoldersResult](readCtx, id, folderTool.Name, folders, nil)
		}
		for _, section := range []struct {
			name string
			ok   bool
		}{
			{"dialogs", out.Dialogs != nil}, {"folders", out.Folders != nil},
			{"identity", out.Identity != nil}, {"send status", out.Send != nil},
		} {
			if !section.ok {
				out.Unavailable = append(out.Unavailable, section.name)
			}
		}
		if s.Store != nil && toolAllowed(id, "get_my_audit_log") {
			entries, err := s.Store.ListAuditFor(readCtx, id.UserID, 5, time.Time{})
			if err != nil {
				out.Unavailable = append(out.Unavailable, "audit")
			} else {
				for _, entry := range entries {
					out.Audit = append(out.Audit, workspaceAuditEntry{Time: entry.Ts, Tool: entry.ToolName, Status: entry.Status})
				}
			}
		} else {
			out.Unavailable = append(out.Unavailable, "audit")
		}
		out.UpdatedAt = time.Now().UTC()
		return mcplib.NewToolResultStructured(out, summarizeWorkspace(out)), nil
	}
}

func workspaceSection[T any](ctx context.Context, id *auth.Identity, name string, handler mcpserver.ToolHandlerFunc, args map[string]any) *T {
	if !toolAllowed(id, name) {
		return nil
	}
	var req mcplib.CallToolRequest
	req.Params.Name = name
	req.Params.Arguments = args
	result, err := handler(ctx, req)
	if err != nil || result == nil || result.IsError || result.StructuredContent == nil {
		return nil
	}
	if value, ok := result.StructuredContent.(T); ok {
		return &value
	}
	// Hidden filtering and the bridge may return a decoded map.
	b, err := json.Marshal(result.StructuredContent)
	if err != nil {
		return nil
	}
	var value T
	if err := json.Unmarshal(b, &value); err != nil {
		return nil
	}
	return &value
}

func summarizeWorkspace(out workspaceSnapshot) string {
	text := "Telegram Workspace — read-only snapshot."
	if out.Identity != nil && out.Identity.Connected != nil {
		if *out.Identity.Connected {
			text += " Telegram session connected."
		} else {
			text += " No Telegram session connected."
		}
	}
	if out.Dialogs != nil {
		var unreadChats, unreadMessages int
		for _, dialog := range out.Dialogs.Dialogs {
			if dialog.UnreadCount > 0 {
				unreadChats++
				unreadMessages += dialog.UnreadCount
			}
		}
		text += fmt.Sprintf(" Among %d recent dialogs, %d have %d unread messages.",
			len(out.Dialogs.Dialogs), unreadChats, unreadMessages)
	}
	if out.Folders != nil {
		text += fmt.Sprintf(" %d chat folders.", len(out.Folders.Folders))
	}
	if len(out.Unavailable) != 0 {
		text += fmt.Sprintf(" Unavailable sections: %s.", strings.Join(out.Unavailable, ", "))
	}
	return text
}
