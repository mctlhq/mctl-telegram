package mcpui

import (
	_ "embed"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

const WorkspaceResourceURI = "ui://mctl-telegram/workspace-2.html"

// PreviousWorkspaceResourceURI keeps cached tool descriptors readable.
const PreviousWorkspaceResourceURI = "ui://mctl-telegram/workspace-1.html"

//go:embed workspace.html
var workspaceHTML string

func WorkspaceResource() mcplib.Resource {
	return mcplib.Resource{
		URI: WorkspaceResourceURI, Name: "telegram-workspace", Title: "Telegram Workspace",
		Description: "Read-only Telegram overview, inbox, search and account status",
		MIMEType:    MIMEType, Meta: mcplib.NewMetaFromMap(uiResourceMeta()),
	}
}
