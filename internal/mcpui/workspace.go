package mcpui

import (
	_ "embed"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

const WorkspaceResourceURI = "ui://mctl-telegram/workspace-3.html"

// WorkspaceResourceV2URI keeps cached version 2 tool descriptors readable.
const WorkspaceResourceV2URI = "ui://mctl-telegram/workspace-2.html"

// PreviousWorkspaceResourceURI keeps cached tool descriptors readable.
const PreviousWorkspaceResourceURI = "ui://mctl-telegram/workspace-1.html"

// WorkspaceResourceVersion returns a bounded version label for a known URI.
func WorkspaceResourceVersion(uri string) string {
	switch uri {
	case WorkspaceResourceURI:
		return "3"
	case WorkspaceResourceV2URI:
		return "2"
	case PreviousWorkspaceResourceURI:
		return "1"
	default:
		return ""
	}
}

//go:embed workspace.html
var workspaceHTML string

func WorkspaceResource() mcplib.Resource {
	return mcplib.Resource{
		URI: WorkspaceResourceURI, Name: "telegram-workspace", Title: "Telegram Workspace",
		Description: "Read-only Telegram overview, inbox, search and account status",
		MIMEType:    MIMEType, Meta: mcplib.NewMetaFromMap(uiResourceMeta()),
	}
}
