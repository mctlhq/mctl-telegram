package mcpui

import (
	_ "embed"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// DashboardResourceURI is the stable URI of the dashboard document. It is
// separate from the triage document so the research flow keeps its own
// resource, and unversioned for the same reason ResourceURI is.
const DashboardResourceURI = "ui://mctl-telegram/dashboard"

// DashboardVersion is the build recorded for the dashboard document. The
// URI does not change; drift is caught by TestDashboardHTMLContentHash.
const DashboardVersion = "0.1.0"

//go:embed dashboard.html
var dashboardHTML string

// DashboardResource is the MCP Apps resource for the tile dashboard.
// The CSP domain lists are empty: the document talks to the host over
// postMessage and opens no origin of its own.
func DashboardResource() mcplib.Resource {
	return mcplib.Resource{
		URI:         DashboardResourceURI,
		Name:        "telegram-dashboard",
		Title:       "Telegram dashboard",
		Description: "Tile dashboard driven by tg-dashboard/v1 templates. Reads dialogs, folders, topics and messages. mark_read and save_draft go through prepare_dashboard_action; send and delete are not available.",
		MIMEType:    MIMEType,
		Meta:        mcplib.NewMetaFromMap(uiResourceMeta()),
	}
}
