// Package mcp wires the three Telegram-user-account MCP tools onto an mcp-go
// streamable HTTP server.
package mcp

import (
	"context"
	"net/http"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

type Server struct {
	Store     *db.Store
	Pool      *telegram.ClientPool
	AllowSend bool
	Confirms  *ConfirmStore
}

func New(store *db.Store, pool *telegram.ClientPool, allowSend bool) *Server {
	return &Server{
		Store:     store,
		Pool:      pool,
		AllowSend: allowSend,
		Confirms:  NewConfirmStore(),
	}
}

func (s *Server) HTTPHandler() http.Handler {
	srv := mcpserver.NewMCPServer(
		"mctl-telegram",
		"0.7.0",
		mcpserver.WithToolCapabilities(true),
	)
	srv.AddTool(s.toolListDialogs())
	srv.AddTool(s.toolGetUnreadMessages())
	srv.AddTool(s.toolGetMessages())
	srv.AddTool(s.toolPrepareSendMessage())
	srv.AddTool(s.toolSendMessage())
	srv.AddTool(s.toolPreparePinMessage())
	srv.AddTool(s.toolPinMessage())
	srv.AddTool(s.toolDisconnectAccount())
	srv.AddTool(s.toolDeleteAccount())
	srv.AddTool(s.toolGetMyAuditLog())

	return mcpserver.NewStreamableHTTPServer(
		srv,
		mcpserver.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			return r.Context()
		}),
	)
}

// Tiny helper used by tool implementations.
func toolErr(format string, a ...any) *mcplib.CallToolResult {
	return mcplib.NewToolResultError(formatErr(format, a...))
}

func formatErr(format string, a ...any) string {
	if len(a) == 0 {
		return format
	}
	return sprintf(format, a...)
}

// sprintf is a thin wrapper to avoid importing fmt in tools.go duplicates.
func sprintf(format string, a ...any) string {
	return fmtSprintfImpl(format, a...)
}
