package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// FirstCallRecorder is the slice of *connectfunnel.Tracker the MCP server
// uses: one successful call by (userID, clientID).
type FirstCallRecorder interface {
	Called(ctx context.Context, userID int64, clientID string)
}

// WithConnectFunnel wires the connect first-call funnel (issue #960).
func (s *Server) WithConnectFunnel(f FirstCallRecorder) *Server {
	s.FirstCall = f
	return s
}

// firstCallHooks adds the funnel's observers to hooks. A tools/list answered
// at all, or a tools/call whose result is not an error, is the "successful
// MCP call" a grant is waiting for: it proves the client got past discovery
// with the token it was just issued. A tools/call that reached a handler and
// came back IsError does not count; it says nothing about whether the
// connector works, only that the tool refused. JSON-RPC-level failures never
// reach the after-hooks.
func (s *Server) firstCallHooks(hooks *mcpserver.Hooks) *mcpserver.Hooks {
	if s.FirstCall == nil {
		return hooks
	}
	hooks.AddAfterListTools(func(ctx context.Context, _ any, _ *mcplib.ListToolsRequest, _ *mcplib.ListToolsResult) {
		s.recordFirstCall(ctx)
	})
	hooks.AddAfterCallTool(func(ctx context.Context, _ any, _ *mcplib.CallToolRequest, result any) {
		if r, ok := result.(*mcplib.CallToolResult); ok && r != nil && r.IsError {
			return
		}
		s.recordFirstCall(ctx)
	})
	return hooks
}

func (s *Server) recordFirstCall(ctx context.Context) {
	id := auth.From(ctx)
	if id == nil {
		return
	}
	s.FirstCall.Called(context.WithoutCancel(ctx), id.UserID, id.ClientID)
}
