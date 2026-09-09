package mcpprobe_test

import (
	"context"
	"net/http/httptest"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// newFixtureServer builds a minimal real mcp-go server (not a hand-rolled
// fake) exposing one read-only tool ("get_my_send_status", mirroring
// mctl-telegram's own real tool) and one non-read-only tool ("send_message"),
// so the read-only guard has something legitimate to refuse. Using the
// pinned SDK's own server, rather than reimplementing MCP wire semantics,
// is what makes T1's "modern request fixture ... against a modern
// fake/server" and T4's "legacy stateful fake" meaningful: the fixture
// enforces the same protocol contract a real deployment does.
func newFixtureServer(t *testing.T, opts ...mcpserver.StreamableHTTPOption) *httptest.Server {
	t.Helper()

	srv := mcpserver.NewMCPServer("mcpprobe-fixture", "1.0.0", mcpserver.WithToolCapabilities(true))
	srv.AddTool(
		mcplib.NewTool("get_my_send_status", mcplib.WithReadOnlyHintAnnotation(true)),
		func(_ context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			return mcplib.NewToolResultText(`{"can_send":true}`), nil
		},
	)
	srv.AddTool(
		mcplib.NewTool("send_message", mcplib.WithReadOnlyHintAnnotation(false)),
		func(_ context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			return mcplib.NewToolResultText("sent"), nil
		},
	)

	httpServer := httptest.NewServer(mcpserver.NewStreamableHTTPServer(srv, opts...))
	t.Cleanup(httpServer.Close)
	return httpServer
}
