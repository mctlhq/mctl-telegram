package mcpprobe_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
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

// toolCallRecorder records the `name` param of every tools/call a fixture
// received, so a test can assert on which tools were actually invoked rather
// than only on what the probe reports about itself.
type toolCallRecorder struct {
	mu    sync.Mutex
	names []string
}

func (r *toolCallRecorder) add(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = append(r.names, name)
}

func (r *toolCallRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.names...)
}

// newHeaderTolerantFixture is deliberately NOT an mcp-go server: it answers
// JSON-RPC without enforcing the SEP-2243 Mcp-Method / Mcp-Name /
// Mcp-Protocol-Version headers at all, and dispatches every tools/call it
// receives. That is the exact target class mcpprobe exists to survey -- a
// server that ignores the header contract -- and the only fixture against
// which the probe's own "never name a guard-refused tool" obligation is
// observable: newFixtureServer's real mcp-go server rejects the
// header-negative battery before dispatch, so it would look identical
// whether or not the probe substituted the sentinel tool name.
//
// It advertises exactly one tool, non-read-only, so the read-only guard has
// to refuse it. The returned recorder holds every tools/call name seen.
func newHeaderTolerantFixture(t *testing.T) (*httptest.Server, *toolCallRecorder) {
	t.Helper()

	rec := &toolCallRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     any            `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "malformed JSON-RPC request", http.StatusBadRequest)
			return
		}

		switch req.Method {
		case string(mcplib.MethodServerDiscover):
			writeRPCResult(t, w, req.ID, map[string]any{
				"supportedVersions": []string{mcplib.ProtocolVersion20260728},
			})
		case string(mcplib.MethodToolsList):
			writeRPCResult(t, w, req.ID, map[string]any{
				"tools": []map[string]any{{
					"name":        "send_message",
					"annotations": map[string]any{"readOnlyHint": false},
				}},
			})
		case string(mcplib.MethodToolsCall):
			name, _ := req.Params["name"].(string)
			rec.add(name)
			writeRPCResult(t, w, req.ID, map[string]any{"isError": false})
		default:
			writeRPCError(t, w, req.ID, mcplib.METHOD_NOT_FOUND, "method not found")
		}
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func writeRPCResult(t *testing.T, w http.ResponseWriter, id any, result map[string]any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}); err != nil {
		t.Errorf("encode JSON-RPC result: %v", err)
	}
}

func writeRPCError(t *testing.T, w http.ResponseWriter, id any, code int, message string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": message},
	}); err != nil {
		t.Errorf("encode JSON-RPC error: %v", err)
	}
}
