package web

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

func namedHandler(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, name)
	})
}

// TestRootMCP_Dispatch pins which requests on "/" reach the MCP handler: a
// page load must keep getting the landing page, and every MCP transport
// request (POST, DELETE, the SSE GET) must not.
func TestRootMCP_Dispatch(t *testing.T) {
	h := RootMCP(namedHandler("landing"), namedHandler("mcp"))
	cases := []struct {
		name, method, accept, want string
	}{
		{"browser page load", http.MethodGet, "text/html,application/xhtml+xml,*/*;q=0.8", "landing"},
		{"GET without Accept", http.MethodGet, "", "landing"},
		{"GET json only", http.MethodGet, "application/json", "landing"},
		{"browser that also lists event-stream", http.MethodGet, "text/html, text/event-stream", "landing"},
		{"MCP SSE stream", http.MethodGet, "text/event-stream", "mcp"},
		{"MCP SSE stream mixed case", http.MethodGet, "Application/JSON, Text/Event-Stream", "mcp"},
		{"JSON-RPC POST", http.MethodPost, "application/json, text/event-stream", "mcp"},
		{"POST without Accept", http.MethodPost, "", "mcp"},
		{"session DELETE", http.MethodDelete, "", "mcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/", nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if got := rec.Body.String(); got != tc.want {
				t.Fatalf("%s / with Accept %q went to %q, want %q", tc.method, tc.accept, got, tc.want)
			}
		})
	}
}

// TestRootMCP_SharesSessionWithMCPPath wires the routes the way
// cmd/server/main.go does, with a real Streamable-HTTP server: a client
// configured with the bare origin initializes on "/", and the session it
// gets is valid on /mcp as well, because both paths share one handler.
func TestRootMCP_SharesSessionWithMCPPath(t *testing.T) {
	srv := mcpserver.NewMCPServer("test", "0.0.0")
	srv.AddTool(mcp.NewTool("ping"), func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("pong"), nil
	})
	mcpHandler := mcpserver.NewStreamableHTTPServer(srv)

	r := chi.NewRouter()
	r.Mount("/mcp", BrowserRedirect(mcpHandler, "/"))
	root := RootMCP(Landing("https://tg.example", "/mcp", "https://tg.example", true), mcpHandler)
	r.Get("/", root.ServeHTTP)
	r.Post("/", root.ServeHTTP)
	r.Delete("/", root.ServeHTTP)

	post := func(path, sessionID, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if sessionID != "" {
			req.Header.Set("Mcp-Session-Id", sessionID)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	initRec := post("/", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`)
	if initRec.Code != http.StatusOK {
		t.Fatalf("POST / initialize: status %d, body %s", initRec.Code, initRec.Body.String())
	}
	sid := initRec.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("POST / initialize returned no Mcp-Session-Id")
	}

	for _, path := range []string{"/", "/mcp"} {
		rec := post(path, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ping"`) {
			t.Fatalf("tools/list on %s with the session from /: status %d, body %s", path, rec.Code, rec.Body.String())
		}
	}

	// A page load on "/" is still the landing page.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("GET / page load: status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
}
