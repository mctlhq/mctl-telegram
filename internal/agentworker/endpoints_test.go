package agentworker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/agent/tools"
)

// Every MCP tool calls only routes that tools.Endpoints maps back to it, so
// the agent API's tool gate sees each tool's traffic, and a tool that
// reaches a new route fails here until the map, and so the gate, covers it.
// The other direction (every tool has a route) is pinned in
// internal/agent/tools.
func TestMCPToolsCallOnlyTheirMappedRoutes(t *testing.T) {
	var mu sync.Mutex
	var hits []string
	r := chi.NewRouter()
	for route := range tools.Endpoints {
		method, pattern, _ := strings.Cut(route, " ")
		r.Method(method, pattern, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			hits = append(hits, route)
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}))
	}
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		hits = append(hits, "UNMAPPED "+req.Method+" "+req.URL.Path)
		mu.Unlock()
		http.NotFound(w, req)
	})
	srv := httptest.NewServer(r)
	defer srv.Close()

	args := map[string]map[string]any{
		"get_recruiter_profile":  {"peer_tg_id": 500100202},
		"propose_reply":          {"intent": "discovery", "text": "hello"},
		"save_job_lead":          {"company": "Acme"},
		"request_owner_approval": {"text": "decide"},
		"send_owner_summary":     {"text": "fyi"},
		"complete_agent_job":     {"status": "ignored"},
	}
	for _, canonical := range tools.Canonical {
		t.Run(canonical, func(t *testing.T) {
			mcp, err := NewMCPServer(NewClient(srv.URL, "test-token", srv.Client()),
				JobContext{JobID: 1, Attempt: 1, ConversationID: 2, EventID: "evt:1"})
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			hits = nil
			mu.Unlock()
			st := mcp.GetTool(canonical)
			if st == nil {
				t.Fatalf("tool %q not registered", canonical)
			}
			req := mcplib.CallToolRequest{}
			req.Params.Name = canonical
			req.Params.Arguments = args[canonical]
			if _, err := st.Handler(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(hits) == 0 {
				t.Fatal("tool called no route")
			}
			for _, h := range hits {
				if !slices.Contains(tools.Endpoints[h], canonical) {
					t.Errorf("tool called %s, which tools.Endpoints does not map to it", h)
				}
			}
		})
	}
}
