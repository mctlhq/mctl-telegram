package mcpprobe

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

// fakeServer is a hand-written MCP endpoint. It exists so the probe's
// negative cases can be asserted against a server whose behaviour the test
// controls exactly, and so a test can prove a rejected request never reached
// dispatch. The in-process test against the real handler wiring lives
// separately, in inprocess_test.go.
type fakeServer struct {
	mu sync.Mutex
	// dispatched counts requests that got past header validation. A
	// well-formed negative case must leave this at zero.
	dispatched []string
	// mintSession makes the legacy initialize hand out a session id.
	mintSession bool
	// requireSession rejects non-initialize requests that arrive without one.
	requireSession bool
	// acceptAnySession models a server that validates the shape of a session
	// identifier but not its existence, so any well-formed value passes.
	// Without it, requireSession models a genuinely session-bound server that
	// only accepts the identifier it issued.
	acceptAnySession bool
	// modern enables the 2026-07-28 binding.
	modern bool
	// legacyOnly makes server/discover an unknown method, which is how a
	// pre-2026-07-28 server behaves.
	legacyOnly bool
	// tools is the inventory tools/list returns.
	tools []fakeTool
	// callPayload is what tools/call answers with. It carries deliberately
	// sensitive-looking values so redaction can be asserted end to end.
	callPayload map[string]any

	lastSession string
}

type fakeTool struct {
	name     string
	readOnly *bool
}

const fakeSessionID = "mcp-session-11111111-2222-3333-4444-555555555555"

func (f *fakeServer) record(method string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dispatched = append(f.dispatched, method)
}

func (f *fakeServer) dispatchedMethods() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dispatched...)
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID     int             `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRPCError(w, http.StatusBadRequest, 0, -32700)
		return
	}
	method := mcp.MCPMethod(body.Method)

	if f.modern {
		if r.Header.Get(mcp.HeaderProtocolVersion) != mcp.ProtocolVersion20260728 {
			writeRPCError(w, http.StatusBadRequest, body.ID, -32020)
			return
		}
		// The SDK's own validator decides these cases, so the fake enforces
		// exactly what a conforming server enforces rather than a
		// hand-rolled approximation of it.
		if err := mcp.ValidateStandardHeaders(r.Header.Get, mcp.ProtocolVersion20260728, method, body.Params); err != nil {
			writeRPCError(w, http.StatusBadRequest, body.ID, -32020)
			return
		}
		if method == mcp.MethodInitialize {
			writeRPCError(w, http.StatusNotFound, body.ID, -32601)
			return
		}
	}

	if f.legacyOnly && method == mcp.MethodServerDiscover {
		// Rejected before record: an unknown method never reaches dispatch.
		writeRPCError(w, http.StatusNotFound, body.ID, -32601)
		return
	}

	if f.requireSession && method != mcp.MethodInitialize {
		got := r.Header.Get(mcp.HeaderSessionID)
		if got == "" || (!f.acceptAnySession && got != fakeSessionID) {
			writeRPCError(w, http.StatusBadRequest, body.ID, -32600)
			return
		}
	}
	f.lastSession = r.Header.Get(mcp.HeaderSessionID)
	f.record(body.Method)

	switch method {
	case mcp.MethodInitialize:
		if f.mintSession {
			w.Header().Set(mcp.HeaderSessionID, fakeSessionID)
		}
		writeRPCResult(w, body.ID, map[string]any{
			"protocolVersion": mcp.ProtocolVersion20250618,
			"capabilities":    map[string]any{},
			"serverInfo":      map[string]any{"name": "fake-telegram", "version": "9.9.9"},
		})
	case mcp.MethodServerDiscover:
		meta := &mcp.Meta{}
		meta.SetServerInfo(mcp.Implementation{Name: "fake-telegram", Version: "9.9.9"})
		writeRPCResult(w, body.ID, map[string]any{
			"supportedVersions": []string{mcp.ProtocolVersion20260728, mcp.ProtocolVersion20250618},
			"capabilities":      map[string]any{},
			"_meta":             meta,
		})
	case mcp.MethodToolsList:
		tools := make([]map[string]any, 0, len(f.tools))
		for _, t := range f.tools {
			entry := map[string]any{"name": t.name, "inputSchema": map[string]any{"type": "object"}}
			if t.readOnly != nil {
				entry["annotations"] = map[string]any{"readOnlyHint": *t.readOnly}
			}
			tools = append(tools, entry)
		}
		writeRPCResult(w, body.ID, map[string]any{"tools": tools})
	case mcp.MethodToolsCall:
		payload := f.callPayload
		if payload == nil {
			payload = map[string]any{
				"content": []map[string]any{{"type": "text", "text": "ok"}},
				"isError": false,
			}
		}
		writeRPCResult(w, body.ID, payload)
	default:
		writeRPCError(w, http.StatusNotFound, body.ID, -32601)
	}
}

func writeRPCResult(w http.ResponseWriter, id int, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeRPCError(w http.ResponseWriter, status, id, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": id,
		"error": map[string]any{"code": code, "message": "rejected"},
	})
}

// newFake starts a fake server and returns it with its URL.
func newFake(t *testing.T, configure func(*fakeServer)) (*fakeServer, string) {
	t.Helper()
	readOnly, mutating := true, false
	f := &fakeServer{
		tools: []fakeTool{
			{name: DefaultTool, readOnly: &readOnly},
			{name: "send_message", readOnly: &mutating},
			{name: "unannotated_tool"},
		},
	}
	if configure != nil {
		configure(f)
	}
	ts := httptest.NewServer(f)
	t.Cleanup(ts.Close)
	return f, ts.URL + "/mcp"
}

// stepByLabel finds a recorded step, failing the test when it is absent.
func stepByLabel(t *testing.T, steps []Step, label string) Step {
	t.Helper()
	for _, s := range steps {
		if s.Label == label {
			return s
		}
	}
	t.Fatalf("no step labelled %q in %v", label, labelsOf(steps))
	return Step{}
}

func labelsOf(steps []Step) []string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Label)
	}
	return out
}

func countMethod(methods []string, want string) int {
	n := 0
	for _, m := range methods {
		if m == want {
			n++
		}
	}
	return n
}

func containsAll(haystack string, needles []string) []string {
	var found []string
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			found = append(found, n)
		}
	}
	return found
}
