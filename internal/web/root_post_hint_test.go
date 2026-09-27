package web

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRootPostHint confirms POST / returns 405 with a JSON-RPC-parseable
// body naming the configured MCP path, and that GET / (the landing page) is
// unaffected by mounting the POST handler alongside it.
func TestRootPostHint(t *testing.T) {
	rec := httptest.NewRecorder()
	RootPostHint("/mcp").ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))

	if rec.Code != 405 {
		t.Fatalf("POST / status = %d, want 405", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	var body struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not valid JSON-RPC: %v; body=%s", err, rec.Body.String())
	}
	if body.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want 2.0", body.JSONRPC)
	}
	if body.Error.Code != -32600 {
		t.Errorf("error.code = %d, want -32600", body.Error.Code)
	}
	if !strings.Contains(body.Error.Message, "/mcp") {
		t.Errorf("error.message = %q, want it to name /mcp", body.Error.Message)
	}

	// GET / must still serve the landing page, unaffected by the POST route.
	getRec := httptest.NewRecorder()
	Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true).
		ServeHTTP(getRec, httptest.NewRequest("GET", "/", nil))
	if getRec.Code != 200 {
		t.Fatalf("GET / status = %d, want 200", getRec.Code)
	}
	if ct := getRec.Header().Get("Content-Type"); strings.Contains(ct, "application/json") {
		t.Errorf("GET / Content-Type = %q, should not be JSON", ct)
	}
}
