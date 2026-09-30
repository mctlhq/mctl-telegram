package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// parseAllowMethodSet reads every "Allow" header value (chi's own 405
// responder calls Header.Add once per method, so there can be several
// single-token Allow headers rather than one comma-joined value — a plain
// Header.Get would silently see only the first), splits each on ',' in case
// a handler like RootPostHint sends one joined value instead, and returns the
// trimmed, sorted method set. Set comparison, not a literal string compare:
// chi's own Allow ordering is not contractual (built from an internal method
// map).
func parseAllowMethodSet(t *testing.T, h http.Header) []string {
	t.Helper()
	var methods []string
	for _, v := range h.Values("Allow") {
		for _, m := range strings.Split(v, ",") {
			m = strings.TrimSpace(m)
			if m == "" {
				continue
			}
			methods = append(methods, m)
		}
	}
	sort.Strings(methods)
	return methods
}

func assertMethodSet(t *testing.T, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("method set = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("method set = %v, want %v", got, want)
		}
	}
}

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
	// Set-based, order-insensitive: RootPostHint's own Allow value is a
	// literal "GET, POST", but T7 compares it against chi's computed Allow
	// for PUT/DELETE/HEAD, whose ordering is not contractual.
	assertMethodSet(t, parseAllowMethodSet(t, rec.Header()), "GET", "POST")

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

// TestRootPostHint_MatchesChiMethodNotAllowed confirms that chi's own 405 for
// an unrouted method on "/" (PUT, DELETE, HEAD) lists the same method set as
// RootPostHint's own Allow header — both GET and POST are registered on "/",
// so chi's computed Allow must agree with the hint handler's, not just with
// the bare GET chi would compute if POST were unregistered.
func TestRootPostHint_MatchesChiMethodNotAllowed(t *testing.T) {
	r := chi.NewRouter()
	r.Get("/", Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true))
	r.Post("/", RootPostHint("/mcp"))

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(method, "/", nil))

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s /: status = %d, want 405", method, rec.Code)
			}
			assertMethodSet(t, parseAllowMethodSet(t, rec.Header()), "GET", "POST")
		})
	}
}
