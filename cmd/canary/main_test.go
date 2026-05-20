package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/client_golang/prometheus/push"
)

// validMCPResponse returns a well-formed JSON-RPC 2.0 success response for a
// tools/call request that returns a single content item.
func validMCPResponse() map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"content": []map[string]any{{"type": "text", "text": "dialog1"}},
			"isError": false,
		},
	}
}

// writeJSON is a test helper that encodes v as JSON into w with status code.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// --- T1: oauth_metadata probe ---

func TestProbeOAuthMetadataValid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 "https://example.com",
			"authorization_endpoint": "https://example.com/auth",
			"token_endpoint":         "https://example.com/token",
		})
	}))
	defer srv.Close()

	err := probeOAuthMetadata(t.Context(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
}

func TestProbeOAuthMetadataMissingField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// token_endpoint is intentionally absent.
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 "https://example.com",
			"authorization_endpoint": "https://example.com/auth",
		})
	}))
	defer srv.Close()

	err := probeOAuthMetadata(t.Context(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected non-nil error for missing token_endpoint")
	}
	if !strings.Contains(err.Error(), "token_endpoint") {
		t.Errorf("error should mention token_endpoint, got: %v", err)
	}
}

func TestProbeOAuthMetadataNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	err := probeOAuthMetadata(t.Context(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected non-nil error for 404 response")
	}
}

// --- T2: list_dialogs / probeMCPTool probe ---

func TestProbeMCPToolSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, validMCPResponse())
	}))
	defer srv.Close()

	result, err := probeMCPTool(t.Context(), srv.Client(), srv.URL, "/mcp", "token", "list_dialogs", map[string]any{"limit": 5})
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.floodWait {
		t.Error("expected floodWait=false")
	}
}

func TestProbeMCPToolJSONRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"error": map[string]any{
				"code":    -32603,
				"message": "internal error",
			},
		})
	}))
	defer srv.Close()

	_, err := probeMCPTool(t.Context(), srv.Client(), srv.URL, "/mcp", "token", "list_dialogs", map[string]any{"limit": 5})
	if err == nil {
		t.Fatal("expected non-nil error for JSON-RPC error response")
	}
}

func TestProbeMCPToolFloodWait(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a success-shaped response whose content text mentions FLOOD_WAIT_30.
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"content": []map[string]any{{"type": "text", "text": "FLOOD_WAIT_30"}},
				"isError": false,
			},
		})
	}))
	defer srv.Close()

	result, err := probeMCPTool(t.Context(), srv.Client(), srv.URL, "/mcp", "token", "list_dialogs", map[string]any{"limit": 5})
	if err == nil {
		t.Fatal("expected non-nil error for FLOOD_WAIT response")
	}
	if result == nil || !result.floodWait {
		t.Errorf("expected floodWait=true, got result=%v", result)
	}
}

// --- T3: Integration tests ---

// newFakeServer builds a single httptest.Server that handles both the OAuth
// metadata path and the MCP path using the provided handlers.
func newFakeServer(t *testing.T, oauthHandler, mcpHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", oauthHandler)
	mux.HandleFunc("/mcp", mcpHandler)
	return httptest.NewServer(mux)
}

// validOAuthHandler serves a complete OAuth AS metadata document.
func validOAuthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                 "https://example.com",
		"authorization_endpoint": "https://example.com/auth",
		"token_endpoint":         "https://example.com/token",
	})
}

func TestRunAndPushSuccess(t *testing.T) {
	// Fake MCP server returns a valid response.
	fakeSrv := newFakeServer(t,
		validOAuthHandler,
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, validMCPResponse())
		},
	)
	defer fakeSrv.Close()

	// Fake Pushgateway: accept PUT/POST and track that it received a request.
	var pushed atomic.Bool
	fakePGW := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Consume the body.
		_, _ = io.Copy(io.Discard, r.Body)
		pushed.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer fakePGW.Close()

	cfg := &config{
		baseURL:     fakeSrv.URL,
		bearerToken: "test-token",
		tgUserID:    "12345",
		timeout:     5 * time.Second,
		mcpPath:     "/mcp",
		probeUnread: false,
		pushgateway: fakePGW.URL,
		metricsAddr: ":0",
	}
	met := newCanaryMetrics()

	ok := run(t.Context(), cfg, met)
	if !ok {
		t.Fatal("expected run to succeed")
	}

	// Push metrics to the fake pushgateway.
	pusher := push.New(fakePGW.URL, "mctl_telegram_canary").Gatherer(met.registry)
	if err := pusher.Push(); err != nil {
		t.Fatalf("push failed: %v", err)
	}

	if !pushed.Load() {
		t.Error("fake pushgateway did not receive a push request")
	}

	if got := testutil.ToFloat64(met.success); got != 1 {
		t.Errorf("expected mctl_telegram_canary_success=1, got %v", got)
	}
}

func TestRunMetricsListDialogsFailure(t *testing.T) {
	// Fake server: OAuth OK, but MCP returns JSON-RPC error.
	fakeSrv := newFakeServer(t,
		validOAuthHandler,
		func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"error": map[string]any{
					"code":    -32603,
					"message": "internal error from mcp",
				},
			})
		},
	)
	defer fakeSrv.Close()

	cfg := &config{
		baseURL:     fakeSrv.URL,
		bearerToken: "test-token",
		tgUserID:    "12345",
		timeout:     5 * time.Second,
		mcpPath:     "/mcp",
		probeUnread: false,
		pushgateway: "",
		metricsAddr: ":0",
	}
	met := newCanaryMetrics()

	ok := run(t.Context(), cfg, met)
	if ok {
		t.Fatal("expected run to fail")
	}

	if got := testutil.ToFloat64(met.success); got != 0 {
		t.Errorf("expected mctl_telegram_canary_success=0, got %v", got)
	}

	if got := testutil.ToFloat64(met.stepFailures.WithLabelValues("list_dialogs")); got != 1 {
		t.Errorf("expected step_failure_total{step=list_dialogs}=1, got %v", got)
	}
}

// TODO: add a test for the main() push-then-exit code path (the cfg.pushgateway != ""
// branch). Requires extracting the push-and-exit logic from main() into a testable
// function and stubbing the Pushgateway HTTP client.
// Tracking: https://github.com/mctlhq/mctl-telegram/issues/TBD
