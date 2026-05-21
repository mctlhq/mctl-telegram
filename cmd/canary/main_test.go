package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/push"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

func TestProbeOAuthMetadataInvalidURL(t *testing.T) {
	// Fields present but not URLs → should fail validation.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 "not-a-url",
			"authorization_endpoint": "https://example.com/auth",
			"token_endpoint":         "https://example.com/token",
		})
	}))
	defer srv.Close()

	err := probeOAuthMetadata(t.Context(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected non-nil error for non-URL issuer")
	}
	if !strings.Contains(err.Error(), "issuer") {
		t.Errorf("error should mention issuer, got: %v", err)
	}
}

func TestProbeOAuthMetadataHTTPIssuerRejected(t *testing.T) {
	// RFC 8414: issuer must use https. http:// must be rejected.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                 "http://example.com",
			"authorization_endpoint": "https://example.com/auth",
			"token_endpoint":         "https://example.com/token",
		})
	}))
	defer srv.Close()

	err := probeOAuthMetadata(t.Context(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected non-nil error for http:// issuer (RFC 8414 requires https)")
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

// --- T2: initMCPSession probe ---

func TestInitMCPSessionSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req jsonRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method != "initialize" {
			http.Error(w, "unexpected method", http.StatusBadRequest)
			return
		}
		w.Header().Set("Mcp-Session-Id", "test-session-123")
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  map[string]any{"protocolVersion": "2024-11-05"},
		})
	}))
	defer srv.Close()

	sid, err := initMCPSession(t.Context(), srv.Client(), srv.URL, "/mcp", "token")
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if sid != "test-session-123" {
		t.Errorf("expected session ID %q, got %q", "test-session-123", sid)
	}
}

func TestInitMCPSessionMissingHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}})
	}))
	defer srv.Close()

	_, err := initMCPSession(t.Context(), srv.Client(), srv.URL, "/mcp", "token")
	if err == nil {
		t.Fatal("expected error when Mcp-Session-Id header is absent")
	}
}

func TestInitMCPSessionNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := initMCPSession(t.Context(), srv.Client(), srv.URL, "/mcp", "bad-token")
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
}

// --- T3: probeMCPTool probe ---

func TestProbeMCPToolSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, validMCPResponse())
	}))
	defer srv.Close()

	result, err := probeMCPTool(t.Context(), srv.Client(), srv.URL, "/mcp", "token", "sess-1", "list_dialogs", map[string]any{"limit": 5})
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

	_, err := probeMCPTool(t.Context(), srv.Client(), srv.URL, "/mcp", "token", "sess-1", "list_dialogs", map[string]any{"limit": 5})
	if err == nil {
		t.Fatal("expected non-nil error for JSON-RPC error response")
	}
}

func TestProbeMCPToolFloodWait_SuccessIsError(t *testing.T) {
	// isError=true with FLOOD_WAIT in content → floodWait=true, error returned.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result": map[string]any{
				"content": []map[string]any{{"type": "text", "text": "FLOOD_WAIT_30"}},
				"isError": true,
			},
		})
	}))
	defer srv.Close()

	result, err := probeMCPTool(t.Context(), srv.Client(), srv.URL, "/mcp", "token", "sess-1", "list_dialogs", map[string]any{"limit": 5})
	if err == nil {
		t.Fatal("expected non-nil error for isError=true FLOOD_WAIT response")
	}
	if result == nil || !result.floodWait {
		t.Errorf("expected floodWait=true, got result=%v", result)
	}
}

func TestProbeMCPToolFloodWait_NotErrorWhenIsErrorFalse(t *testing.T) {
	// isError=false: content that mentions FLOOD_WAIT_ is user data, not an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	result, err := probeMCPTool(t.Context(), srv.Client(), srv.URL, "/mcp", "token", "sess-1", "list_dialogs", map[string]any{"limit": 5})
	if err != nil {
		t.Fatalf("expected nil error when isError=false, got: %v", err)
	}
	if result == nil || result.floodWait {
		t.Errorf("expected floodWait=false for isError=false, got result=%v", result)
	}
}

func TestProbeMCPToolFloodWait_JSONRPCError(t *testing.T) {
	// JSON-RPC error with FLOOD_WAIT in message → floodWait=true.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"error": map[string]any{
				"code":    -32603,
				"message": "FLOOD_WAIT_60: flood wait",
			},
		})
	}))
	defer srv.Close()

	result, err := probeMCPTool(t.Context(), srv.Client(), srv.URL, "/mcp", "token", "sess-1", "list_dialogs", map[string]any{"limit": 5})
	if err == nil {
		t.Fatal("expected non-nil error for FLOOD_WAIT JSON-RPC error")
	}
	if result == nil || !result.floodWait {
		t.Errorf("expected floodWait=true, got result=%v", result)
	}
}

// --- T4: Integration tests ---

// newFakeServer builds a single httptest.Server that handles both the OAuth
// metadata path and the MCP path. The mcpHandler receives only tools/call
// requests; initialize requests are handled automatically (session ID returned).
func newFakeServer(t *testing.T, oauthHandler http.HandlerFunc, mcpHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", oauthHandler)
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		// Route initialize to built-in handler; forward everything else.
		var req struct {
			Method string `json:"method"`
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
		_ = json.Unmarshal(body, &req)
		if req.Method == "initialize" {
			w.Header().Set("Mcp-Session-Id", "fake-session-id")
			writeJSON(w, http.StatusOK, map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"result":  map[string]any{"protocolVersion": "2024-11-05"},
			})
			return
		}
		// Re-inject the already-read body for the delegate handler.
		r.Body = io.NopCloser(bytes.NewReader(body))
		mcpHandler(w, r)
	})
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
