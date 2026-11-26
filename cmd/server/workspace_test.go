package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/config"
	mcpapp "github.com/mctlhq/mctl-telegram/internal/mcp"
)

func TestWorkspaceRoutesReachOnlyApprovedPaths(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := serverRoutes(&config.Config{ToolFilter: config.TelegramWorkspaceReadOnly, MCPPath: "/mcp"}, next)
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/mcp", http.StatusNoContent},
		{"/.well-known/oauth-protected-resource/mcp", http.StatusNoContent},
		{"/oauth/token", http.StatusNoContent},
		{"/oauth/revoke", http.StatusNoContent},
		{"/readyz", http.StatusNoContent},
		{"/", http.StatusNotFound},
		{"/%6dcp", http.StatusNotFound},
		{"/mcp/../oauth/token", http.StatusNotFound},
		{"/api/account", http.StatusNotFound},
		{"/api/agent/token", http.StatusNotFound},
		{"/oauth/demo/login", http.StatusNotFound},
		{"/oauth/telegram/enable_access/start", http.StatusNotFound},
		{"/local-bridge/activate", http.StatusNotFound},
		{"/bridge", http.StatusNotFound},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code != tc.want {
			t.Errorf("%s status %d, want %d", tc.path, w.Code, tc.want)
		}
	}
}

func TestWorkspaceHTTPRequiresIsolatedOAuthIdentity(t *testing.T) {
	const issuerURL = "https://workspace.example.test"
	const audience = "workspace"
	const alice = 8511
	const bob = 8512
	key := []byte("synthetic-workspace-signing-key")
	store := openRevocationWiringStore(t, true)
	provider, err := localjwt.NewProvider(store, localjwt.ProviderConfig{
		Secret: key, ExpectedIssuer: issuerURL, ExpectedAudience: audience, AudienceRequired: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		ToolFilter: config.TelegramWorkspaceReadOnly, TGLoginClients: []int64{alice},
		MCPPath: "/workspace/mcp", PublicBaseURL: issuerURL, MCPResourceBaseURL: "https://tg.example.test",
	}
	mcpURL := cfg.MCPBaseURL() + cfg.MCPPath
	srv := &mcpapp.Server{Store: store, AppsEnabled: true, ToolFilter: cfg.ToolFilter}
	factory := auth.MCPMiddleware(workspaceMCPProvider(cfg, provider), true, nil, auth.ResourceMetadata{BaseURL: cfg.MCPBaseURL(), MCPPath: cfg.MCPPath})
	handler := serverRoutes(cfg, factory(srv.HTTPHandler()))
	body := `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"ui://mctl-telegram/workspace-1.html"}}`
	for _, tc := range []struct {
		name, issuer string
		audience     string
		id           int64
		scopes       []string
		want         int
	}{
		{"valid", issuerURL, audience, alice, workspaceOAuthScopes(cfg), http.StatusOK},
		{"anonymous", "", "", 0, nil, http.StatusUnauthorized},
		{"wrong issuer", "https://another.example.test", audience, alice, workspaceOAuthScopes(cfg), http.StatusUnauthorized},
		{"wrong audience", issuerURL, "another", alice, workspaceOAuthScopes(cfg), http.StatusUnauthorized},
		{"foreign identity", issuerURL, audience, bob, workspaceOAuthScopes(cfg), http.StatusUnauthorized},
		{"excess scope", issuerURL, audience, alice, []string{"telegram:messages:send"}, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, mcpURL, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			if tc.issuer != "" {
				issuer, err := localjwt.NewIssuer(key, tc.issuer)
				if err != nil {
					t.Fatal(err)
				}
				token, err := issuer.Mint(localjwt.Claims{
					Subject: "synthetic", TelegramID: tc.id, Audience: []string{tc.audience}, Scopes: tc.scopes,
				}, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+token)
			}
			if tc.want == http.StatusOK {
				init := httptest.NewRequest(http.MethodPost, mcpURL, strings.NewReader(
					`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"workspace-test","version":"1"}}}`))
				init.Header = req.Header.Clone()
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, init)
				if w.Code != http.StatusOK || w.Header().Get("Mcp-Session-Id") == "" {
					t.Fatalf("initialize status %d, expected authenticated session", w.Code)
				}
				req.Header.Set("Mcp-Session-Id", w.Header().Get("Mcp-Session-Id"))
				req.Header.Set("MCP-Protocol-Version", "2025-11-25")
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatalf("status %d, want %d", w.Code, tc.want)
			}
			if tc.want == http.StatusUnauthorized && !strings.Contains(w.Header().Get("WWW-Authenticate"),
				`resource_metadata="https://tg.example.test/.well-known/oauth-protected-resource/workspace/mcp"`) {
				t.Fatal("401 challenge did not advertise the branded protected-resource metadata")
			}
			if tc.want == http.StatusOK && !strings.Contains(w.Body.String(), "text/html;profile=mcp-app") {
				t.Fatal("authenticated request did not return workspace HTML")
			}
		})
	}
}

func TestWorkspaceBrandedRoutesKeepOAuthAndMCPOnSeparateHosts(t *testing.T) {
	cfg := &config.Config{
		ToolFilter:         config.TelegramWorkspaceReadOnly,
		PublicBaseURL:      "https://workspace-auth.example.test",
		MCPResourceBaseURL: "https://tg.example.test",
		MCPPath:            "/workspace/mcp",
	}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := serverRoutes(cfg, next)
	for _, tc := range []struct {
		host, path string
		want       int
	}{
		{"tg.example.test", "/workspace/mcp", http.StatusNoContent},
		{"tg.example.test", "/.well-known/oauth-protected-resource/workspace/mcp", http.StatusNoContent},
		{"workspace-auth.example.test", "/workspace/mcp", http.StatusNotFound},
		{"tg.example.test", "/oauth/token", http.StatusNotFound},
		{"workspace-auth.example.test", "/oauth/token", http.StatusNoContent},
		{"workspace-auth.example.test", "/.well-known/oauth-authorization-server", http.StatusNoContent},
		{"workspace-auth.example.test", "/.well-known/oauth-protected-resource", http.StatusNotFound},
		{"tg.example.test", "/.well-known/oauth-protected-resource", http.StatusNotFound},
		{"tg.example.test", "/mcp", http.StatusNotFound},
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://"+tc.host+tc.path, nil))
		if w.Code != tc.want {
			t.Errorf("%s%s status %d, want %d", tc.host, tc.path, w.Code, tc.want)
		}
	}
}
