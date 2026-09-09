package mcpprobe_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/mcpprobe"
)

// newOAuthFixtureServer serves the well-known metadata endpoints plus a
// bearer-gated /mcp that returns mctl-telegram's real 401 challenge shape
// (WWW-Authenticate: Bearer ..., resource_metadata="...").
func newOAuthFixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resource":"https://tg.test/mcp"}`))
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"issuer": "https://tg.test",
			"token_endpoint_auth_methods_supported": ["none"]
		}`))
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mctl-telegram", resource_metadata="https://tg.test/.well-known/oauth-protected-resource"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	httpServer := httptest.NewServer(mux)
	t.Cleanup(httpServer.Close)
	return httpServer
}

// T7 (partial; the OAuth half of the metadata/401 test list): protected-
// resource and authorization-server metadata are collected, the 401
// challenge is classified, and token_endpoint_auth_methods_supported is
// recorded so Cloudflare public-client compatibility can be assessed
// (requirements.md acceptance criterion E).
func TestProbeOAuth_MetadataAndChallenge(t *testing.T) {
	srv := newOAuthFixtureServer(t)

	result, err := mcpprobe.ProbeOAuth(context.Background(), mcpprobe.OAuthProbeConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("ProbeOAuth: %v", err)
	}

	if result.ProtectedResourceHTTPStatus != http.StatusOK {
		t.Errorf("protected-resource status = %d, want 200", result.ProtectedResourceHTTPStatus)
	}
	if result.AuthorizationServerHTTPStatus != http.StatusOK {
		t.Errorf("authorization-server status = %d, want 200", result.AuthorizationServerHTTPStatus)
	}
	if result.Issuer != "https://tg.test" {
		t.Errorf("issuer = %q, want https://tg.test", result.Issuer)
	}
	if !result.PublicClientPKCECompatible {
		t.Error("PublicClientPKCECompatible = false, want true (token_endpoint_auth_methods_supported includes \"none\")")
	}
	if !result.AuthenticatedProbeSkipped {
		t.Error("AuthenticatedProbeSkipped = false, want true when no bearer token was configured")
	}

	if result.Unauthenticated401 == nil {
		t.Fatal("Unauthenticated401 missing")
	}
	if result.Unauthenticated401.HTTPStatus != http.StatusUnauthorized {
		t.Errorf("401 challenge status = %d, want 401", result.Unauthenticated401.HTTPStatus)
	}
	if !result.Unauthenticated401.HasWWWAuthenticateHeader {
		t.Error("expected WWW-Authenticate header to be recorded as present")
	}
	if !result.Unauthenticated401.WWWAuthenticateIsBearer {
		t.Error("expected WWW-Authenticate to be classified as a Bearer challenge")
	}
	if !result.Unauthenticated401.HasResourceMetadataParam {
		t.Error("expected resource_metadata param to be recorded as present")
	}
}
