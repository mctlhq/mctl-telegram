package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/oauth"
)

func TestProtectedResource_ScopesMatchDCRNegotiableScopes(t *testing.T) {
	cfg := &config.Config{PublicBaseURL: "https://tg.mctl.ai", MCPPath: "/mcp"}
	h := protectedResource(cfg, "https://tg.mctl.ai")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	var meta protectedResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !reflect.DeepEqual(meta.ScopesSupported, oauth.DCRNegotiableScopes) {
		t.Errorf("scopes_supported = %v, want %v", meta.ScopesSupported, oauth.DCRNegotiableScopes)
	}
}

func TestProtectedResource_OmitsMctlAndAdminUsers(t *testing.T) {
	cfg := &config.Config{PublicBaseURL: "https://tg.mctl.ai", MCPPath: "/mcp"}
	h := protectedResource(cfg, "https://tg.mctl.ai")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	var meta protectedResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&meta); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, bogus := range []string{"mctl", "admin:users"} {
		for _, got := range meta.ScopesSupported {
			if got == bogus {
				t.Errorf("scopes_supported must not include %q (never DCR-negotiable — see oauth.DCRNegotiableScopes)", bogus)
			}
		}
	}
}

func TestProtectedResource_ResourceByPath(t *testing.T) {
	cfg := &config.Config{PublicBaseURL: "https://tg.mctl.ai", MCPPath: "/mcp"}
	h := protectedResource(cfg, "https://tg.mctl.ai")

	cases := []struct {
		path         string
		wantResource string
	}{
		{"/.well-known/oauth-protected-resource", "https://tg.mctl.ai"},
		{"/.well-known/oauth-protected-resource/mcp", "https://tg.mctl.ai/mcp"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, c.path, nil)
		rec := httptest.NewRecorder()
		h(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", c.path, rec.Code)
		}
		var meta protectedResourceMetadata
		if err := json.NewDecoder(rec.Body).Decode(&meta); err != nil {
			t.Fatalf("%s: decode: %v", c.path, err)
		}
		if meta.Resource != c.wantResource {
			t.Errorf("%s: resource = %q, want %q", c.path, meta.Resource, c.wantResource)
		}
		if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "https://tg.mctl.ai" {
			t.Errorf("%s: authorization_servers = %v, want [https://tg.mctl.ai]", c.path, meta.AuthorizationServers)
		}
	}
}
