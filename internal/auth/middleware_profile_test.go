package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fixedProvider struct{ id *Identity }

func (p fixedProvider) Authenticate(_ *http.Request) (*Identity, error) { return p.id, nil }

// A profile is enforced on the MCP tool surface only, so every other
// authenticated route must refuse a profiled credential outright, or the
// restricted client keeps its full scopes there (DELETE /api/account, an
// unprofiled worker token). MCPMiddleware is the one opt-in.
func TestMiddleware_ProfiledCredentialOnlyOnMCP(t *testing.T) {
	profiled := &Identity{UserID: 7, Scopes: []string{"account:manage"}, ClientID: "claude.ai", Profile: "core-readonly"}
	plain := &Identity{UserID: 7, Scopes: []string{"account:manage"}, ClientID: "claude.ai"}
	html := func(w http.ResponseWriter, _ *http.Request, status int, _ string) { w.WriteHeader(status) }

	for name, tc := range map[string]struct {
		mw      func(http.Handler) http.Handler
		id      *Identity
		reached bool
	}{
		"Middleware refuses profiled":         {Middleware(fixedProvider{profiled}, true, nil, ResourceMetadata{}), profiled, false},
		"MiddlewareWithHTML refuses profiled": {MiddlewareWithHTML(fixedProvider{profiled}, true, nil, ResourceMetadata{}, html), profiled, false},
		"MCPMiddleware admits profiled":       {MCPMiddleware(fixedProvider{profiled}, true, nil, ResourceMetadata{}), profiled, true},
		"Middleware admits unprofiled":        {Middleware(fixedProvider{plain}, true, nil, ResourceMetadata{}), plain, true},
		"MCPMiddleware admits unprofiled":     {MCPMiddleware(fixedProvider{plain}, true, nil, ResourceMetadata{}), plain, true},
	} {
		t.Run(name, func(t *testing.T) {
			var got *Identity
			reached := false
			h := tc.mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached, got = true, From(r.Context())
			}))
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, "/api/account", nil)
			req.Header.Set("Accept", "application/json")
			h.ServeHTTP(rec, req)
			if reached != tc.reached {
				t.Fatalf("handler reached = %v, want %v (status %d)", reached, tc.reached, rec.Code)
			}
			if !tc.reached {
				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403", rec.Code)
				}
				if strings.Contains(name, "HTML") {
					return
				}
				if !strings.Contains(rec.Body.String(), MsgProfileRestricted) {
					t.Fatalf("body = %s, want %q", rec.Body.String(), MsgProfileRestricted)
				}
				return
			}
			if got == nil || got.Profile != tc.id.Profile {
				t.Fatalf("identity in context = %+v, want profile %q", got, tc.id.Profile)
			}
		})
	}
}
