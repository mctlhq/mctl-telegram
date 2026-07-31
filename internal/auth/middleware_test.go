package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// noTokenProvider always reports "no identity, no error" — the (nil, nil)
// case Middleware treats as anonymous unless required is true, in which
// case it 401s and writes WWW-Authenticate.
type noTokenProvider struct{}

func (noTokenProvider) Authenticate(_ *http.Request) (*Identity, error) {
	return nil, nil
}

func TestMiddleware_WWWAuthenticate_ResourceMetadataByPath(t *testing.T) {
	cases := []struct {
		name        string
		requestPath string
		want        string
	}{
		{
			name:        "root path gets root PRM document",
			requestPath: "/api/account",
			want:        `Bearer realm="mctl-telegram", resource_metadata="https://tg.mctl.ai/.well-known/oauth-protected-resource"`,
		},
		{
			name:        "MCP path gets /mcp-suffixed PRM document",
			requestPath: "/mcp",
			want:        `Bearer realm="mctl-telegram", resource_metadata="https://tg.mctl.ai/.well-known/oauth-protected-resource/mcp"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rm := ResourceMetadata{BaseURL: "https://tg.mctl.ai", MCPPath: "/mcp"}
			h := Middleware(noTokenProvider{}, true, nil, rm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("handler should not be reached without a token")
			}))
			req := httptest.NewRequest(http.MethodGet, c.requestPath, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != c.want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, c.want)
			}
		})
	}
}

func TestMiddleware_WWWAuthenticate_ZeroValueResourceMetadataOmitsHint(t *testing.T) {
	h := Middleware(noTokenProvider{}, true, nil, ResourceMetadata{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached without a token")
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/account", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	want := `Bearer realm="mctl-telegram"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}
