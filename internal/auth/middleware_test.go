package auth

import (
	"errors"
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

// failingProvider reports an authentication error — the branch a client hits
// when it presents a token that no longer verifies. The messages used below
// are the literal strings produced by localjwt/sharedhmac, so the test tracks
// what classifyAuthError actually sees in production.
type failingProvider struct{ err error }

func (p failingProvider) Authenticate(_ *http.Request) (*Identity, error) {
	return nil, p.err
}

func TestMiddleware_WWWAuthenticate_OnFailedAuth(t *testing.T) {
	cases := []struct {
		name        string
		requestPath string
		err         error
		want        string
	}{
		{
			name:        "expired token on root path gets root PRM document",
			requestPath: "/api/account",
			err:         errors.New("JWT expired"),
			want:        `Bearer realm="mctl-telegram", resource_metadata="https://tg.mctl.ai/.well-known/oauth-protected-resource", error="invalid_token"`,
		},
		{
			name:        "expired token on MCP path gets /mcp-suffixed PRM document",
			requestPath: "/mcp",
			err:         errors.New("JWT expired"),
			want:        `Bearer realm="mctl-telegram", resource_metadata="https://tg.mctl.ai/.well-known/oauth-protected-resource/mcp", error="invalid_token"`,
		},
		{
			name:        "bad signature is still invalid_token",
			requestPath: "/mcp",
			err:         errors.New("invalid JWT signature"),
			want:        `Bearer realm="mctl-telegram", resource_metadata="https://tg.mctl.ai/.well-known/oauth-protected-resource/mcp", error="invalid_token"`,
		},
		{
			name:        "non-Bearer scheme is a malformed request, not a bad token",
			requestPath: "/mcp",
			err:         errors.New("Authorization header must use Bearer scheme"),
			want:        `Bearer realm="mctl-telegram", resource_metadata="https://tg.mctl.ai/.well-known/oauth-protected-resource/mcp", error="invalid_request"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rm := ResourceMetadata{BaseURL: "https://tg.mctl.ai", MCPPath: "/mcp"}
			h := Middleware(failingProvider{err: c.err}, true, nil, rm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("handler should not be reached when authentication fails")
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

// A deployment with no PublicBaseURL still has to tell the client the token
// was rejected, even though it cannot point at a PRM document.
func TestMiddleware_WWWAuthenticate_FailedAuthWithZeroValueResourceMetadata(t *testing.T) {
	h := Middleware(failingProvider{err: errors.New("JWT expired")}, true, nil, ResourceMetadata{})(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("handler should not be reached when authentication fails")
		}))
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	want := `Bearer realm="mctl-telegram", error="invalid_token"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
}
