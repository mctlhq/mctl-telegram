package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
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

func TestWantsJSON(t *testing.T) {
	cases := []struct {
		name     string
		accept   string
		xhr      string
		wantJSON bool
	}{
		{name: "browser chrome", accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8", wantJSON: false},
		{name: "text/html only", accept: "text/html", wantJSON: false},
		{name: "application/json", accept: "application/json", wantJSON: true},
		{name: "json and sse", accept: "application/json, text/event-stream", wantJSON: true},
		{name: "empty", accept: "", wantJSON: true},
		{name: "star", accept: "*/*", wantJSON: true},
		{name: "xhr wins over html", accept: "text/html", xhr: "XMLHttpRequest", wantJSON: true},
		{name: "both html and json prefer json", accept: "text/html, application/json", wantJSON: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
			if c.accept != "" {
				req.Header.Set("Accept", c.accept)
			}
			if c.xhr != "" {
				req.Header.Set("X-Requested-With", c.xhr)
			}
			if got := WantsJSON(req); got != c.wantJSON {
				t.Errorf("WantsJSON = %v, want %v", got, c.wantJSON)
			}
		})
	}
}

func TestMiddlewareWithHTML_BrowserGetsRenderer(t *testing.T) {
	var called bool
	html := func(w http.ResponseWriter, r *http.Request, status int, msg string) {
		called = true
		if status != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", status)
		}
		if msg != "authentication required" {
			t.Errorf("msg = %q, want authentication required", msg)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte("<html>sign in</html>"))
	}
	h := MiddlewareWithHTML(noTokenProvider{}, true, nil, ResourceMetadata{}, html)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("handler should not run")
	}))

	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called {
		t.Fatal("HTML renderer was not used")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Body.String() != "<html>sign in</html>" {
		t.Errorf("body = %q", rec.Body.String())
	}
}

func TestMiddlewareWithHTML_JSONSkipsRenderer(t *testing.T) {
	html := func(http.ResponseWriter, *http.Request, int, string) {
		t.Fatal("HTML renderer must not run for API clients")
	}
	h := MiddlewareWithHTML(failingProvider{err: errors.New("JWT expired")}, true, nil, ResourceMetadata{}, html)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("handler should not run")
		}))

	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Body.String() != "{\"error\":\"invalid credentials\"}\n" {
		t.Errorf("body = %q", rec.Body.String())
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

// Only the HTML-capable middleware negotiates its 401 body, so only it may
// claim a Vary — a plain Middleware always answers JSON and must not tell
// caches otherwise.
func TestMiddlewareWithHTML_DeclaresNegotiationVary(t *testing.T) {
	html := func(w http.ResponseWriter, r *http.Request, status int, msg string) {
		w.WriteHeader(status)
	}
	for _, accept := range []string{"text/html", "application/json"} {
		h := MiddlewareWithHTML(noTokenProvider{}, true, nil, ResourceMetadata{}, html)(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("handler should not run")
			}))
		req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
		req.Header.Set("Accept", accept)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		wantExactNegotiationVary(t, rec.Header(), "Accept "+accept)
	}
}

// The renderer wired in cmd/server/main.go adds the header itself, because it
// also serves direct handler calls that never reach this middleware. On the
// middleware path it therefore runs after writeUnauthorized already added it.
func TestMiddlewareWithHTML_VaryNotDuplicatedByRenderer(t *testing.T) {
	renderer := func(w http.ResponseWriter, r *http.Request, status int, msg string) {
		AddNegotiationVary(w)
		w.WriteHeader(status)
	}
	h := MiddlewareWithHTML(noTokenProvider{}, true, nil, ResourceMetadata{}, renderer)(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("handler should not run")
		}))
	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	wantExactNegotiationVary(t, rec.Header(), "renderer re-adds")
}

// A Vary a compression layer already set must not make AddNegotiationVary
// think Accept is covered — "Accept-Encoding" is a different field name.
func TestAddNegotiationVary_DistinguishesAcceptPrefixedFields(t *testing.T) {
	rec := httptest.NewRecorder()
	rec.Header().Add("Vary", "Accept-Encoding, Accept-Language")
	AddNegotiationVary(rec)

	got := varyTokens(rec.Header())
	want := []string{"Accept-Encoding", "Accept-Language", "Accept", "X-Requested-With"}
	if !slices.Equal(got, want) {
		t.Fatalf("Vary = %v, want %v", got, want)
	}
}

func TestMiddleware_JSONOnlyDoesNotVary(t *testing.T) {
	h := Middleware(noTokenProvider{}, true, nil, ResourceMetadata{})(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("handler should not run")
		}))
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if vary := rec.Header().Values("Vary"); len(vary) != 0 {
		t.Fatalf("Vary = %v, want none for a JSON-only route", vary)
	}
}

// varyTokens flattens the Vary header into its individual field names.
// Asserting on this rather than substring-matching the raw values matters
// twice over: "Accept-Encoding" contains "Accept", and a duplicated append
// is invisible to a Contains check.
func varyTokens(h http.Header) []string {
	var out []string
	for _, v := range h.Values("Vary") {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				out = append(out, http.CanonicalHeaderKey(tok))
			}
		}
	}
	return out
}

func wantExactNegotiationVary(t *testing.T, h http.Header, ctx string) {
	t.Helper()
	got := varyTokens(h)
	want := []string{"Accept", "X-Requested-With"}
	if !slices.Equal(got, want) {
		t.Fatalf("%s: Vary = %v, want exactly %v", ctx, got, want)
	}
}

// The Vary only picks the representation. Keeping a 401 out of caches
// entirely is what stops one being replayed to a caller who has since
// acquired a valid cookie, and it must hold on the JSON arm too — that arm
// previously shipped no Cache-Control at all.
func TestMiddlewareWithHTML_UnauthorizedIsNoStore(t *testing.T) {
	renderer := func(w http.ResponseWriter, r *http.Request, status int, msg string) {
		w.WriteHeader(status)
	}
	for _, accept := range []string{"text/html", "application/json"} {
		h := MiddlewareWithHTML(noTokenProvider{}, true, nil, ResourceMetadata{}, renderer)(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("handler should not run")
			}))
		req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
		req.Header.Set("Accept", accept)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("Accept %q: Cache-Control = %q, want no-store", accept, cc)
		}
	}
}
