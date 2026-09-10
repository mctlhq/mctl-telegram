package mcpprobe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// authSurface is a fake authorization surface plus a recorder. It answers
// discovery, and it remembers every request it received so a test can assert
// what the probe did *not* do — which is the whole point of the credential
// guarantee.
type authSurface struct {
	mu       sync.Mutex
	requests []recordedRequest

	authMethods []string
	mcpPath     string
	omitPRM     bool
	challenge   string
}

type recordedRequest struct {
	method string
	path   string
	body   string
	header http.Header
}

func (a *authSurface) record(r *http.Request) {
	body := make([]byte, 0)
	if r.Body != nil {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		body = buf[:n]
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, recordedRequest{
		method: r.Method, path: r.URL.Path, body: string(body), header: r.Header.Clone(),
	})
}

func (a *authSurface) recorded() []recordedRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]recordedRequest(nil), a.requests...)
}

func (a *authSurface) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.record(r)
	base := "http://" + r.Host
	switch {
	case strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource"):
		if a.omitPRM {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]any{
			"resource":              base + a.mcpPath,
			"authorization_servers": []string{base},
			"scopes_supported":      []string{"telegram:messages:read"},
		})
	case r.URL.Path == "/.well-known/oauth-authorization-server":
		writeJSON(w, map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/oauth/authorize",
			"token_endpoint":                        base + "/oauth/token",
			"registration_endpoint":                 base + "/oauth/register",
			"token_endpoint_auth_methods_supported": a.authMethods,
			"code_challenge_methods_supported":      []string{"S256"},
		})
	case r.URL.Path == a.mcpPath:
		challenge := a.challenge
		if challenge == "" {
			challenge = `Bearer realm="mctl-telegram", resource_metadata="` +
				base + "/.well-known/oauth-protected-resource" + a.mcpPath + `"`
		}
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func newAuthSurface(t *testing.T, configure func(*authSurface)) (*authSurface, string) {
	t.Helper()
	a := &authSurface{mcpPath: "/mcp", authMethods: []string{"none"}}
	if configure != nil {
		configure(a)
	}
	ts := httptest.NewServer(a)
	t.Cleanup(ts.Close)
	return a, ts.URL + a.mcpPath
}

// TestOAuthProbe_ReadsDiscoveryAndChallenge covers the happy path of the
// authorization surface probe.
func TestOAuthProbe_ReadsDiscoveryAndChallenge(t *testing.T) {
	_, url := newAuthSurface(t, nil)

	report := probeOAuth(context.Background(), http.DefaultClient, url)

	if report.ProtectedResource.Outcome != OutcomePass {
		t.Errorf("root protected-resource = %+v", report.ProtectedResource)
	}
	if report.ProtectedResourcePath.Outcome != OutcomePass {
		t.Errorf("path-variant protected-resource = %+v", report.ProtectedResourcePath)
	}
	as := report.AuthorizationServer
	if as.Outcome != OutcomePass || !as.PKCES256 || !as.TokenEndpoint || !as.RegistrationEndpoint {
		t.Errorf("authorization server = %+v", as)
	}
	if !as.SupportsPublicClient || as.RequiresClientCredential {
		t.Errorf("public-client classification wrong: %+v", as)
	}
	ch := report.Unauthenticated
	if ch.Outcome != OutcomePass || !ch.BearerScheme || !ch.ResourceMetadataPresent || !ch.ResourceMetadataMatches {
		t.Errorf("challenge = %+v", ch)
	}
	if ch.Realm != "mctl-telegram" {
		t.Errorf("realm = %q", ch.Realm)
	}
}

// TestOAuthProbe_ClassifiesACredentialRequiringServer is the go/no-go signal
// the compatibility gate turns on. A server that will not accept a public
// client must be reported as such, plainly, so the decision that follows is
// a deliberate one rather than an accident of configuration.
func TestOAuthProbe_ClassifiesACredentialRequiringServer(t *testing.T) {
	surface, url := newAuthSurface(t, func(a *authSurface) {
		// Two credential-bearing methods and no public-client option.
		a.authMethods = []string{"client_" + "secret_post", "client_" + "secret_basic"}
	})

	report := probeOAuth(context.Background(), http.DefaultClient, url)
	as := report.AuthorizationServer

	if as.SupportsPublicClient {
		t.Error("a server advertising no public-client method was classified as supporting one")
	}
	if !as.RequiresClientCredential {
		t.Error("a credential-requiring server was not flagged")
	}
	if len(as.TokenEndpointAuthMethods) != 2 {
		t.Errorf("advertised methods = %v, want both echoed verbatim", as.TokenEndpointAuthMethods)
	}
	// Classification must not turn into participation: the probe learns the
	// server wants a credential and stops there.
	for _, r := range surface.recorded() {
		if strings.Contains(r.path, "/oauth/token") || strings.Contains(r.path, "/oauth/register") {
			t.Errorf("probe contacted %s %s after classifying the server", r.method, r.path)
		}
	}
}

// TestOAuthProbe_ReportsAMissingChallengePointer keeps a discovery gap
// visible instead of letting a 401 alone stand in for conformance.
func TestOAuthProbe_ReportsAMissingChallengePointer(t *testing.T) {
	_, url := newAuthSurface(t, func(a *authSurface) {
		a.challenge = `Bearer realm="mctl-telegram"`
	})

	report := probeOAuth(context.Background(), http.DefaultClient, url)
	if report.Unauthenticated.ResourceMetadataPresent {
		t.Error("probe reported a resource_metadata pointer that was not sent")
	}
	if report.Unauthenticated.Outcome != OutcomeFail {
		t.Errorf("challenge outcome = %s, want FAIL", report.Unauthenticated.Outcome)
	}
}

// TestOAuthProbe_ReportsAnUnprotectedEndpoint refuses to paper over the most
// consequential finding this probe can make.
func TestOAuthProbe_ReportsAnUnprotectedEndpoint(t *testing.T) {
	fake, url := newFake(t, func(f *fakeServer) { f.modern = true })
	_ = fake

	report := probeOAuth(context.Background(), http.DefaultClient, url)
	if report.Unauthenticated.Outcome != OutcomeFail {
		t.Errorf("an endpoint that served an unauthenticated caller was not reported: %+v",
			report.Unauthenticated)
	}
}
