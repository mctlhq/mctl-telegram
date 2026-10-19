package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/oauth/cimd"
)

// A synthetic platform standing in for an agent platform that publishes a
// Client ID Metadata Document. The host is deliberately absent from the
// implicit-host allowlist: a CIMD client must not need it.
const (
	cimdClientID = "https://platform.example.test/.well-known/oauth-client-id"
	cimdCallback = "https://platform.example.test/api/mcp/oauth/callback"
)

// stubCIMD is a CIMDResolver whose answer a test can change mid-flow, to
// model a document edit or a host taken off the allowlist.
type stubCIMD struct {
	mu    sync.Mutex
	doc   cimd.Document
	err   error
	calls int
}

func (s *stubCIMD) Resolve(_ context.Context, clientID string) (cimd.Document, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return cimd.Document{}, s.err
	}
	if clientID != s.doc.ClientID {
		return cimd.Document{}, cimd.ErrNotAllowed
	}
	return s.doc, nil
}

func (s *stubCIMD) set(doc cimd.Document, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.doc, s.err = doc, err
}

func platformDoc() cimd.Document {
	return cimd.Document{
		ClientID:     cimdClientID,
		ClientName:   "Example Platform",
		RedirectURIs: []string{cimdCallback},
		AuthMethod:   cimd.AuthMethodNone,
	}
}

func withCIMD(r CIMDResolver) func(*Config) {
	return func(c *Config) {
		c.AllowImplicitClient = false
		c.CIMD = r
	}
}

func tokenErrorCode(t *testing.T, body string) string {
	t.Helper()
	var resp map[string]string
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode token error %q: %v", body, err)
	}
	return resp["error"]
}

// TestCIMD_FullFlowAndHostRemoval drives a CIMD client through authorize,
// callback, code exchange and refresh, then refuses its document and checks
// that the next refresh is cut off without touching the database.
func TestCIMD_FullFlowAndHostRemoval(t *testing.T) {
	stub := &stubCIMD{}
	stub.set(platformDoc(), nil)
	srv := newTestServer(t, withCIMD(stub))
	mux := newMockRouter()
	srv.Register(mux)

	resp := authCodeTokensFor(t, srv, mux, cimdClientID, cimdCallback)
	rt, _ := resp["refresh_token"].(string)
	if rt == "" {
		t.Fatal("CIMD client got no refresh_token")
	}
	if got := srv.clientDisplayName(context.Background(), cimdClientID); got != "Example Platform" {
		t.Fatalf("display name = %q, want the document's client_name", got)
	}

	refresh := func(tok string) (int, string) {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}, "client_id": {cimdClientID}}
		rec := doTokenRequest(t, mux, form)
		return rec.Code, rec.Body.String()
	}
	code, body := refresh(rt)
	if code != http.StatusOK {
		t.Fatalf("refresh with a live document: %d %s", code, body)
	}
	var next map[string]any
	_ = json.Unmarshal([]byte(body), &next)
	rt2, _ := next["refresh_token"].(string)

	// The operator removes the host from OAUTH_CIMD_ALLOWED_HOSTS.
	stub.set(platformDoc(), cimd.ErrNotAllowed)
	code, body = refresh(rt2)
	if code != http.StatusBadRequest || tokenErrorCode(t, body) != "invalid_client" {
		t.Fatalf("refresh after host removal: %d %s, want 400 invalid_client", code, body)
	}
	if strings.Contains(body, "not allowed") {
		t.Fatalf("refusal leaked the reason to the caller: %s", body)
	}

	// A rate-limited fetch is retryable, not a verdict on the client.
	stub.set(platformDoc(), cimd.ErrRateLimited)
	code, body = refresh(rt2)
	if code != http.StatusServiceUnavailable || tokenErrorCode(t, body) != "server_error" {
		t.Fatalf("refresh while the document is rate-limited: %d %s, want 503 server_error", code, body)
	}

	// Neither refusal reached the token lookup, so rt2 was neither rotated
	// nor treated as reused: once the host is back, it still works.
	stub.set(platformDoc(), nil)
	if code, body = refresh(rt2); code != http.StatusOK {
		t.Fatalf("refresh after the host is restored: %d %s", code, body)
	}
}

// TestCIMD_AuthorizeRefusals pins each way a CIMD client is refused at
// /oauth/authorize, and that none of them falls through to the DCR or
// implicit-client path.
func TestCIMD_AuthorizeRefusals(t *testing.T) {
	ctx := context.Background()
	pkjwt := platformDoc()
	pkjwt.AuthMethod = cimd.AuthMethodPrivateKeyJWT

	cases := []struct {
		name     string
		doc      cimd.Document
		err      error
		redirect string
	}{
		{"redirect not in document", platformDoc(), nil, "https://platform.example.test/other"},
		{"redirect on another host", platformDoc(), nil, "https://evil.example.test/api/mcp/oauth/callback"},
		{"host not allowed", platformDoc(), cimd.ErrNotAllowed, cimdCallback},
		{"fetch failed", platformDoc(), cimd.ErrFetch, cimdCallback},
		{"invalid document", platformDoc(), cimd.ErrInvalidDocument, cimdCallback},
		{"private_key_jwt not supported yet", pkjwt, nil, cimdCallback},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubCIMD{}
			stub.set(tc.doc, tc.err)
			// Implicit clients on, with the platform host allowlisted: a
			// refused CIMD client must still not be rescued by that path.
			srv := newTestServer(t, func(c *Config) {
				c.CIMD = stub
				c.AllowImplicitClient = true
				c.AllowedImplicitHosts = []string{"platform.example.test", "evil.example.test"}
			})
			if err := srv.validateClient(ctx, cimdClientID, tc.redirect); err == nil {
				t.Fatal("refused CIMD client was accepted")
			}
			if stub.calls == 0 {
				t.Fatal("resolver was never consulted")
			}
		})
	}
}

// TestCIMD_TokenCodeRefusedBeforeConsume checks that a code exchange for a
// CIMD client whose document is refused fails as invalid_client, and that the
// code is not consumed: it is redeemable once the document is usable again.
func TestCIMD_TokenCodeRefusedBeforeConsume(t *testing.T) {
	stub := &stubCIMD{}
	stub.set(platformDoc(), nil)
	srv := newTestServer(t, withCIMD(stub))
	mux := newMockRouter()
	srv.Register(mux)

	verifier, challenge := pkceVerifierAndChallenge()
	cs := obtainAuthorizationCodeFor(t, srv, mux, challenge, cimdClientID, cimdCallback)
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {cs.code}, "client_id": {cimdClientID},
		"redirect_uri": {cimdCallback}, "code_verifier": {verifier},
	}

	stub.set(platformDoc(), cimd.ErrInvalidDocument)
	rec := doTokenRequest(t, mux, form)
	if rec.Code != http.StatusBadRequest || tokenErrorCode(t, rec.Body.String()) != "invalid_client" {
		t.Fatalf("code exchange with a refused document: %d %s", rec.Code, rec.Body.String())
	}
	// A fetch that failed observed nothing about the client: a retryable
	// server error, never invalid_client.
	stub.set(platformDoc(), cimd.ErrFetch)
	rec = doTokenRequest(t, mux, form)
	if rec.Code != http.StatusServiceUnavailable || tokenErrorCode(t, rec.Body.String()) != "server_error" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("code exchange with an unreachable document: %d %s, want 503 server_error with Retry-After", rec.Code, rec.Body.String())
	}

	stub.set(platformDoc(), nil)
	if rec = doTokenRequest(t, mux, form); rec.Code != http.StatusOK {
		t.Fatalf("code was consumed by the refused attempt: %d %s", rec.Code, rec.Body.String())
	}
}

// TestCIMD_OffLeavesURLClientsOnTheOldPath checks that with CIMD off a URL
// client_id is an ordinary unregistered client_id, and that with CIMD on a
// DCR-style client_id never reaches the resolver.
// TestCIMD_AuthorizeHandlerAnswers pins what /oauth/authorize itself sends:
// an unreachable document is a retryable 503 temporarily_unavailable, and a
// redirect_uri the document does not list gets the same generic refusal as
// any other unusable document, without echoing the detail.
func TestCIMD_AuthorizeHandlerAnswers(t *testing.T) {
	authorize := func(t *testing.T, stub *stubCIMD, redirect string) *httptest.ResponseRecorder {
		t.Helper()
		srv := newTestServer(t, withCIMD(stub))
		mux := newMockRouter()
		srv.Register(mux)
		_, challenge := pkceVerifierAndChallenge()
		q := url.Values{
			"response_type": {"code"}, "client_id": {cimdClientID}, "redirect_uri": {redirect},
			"state": {"s"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"},
		}
		rec := httptest.NewRecorder()
		mux.serve("GET", "/oauth/authorize", rec, httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil))
		return rec
	}

	stub := &stubCIMD{}
	stub.set(platformDoc(), cimd.ErrFetch)
	rec := authorize(t, stub, cimdCallback)
	if rec.Code != http.StatusServiceUnavailable || tokenErrorCode(t, rec.Body.String()) != "temporarily_unavailable" || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("unreachable document: %d %s, want 503 temporarily_unavailable with Retry-After", rec.Code, rec.Body.String())
	}

	stub.set(platformDoc(), nil)
	const unlisted = "https://platform.example.test/unlisted"
	rec = authorize(t, stub, unlisted)
	if rec.Code != http.StatusBadRequest || tokenErrorCode(t, rec.Body.String()) != "invalid_client" {
		t.Fatalf("unlisted redirect: %d %s, want 400 invalid_client", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), unlisted) {
		t.Fatalf("refusal echoed the redirect detail: %s", rec.Body.String())
	}
}

// TestCIMD_TokenCodeRechecksRedirect checks that a document which stopped
// listing the code's redirect_uri refuses the exchange before the code is
// consumed, and that an over-long client_id is refused at the token endpoint
// as it is at authorize, without reaching the resolver.
func TestCIMD_TokenCodeRechecksRedirect(t *testing.T) {
	stub := &stubCIMD{}
	stub.set(platformDoc(), nil)
	srv := newTestServer(t, withCIMD(stub))
	mux := newMockRouter()
	srv.Register(mux)

	verifier, challenge := pkceVerifierAndChallenge()
	cs := obtainAuthorizationCodeFor(t, srv, mux, challenge, cimdClientID, cimdCallback)
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {cs.code}, "client_id": {cimdClientID},
		"redirect_uri": {cimdCallback}, "code_verifier": {verifier},
	}
	edited := platformDoc()
	edited.RedirectURIs = []string{"https://platform.example.test/new-callback"}
	stub.set(edited, nil)
	rec := doTokenRequest(t, mux, form)
	if rec.Code != http.StatusBadRequest || tokenErrorCode(t, rec.Body.String()) != "invalid_client" {
		t.Fatalf("code exchange after the redirect left the document: %d %s", rec.Code, rec.Body.String())
	}
	stub.set(platformDoc(), nil)
	if rec = doTokenRequest(t, mux, form); rec.Code != http.StatusOK {
		t.Fatalf("code was consumed by the refused attempt: %d %s", rec.Code, rec.Body.String())
	}

	long := "https://platform.example.test/" + strings.Repeat("a", maxClientIDBytes)
	calls := stub.calls
	rec = doTokenRequest(t, mux, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {long}})
	if rec.Code != http.StatusBadRequest || tokenErrorCode(t, rec.Body.String()) != "invalid_client" {
		t.Fatalf("over-long client_id at refresh: %d %s, want 400 invalid_client", rec.Code, rec.Body.String())
	}
	if stub.calls != calls {
		t.Fatal("an over-long client_id reached the resolver")
	}
}

func TestCIMD_OffLeavesURLClientsOnTheOldPath(t *testing.T) {
	ctx := context.Background()

	off := newTestServer(t, func(c *Config) { c.AllowImplicitClient = false })
	err := off.validateClient(ctx, cimdClientID, cimdCallback)
	if err == nil || !strings.Contains(err.Error(), "unknown client_id") {
		t.Fatalf("CIMD off: got %v, want the unknown client_id refusal", err)
	}

	stub := &stubCIMD{}
	stub.set(platformDoc(), nil)
	on := newTestServer(t, func(c *Config) { c.CIMD = stub })
	if err := on.validateClient(ctx, "claude.ai", "https://claude.ai/cb"); err != nil {
		t.Fatalf("implicit client broke with CIMD on: %v", err)
	}
	if stub.calls != 0 {
		t.Fatalf("resolver consulted %d times for a non-URL client_id", stub.calls)
	}
}

// TestCIMD_RealResolverRefusesUnlistedHostOffline wires the concrete resolver
// and checks that a host off the allowlist is refused before any network
// access (the HTTP client here fails every request).
func TestCIMD_RealResolverRefusesUnlistedHostOffline(t *testing.T) {
	r := cimd.NewResolver(cimd.Options{
		AllowedHosts: []string{"other.example.test"},
		HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Error("resolver reached the network for a host off the allowlist")
			return nil, errors.New("offline")
		})},
	})
	srv := newTestServer(t, withCIMD(r))
	if err := srv.validateClient(context.Background(), cimdClientID, cimdCallback); !errors.Is(err, errCIMDRefused) {
		t.Fatalf("got %v, want errCIMDRefused", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
