package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// portalCallback is a synthetic exact callback standing in for the one an
// enterprise MCP gateway displays. The real production callback is never
// baked into this repository: an operator copies whatever the counterpart's
// dashboard shows into OAUTH_PREREGISTERED_CLIENTS.
const (
	portalClientID = "portal-client"
	portalCallback = "https://portal.example.test/servers-callback"
)

func withPortalClient(c *Config) {
	c.AllowImplicitClient = false
	c.PreregisteredClients = []PreregisteredClient{{
		ClientID:     portalClientID,
		ClientName:   "Example Portal",
		RedirectURIs: []string{portalCallback},
	}}
}

// TestPreregisteredClient_ExactRedirectOnly is the core of the contract: the
// configured URI is accepted byte-for-byte and every near-miss is refused.
// Path, query and port variants each get their own case because each is a
// different way an attacker-controlled destination could ride in on a
// legitimate registration.
func TestPreregisteredClient_ExactRedirectOnly(t *testing.T) {
	srv := newTestServer(t, withPortalClient)
	ctx := context.Background()

	if err := srv.validateClient(ctx, portalClientID, portalCallback); err != nil {
		t.Fatalf("exact callback rejected: %v", err)
	}

	rejected := []struct {
		name string
		uri  string
	}{
		{"path suffix", portalCallback + "/extra"},
		{"path prefix trimmed", "https://portal.example.test/servers"},
		{"trailing slash", portalCallback + "/"},
		{"query appended", portalCallback + "?next=1"},
		{"fragment appended", portalCallback + "#x"},
		{"explicit port", "https://portal.example.test:8443/servers-callback"},
		{"http scheme", "http://portal.example.test/servers-callback"},
		{"different host", "https://evil.example.test/servers-callback"},
		{"userinfo prefix", "https://evil.example.test@portal.example.test/servers-callback"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if err := srv.validateClient(ctx, portalClientID, tc.uri); err == nil {
				t.Fatalf("validateClient accepted %q", tc.uri)
			}
		})
	}
}

// TestPreregisteredClient_DoesNotWidenImplicitAcceptance confirms the point of
// preferring pre-registration over the implicit-host allowlist: the portal's
// callback host is trusted for this client_id and nothing else. An
// unregistered client_id pointing at the same host is still refused.
func TestPreregisteredClient_DoesNotWidenImplicitAcceptance(t *testing.T) {
	srv := newTestServer(t, withPortalClient)
	if err := srv.validateClient(context.Background(), "some-other-client", portalCallback); err == nil {
		t.Fatal("an unregistered client_id was accepted for the pre-registered callback host")
	}
}

// TestPreregisteredClient_FullFlowWithoutRegistration walks authorize →
// callback → token for the static client with AllowImplicitClient=false and
// no POST /oauth/register anywhere, which is what makes this path viable for
// a counterpart that cannot perform RFC 7591 registration.
func TestPreregisteredClient_FullFlowWithoutRegistration(t *testing.T) {
	srv := newTestServer(t, withPortalClient)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, 500100101)

	verifier, challenge := pkceVerifierAndChallenge()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {portalClientID},
		"redirect_uri":          {portalCallback},
		"state":                 {"portal-state-abc"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, body = %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize redirect parse: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("authorize redirect carried no state")
	}

	redirect := authCodeRedirect(t, callbackWithState(t, mux, state))
	if redirect.Scheme+"://"+redirect.Host+redirect.Path != portalCallback {
		t.Fatalf("redirect target = %s, want %s", redirect, portalCallback)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatal("redirect carried no authorization code")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", portalClientID)
	form.Set("redirect_uri", portalCallback)
	form.Set("code_verifier", verifier)
	tokReq := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/token", tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", tokRec.Code, tokRec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(tokRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tok, _ := resp["access_token"].(string); tok == "" {
		t.Fatal("token response carried no access_token")
	}
}

// TestPreregisteredClient_NeverSwept mirrors the built-in connect client's
// guarantee: a static registration has a zero CreatedAt and so outlives the
// dynamic-registration TTL sweep.
func TestPreregisteredClient_NeverSwept(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		withPortalClient(c)
		c.ClientRegistrationTTL = 1 * time.Second
	})

	srv.sweep(time.Now().Add(1 * time.Hour))

	srv.mu.Lock()
	_, ok := srv.clients[portalClientID]
	srv.mu.Unlock()
	if !ok {
		t.Error("pre-registered client was swept, want it to persist indefinitely")
	}
}

// TestPreregisteredClient_NeverEvictedByRegistrationCap confirms that dynamic
// registrations cannot push a static client out of the registry.
func TestPreregisteredClient_NeverEvictedByRegistrationCap(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		withPortalClient(c)
		c.AllowImplicitClient = true // /oauth/register validates against the implicit host list
		c.MaxRegisteredClients = 1
	})
	mux := newMockRouter()
	srv.Register(mux)

	for _, name := range []string{"first", "second"} {
		body := `{"client_name":"` + name + `","redirect_uris":["https://claude.ai/cb"]}`
		req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.serve("POST", "/oauth/register", rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("register %s: %d %s", name, rec.Code, rec.Body.String())
		}
	}

	srv.mu.Lock()
	_, ok := srv.clients[portalClientID]
	srv.mu.Unlock()
	if !ok {
		t.Error("pre-registered client was evicted by the dynamic registration cap")
	}
}

// TestNew_RejectsBadPreregisteredClients keeps the configuration fail-closed:
// a record the server cannot honour stops startup instead of booting a server
// that quietly lacks the client the deployment was changed for.
func TestNew_RejectsBadPreregisteredClients(t *testing.T) {
	cases := []struct {
		name   string
		client PreregisteredClient
		want   string
	}{
		{"empty client_id", PreregisteredClient{RedirectURIs: []string{portalCallback}}, "client_id is required"},
		{"no redirect_uris", PreregisteredClient{ClientID: "x"}, "at least one redirect_uri"},
		{"backslash", PreregisteredClient{ClientID: "x", RedirectURIs: []string{`https://portal.example.test\@evil.test/cb`}}, "backslash"},
		{"userinfo", PreregisteredClient{ClientID: "x", RedirectURIs: []string{"https://evil.test@portal.example.test/cb"}}, "userinfo"},
		{"non-loopback http", PreregisteredClient{ClientID: "x", RedirectURIs: []string{"http://portal.example.test/cb"}}, "scheme"},
		{"fragment", PreregisteredClient{ClientID: "x", RedirectURIs: []string{portalCallback + "#frag"}}, "fragment"},
		{"collides with built-in", PreregisteredClient{ClientID: ConnectClientID, RedirectURIs: []string{portalCallback}}, "already registered"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Issuer:               testIssuer,
				JWTSecret:            testJWTSecret,
				TelegramOIDC:         newFakeAuthenticator(),
				AdminTelegramIDs:     map[int64]bool{500100101: true},
				AccessTokenTTL:       1 * time.Hour,
				CodeTTL:              1 * time.Minute,
				PreregisteredClients: []PreregisteredClient{tc.client},
			}
			_, err := New(context.Background(), cfg, newTestStore(t))
			if err == nil {
				t.Fatalf("New accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestPreregisteredClient_LoopbackHTTPAccepted keeps a native/CLI counterpart
// registrable: RFC 8252 loopback redirects stay valid for static records too.
func TestPreregisteredClient_LoopbackHTTPAccepted(t *testing.T) {
	const loopback = "http://127.0.0.1:8976/callback"
	srv := newTestServer(t, func(c *Config) {
		c.AllowImplicitClient = false
		c.PreregisteredClients = []PreregisteredClient{{ClientID: "cli", RedirectURIs: []string{loopback}}}
	})
	if err := srv.validateClient(context.Background(), "cli", loopback); err != nil {
		t.Fatalf("loopback callback rejected: %v", err)
	}
}

// TestNew_RejectsHostlessPreregisteredRedirect covers the one authority check
// the shared shape helper does not make. For the implicit path the host
// allowlist is the backstop, so a missing authority is caught downstream;
// pre-registration deliberately skips that allowlist, which leaves nothing
// checking it.
func TestNew_RejectsHostlessPreregisteredRedirect(t *testing.T) {
	for _, uri := range []string{"https:///servers-callback", "https://"} {
		cfg := Config{
			Issuer:           testIssuer,
			JWTSecret:        testJWTSecret,
			TelegramOIDC:     newFakeAuthenticator(),
			AdminTelegramIDs: map[int64]bool{500100101: true},
			AccessTokenTTL:   1 * time.Hour,
			CodeTTL:          1 * time.Minute,
			PreregisteredClients: []PreregisteredClient{{
				ClientID: "hostless", RedirectURIs: []string{uri},
			}},
		}
		_, err := New(context.Background(), cfg, newTestStore(t))
		if err == nil {
			t.Errorf("New accepted a redirect_uri with no host: %q", uri)
			continue
		}
		if !strings.Contains(err.Error(), "must have a host") {
			t.Errorf("error for %q = %v, want it to name the missing host", uri, err)
		}
	}
}
