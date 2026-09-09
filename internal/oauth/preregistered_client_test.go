package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Synthetic portal fixtures (issue #585 / design.md section 4). Never a real
// Cloudflare hostname or callback -- see CLAUDE.md and the proposal's
// explicit "no real Cloudflare hostname" rule.
const (
	portalClientID    = "portal-client-id"
	portalRedirectURI = "https://portal.example.test/servers-callback"
)

// T8: a pre-registered public client is accepted with its exact redirect_uri
// and rejected for path/query/port variants, with AllowImplicitClient=false
// and without any /oauth/register call.
func TestPreregisteredClient_ExactRedirectMatching(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.AllowImplicitClient = false
		c.PreregisteredClients = []PreregisteredClient{
			{ClientID: portalClientID, RedirectURIs: []string{portalRedirectURI}},
		}
	})
	ctx := context.Background()

	if err := srv.validateClient(ctx, portalClientID, portalRedirectURI); err != nil {
		t.Errorf("exact pre-registered redirect_uri rejected: %v", err)
	}

	rejected := []string{
		"https://portal.example.test/servers-callback/extra",
		"https://portal.example.test/servers-callback?x=1",
		"https://portal.example.test:8443/servers-callback",
		"http://portal.example.test/servers-callback",
		"https://evil.example.test/servers-callback",
	}
	for _, uri := range rejected {
		if err := srv.validateClient(ctx, portalClientID, uri); err == nil {
			t.Errorf("validateClient accepted variant redirect_uri %q, want rejection", uri)
		}
	}

	// A client_id never pre-registered must still be refused outright --
	// pre-registration must not have loosened the implicit-off default.
	if err := srv.validateClient(ctx, "never-registered", portalRedirectURI); err == nil {
		t.Error("unregistered client_id accepted while implicit clients are off")
	} else if !strings.Contains(err.Error(), "unknown client_id") {
		t.Errorf("unexpected error for unregistered client: %v", err)
	}
}

// The pre-registered client must work through the real /oauth/authorize
// HTTP path too -- not just validateClient in isolation -- with
// AllowImplicitClient=false and without ever calling /oauth/register.
func TestPreregisteredClient_AuthorizeWithoutRegisterOrImplicitClient(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.AllowImplicitClient = false
		c.PreregisteredClients = []PreregisteredClient{
			{ClientID: portalClientID, RedirectURIs: []string{portalRedirectURI}},
		}
	})
	r := chi.NewRouter()
	srv.Register(r)
	ts := httptest.NewServer(r)
	defer ts.Close()

	verifier, challenge := pkceVerifierAndChallenge()

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {portalClientID},
		"redirect_uri":          {portalRedirectURI},
		"state":                 {"portal-state-1"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	_ = verifier // the PKCE verifier itself is only needed for a full token exchange, not the authorize leg

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(ts.URL + "/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatalf("GET /oauth/authorize: %v", err)
	}
	defer resp.Body.Close()

	// A rejected client_id/redirect_uri combination fails validateClient
	// before ever reaching the Telegram OIDC redirect, and mctl's handler
	// reports that as a 400. Success here means it got past client
	// validation -- i.e. the pre-registration was honored -- and moved on
	// to the next stage of the flow (redirecting to Telegram OIDC).
	if resp.StatusCode == http.StatusBadRequest {
		t.Fatalf("authorize rejected the pre-registered client: HTTP %d", resp.StatusCode)
	}
}
