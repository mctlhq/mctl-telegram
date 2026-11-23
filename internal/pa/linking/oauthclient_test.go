package linking

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/egress"
)

const (
	testRefresh = "rt-synthetic-not-real-0123456789"
	testAccess  = "at-synthetic-not-real-0123456789"
)

type fakeAS struct {
	mu     sync.Mutex
	forms  []url.Values
	paths  []string
	status int
	body   string
}

func newFakeAS(t *testing.T, status int, body string) (*fakeAS, *httptest.Server) {
	t.Helper()
	f := &fakeAS{status: status, body: body}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		f.mu.Lock()
		f.forms = append(f.forms, form)
		f.paths = append(f.paths, r.Method+" "+r.URL.Path+" "+r.Header.Get("Content-Type"))
		st, b := f.status, f.body
		f.mu.Unlock()
		w.WriteHeader(st)
		_, _ = io.WriteString(w, b)
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

// oauthClientFor builds an OAuthClient on srv's client: egress refuses the
// loopback test server, so the egress clients themselves are covered by
// TestNewOAuthClient_UsesEgress.
func oauthClientFor(srv *httptest.Server, revocation bool) *OAuthClient {
	s := OAuthServer{
		ClientID: "pa-preview", TokenEndpoint: srv.URL + "/oauth/token", Resource: "https://tg.example/mcp",
		AllowedHosts: []string{"tg.example"},
	}
	c := &OAuthClient{
		servers: map[connection.Server]OAuthServer{},
		token:   map[connection.Server]*http.Client{connection.ServerTG: srv.Client()},
		revoke:  map[connection.Server]*http.Client{},
	}
	if revocation {
		s.RevocationEndpoint = srv.URL + "/oauth/revoke"
		c.revoke[connection.ServerTG] = srv.Client()
	}
	c.servers[connection.ServerTG] = s
	return c
}

func TestOAuthClient_RevokeRFC7009(t *testing.T) {
	f, srv := newFakeAS(t, http.StatusOK, "")
	c := oauthClientFor(srv, true)
	if err := c.Revoke(context.Background(), connection.ServerTG, connection.NewSecret(testRefresh), connection.HintRefreshToken); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(f.forms) != 1 {
		t.Fatalf("%d requests", len(f.forms))
	}
	got := f.forms[0]
	if got.Get("token") != testRefresh || got.Get("token_type_hint") != "refresh_token" || got.Get("client_id") != "pa-preview" || len(got) != 3 {
		t.Errorf("revocation form = %v", got)
	}
	if f.paths[0] != "POST /oauth/revoke application/x-www-form-urlencoded" {
		t.Errorf("request = %s", f.paths[0])
	}
}

// Only 200 is success; every other answer is an error without the token.
func TestOAuthClient_RevokeRefusalIsError(t *testing.T) {
	for _, st := range []int{http.StatusBadRequest, http.StatusServiceUnavailable, http.StatusNoContent, http.StatusFound} {
		_, srv := newFakeAS(t, st, `{"error":"unsupported_token_type","token":"`+testAccess+`"}`)
		err := oauthClientFor(srv, true).Revoke(context.Background(), connection.ServerTG, connection.NewSecret(testAccess), connection.HintAccessToken)
		if !errors.Is(err, ErrRevocationEndpoint) {
			t.Errorf("HTTP %d: err = %v", st, err)
		}
		if err != nil && strings.Contains(err.Error(), testAccess) {
			t.Errorf("HTTP %d: error carries the token", st)
		}
	}
}

// A server without a revocation endpoint is ErrNotRevocable, never a
// silent success, and nothing is sent.
func TestOAuthClient_RevokeWithoutEndpoint(t *testing.T) {
	f, srv := newFakeAS(t, http.StatusOK, "")
	err := oauthClientFor(srv, false).Revoke(context.Background(), connection.ServerTG, connection.NewSecret(testAccess), connection.HintAccessToken)
	if !errors.Is(err, ErrNotRevocable) {
		t.Fatalf("err = %v, want ErrNotRevocable", err)
	}
	if len(f.forms) != 0 {
		t.Fatal("a request was sent")
	}
	if err := oauthClientFor(srv, true).Revoke(context.Background(), connection.ServerAlice, connection.NewSecret(testAccess), connection.HintAccessToken); err == nil {
		t.Fatal("unknown server revoked")
	}
}

func TestOAuthClient_RefreshGrant(t *testing.T) {
	f, srv := newFakeAS(t, http.StatusOK, `{"access_token":"x"}`)
	body, err := oauthClientFor(srv, true).Refresh(context.Background(), connection.ServerTG, connection.NewSecret(testRefresh))
	if err != nil || string(body) != `{"access_token":"x"}` {
		t.Fatalf("Refresh = %q, %v", body, err)
	}
	got := f.forms[0]
	if got.Get("grant_type") != "refresh_token" || got.Get("refresh_token") != testRefresh || got.Get("client_id") != "pa-preview" ||
		got.Get("resource") != "https://tg.example/mcp" || len(got) != 4 {
		t.Errorf("refresh form = %v", got)
	}
	if f.paths[0] != "POST /oauth/token application/x-www-form-urlencoded" {
		t.Errorf("request = %s", f.paths[0])
	}
}

// invalid_grant, and only a readable invalid_grant, is ErrInvalidGrant;
// anything else is transient, never taken for invalid_grant.
func TestOAuthClient_RefreshErrorMapping(t *testing.T) {
	cases := []struct {
		status  int
		body    string
		invalid bool
	}{
		{http.StatusBadRequest, `{"error":"invalid_grant","error_description":"refresh token already used"}`, true},
		{http.StatusUnauthorized, `{"error":"invalid_grant"}`, true},
		{http.StatusBadRequest, `{"error":"invalid_request"}`, false},
		{http.StatusBadRequest, `not json invalid_grant`, false},
		{http.StatusBadRequest, ``, false},
		{http.StatusInternalServerError, `{"error":"invalid_grant"}`, false},
		{http.StatusServiceUnavailable, ``, false},
		{http.StatusFound, `{"error":"invalid_grant"}`, false},
	}
	for _, tc := range cases {
		_, srv := newFakeAS(t, tc.status, tc.body)
		_, err := oauthClientFor(srv, true).Refresh(context.Background(), connection.ServerTG, connection.NewSecret(testRefresh))
		if err == nil {
			t.Errorf("HTTP %d %q: no error", tc.status, tc.body)
			continue
		}
		if errors.Is(err, connection.ErrInvalidGrant) != tc.invalid {
			t.Errorf("HTTP %d %q: invalid_grant = %v, want %v (%v)", tc.status, tc.body, !tc.invalid, tc.invalid, err)
		}
		if strings.Contains(err.Error(), testRefresh) {
			t.Errorf("HTTP %d: error carries the refresh token", tc.status)
		}
	}
}

// The production constructor builds egress clients: a loopback endpoint,
// which egress refuses, is never reached, and a server without a
// revocation endpoint gets no revocation client.
func TestNewOAuthClient_UsesEgress(t *testing.T) {
	f, srv := newFakeAS(t, http.StatusOK, `{}`)
	c, err := NewOAuthClient(map[connection.Server]OAuthServer{connection.ServerTG: {
		ClientID: "pa-preview", TokenEndpoint: srv.URL + "/oauth/token", RevocationEndpoint: srv.URL + "/oauth/revoke",
		Resource: "https://tg.example/mcp", AllowedHosts: []string{"tg.example"},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(context.Background(), connection.ServerTG, connection.NewSecret(testRefresh)); err == nil {
		t.Error("refresh reached a loopback endpoint")
	}
	if err := c.Revoke(context.Background(), connection.ServerTG, connection.NewSecret(testRefresh), connection.HintRefreshToken); err == nil {
		t.Error("revoke reached a loopback endpoint")
	}
	if _, err := c.TokenClient().ExchangeCode(context.Background(), connection.ServerTG, ExchangeRequest{
		TokenEndpoint: srv.URL + "/oauth/token", Code: connection.NewSecret("c"), Verifier: connection.NewSecret("v"),
	}); !errors.Is(err, egress.ErrNotHTTPS) && !errors.Is(err, egress.ErrPort) && !errors.Is(err, egress.ErrHostNotAllowed) {
		t.Errorf("exchange to a loopback endpoint: %v", err)
	}
	if len(f.forms) != 0 {
		t.Fatalf("%d requests reached the loopback server", len(f.forms))
	}
	if _, err := NewOAuthClient(map[connection.Server]OAuthServer{connection.ServerTG: {ClientID: "x", TokenEndpoint: "https://tg.example/t", Resource: "r"}}, nil); err == nil {
		t.Error("no allowlist accepted")
	}
	nr, err := NewOAuthClient(map[connection.Server]OAuthServer{connection.ServerTG: {
		ClientID: "x", TokenEndpoint: "https://tg.example/t", Resource: "r", AllowedHosts: []string{"tg.example"},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := nr.Revoke(context.Background(), connection.ServerTG, connection.NewSecret(testAccess), connection.HintAccessToken); !errors.Is(err, ErrNotRevocable) {
		t.Errorf("no revocation endpoint: %v", err)
	}
}
