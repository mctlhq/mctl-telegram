package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
)

// admin:broadcast is granted only to identities that are BOTH full platform
// admins and broadcast operators (issue-439). Operator membership alone, or
// the lookup-admin tier, grants nothing.
func TestResolveScopes_BroadcastNeedsAdminAndOperator(t *testing.T) {
	const admin, adminOp, lookupOp, clientOp = 1001, 1002, 1003, 1004
	srv := newTestServer(t, func(c *Config) {
		c.AdminTelegramIDs = map[int64]bool{admin: true, adminOp: true}
		c.LookupAdminTelegramIDs = map[int64]bool{lookupOp: true}
		c.ClientTelegramIDs = map[int64]bool{clientOp: true}
		c.BroadcastOperatorTelegramIDs = map[int64]bool{adminOp: true, lookupOp: true, clientOp: true}
	})
	for _, tc := range []struct {
		tg   int64
		want bool
	}{{admin, false}, {adminOp, true}, {lookupOp, false}, {clientOp, false}} {
		_, scopes, err := srv.ResolveScopes(context.Background(), tc.tg)
		if err != nil {
			t.Fatal(err)
		}
		if got := slices.Contains(scopes, "admin:broadcast"); got != tc.want {
			t.Errorf("tg %d: admin:broadcast granted = %v, want %v (scopes %v)", tc.tg, got, tc.want, scopes)
		}
	}
}

// Every access token carries the client it was issued to. The broadcast
// approval page trusts only client_id=ConnectClientID, so an MCP client's
// token must carry its own id and the connect login must carry the connect id.
func TestAccessToken_CarriesClientID(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.BroadcastOperatorTelegramIDs = map[int64]bool{500100101: true} })
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, 500100101)

	resp := authCodeTokens(t, srv, mux)
	access, _ := resp["access_token"].(string)
	c, err := localjwt.Verify(access, testJWTSecret, testIssuer)
	if err != nil || c.ClientID != "claude.ai" {
		t.Fatalf("auth-code token client_id = %q %v", c.ClientID, err)
	}

	// A refreshed token keeps the refresh token's client.
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {resp["refresh_token"].(string)}, "client_id": {"claude.ai"}}
	rec := doTokenRequest(t, mux, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh = %d %s", rec.Code, rec.Body.String())
	}
	if c, err := localjwt.Verify(jsonField(t, rec.Body.Bytes(), "access_token"), testJWTSecret, testIssuer); err != nil || c.ClientID != "claude.ai" {
		t.Fatalf("refreshed token client_id = %q %v", c.ClientID, err)
	}

	verifier, challenge := pkceVerifierAndChallenge()
	connectRedirect := testIssuer + "/telegram/connect/done"
	cs := obtainAuthorizationCodeFor(t, srv, mux, challenge, ConnectClientID, connectRedirect)
	tok, err := srv.ExchangeConnect(context.Background(), cs.code, verifier, ConnectClientID, connectRedirect)
	if err != nil {
		t.Fatal(err)
	}
	c, err = localjwt.Verify(tok, testJWTSecret, testIssuer)
	if err != nil || c.ClientID != ConnectClientID {
		t.Fatalf("connect token client_id = %q %v", c.ClientID, err)
	}
	// The browser token is the one the approval page needs admin:broadcast on.
	if !slices.Contains(c.Scopes, "admin:broadcast") {
		t.Fatalf("connect token of an admin operator lacks admin:broadcast: %v", c.Scopes)
	}
}

// The token endpoint must not mint a self-connect token: whoever started an
// authorize request for the connect client with their own PKCE pair and got
// hold of the code would otherwise hold the one credential the broadcast
// approval page accepts, without the browser handler ever seeing it.
func TestTokenEndpoint_RefusesConnectClient(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, 500100101)

	verifier, challenge := pkceVerifierAndChallenge()
	connectRedirect := testIssuer + "/telegram/connect/done"
	cs := obtainAuthorizationCodeFor(t, srv, mux, challenge, ConnectClientID, connectRedirect)
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {cs.code}, "client_id": {ConnectClientID},
		"redirect_uri": {connectRedirect}, "code_verifier": {verifier},
	}
	rec := doTokenRequest(t, mux, form)
	if rec.Code == http.StatusOK || jsonField(t, rec.Body.Bytes(), "error") != "unauthorized_client" {
		t.Fatalf("token endpoint redeemed a connect code: %d %s", rec.Code, rec.Body.String())
	}
	// The refused code is still redeemable by the in-process exchange: the
	// refusal happens before the code is consumed.
	if _, err := srv.ExchangeConnect(context.Background(), cs.code, verifier, ConnectClientID, connectRedirect); err != nil {
		t.Fatalf("connect exchange after refusal: %v", err)
	}

	refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"anything"}, "client_id": {ConnectClientID}}
	if rec := doTokenRequest(t, mux, refresh); jsonField(t, rec.Body.Bytes(), "error") != "unauthorized_client" {
		t.Fatalf("refresh for the connect client = %d %s", rec.Code, rec.Body.String())
	}
}

func jsonField(t *testing.T, body []byte, key string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	s, _ := m[key].(string)
	return s
}
