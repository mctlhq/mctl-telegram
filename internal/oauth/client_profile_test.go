package oauth

import (
	"net/http"
	"net/url"
	"slices"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

func refreshFor(t *testing.T, mux *mockRouter, refreshTok, clientID string) (access, nextRefresh string) {
	t.Helper()
	rec := doTokenRequest(t, mux, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshTok}, "client_id": {clientID}})
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh = %d %s", rec.Code, rec.Body.String())
	}
	return jsonField(t, rec.Body.Bytes(), "access_token"), jsonField(t, rec.Body.Bytes(), "refresh_token")
}

func claimsOf(t *testing.T, tok string) *localjwt.Claims {
	t.Helper()
	c, err := localjwt.Verify(tok, testJWTSecret, testIssuer)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return c
}

// TestAccessToken_CarriesBoundProfile: a client bound in ClientProfiles gets
// its profile stamped into the code-exchange token and into every refreshed
// token, and the profile leaves the granted scopes exactly as they were.
func TestAccessToken_CarriesBoundProfile(t *testing.T) {
	const tg int64 = 555000111
	plain := newTestServer(t, func(c *Config) { c.ClientTelegramIDs = map[int64]bool{tg: true} })
	bound := newTestServer(t, func(c *Config) {
		c.ClientTelegramIDs = map[int64]bool{tg: true}
		c.ClientProfiles = map[string]string{"claude.ai": toolprofile.CoreReadonly}
	})

	var scopes [2][]string
	for i, srv := range []*Server{plain, bound} {
		mux := newMockRouter()
		srv.Register(mux)
		seedSession(t, srv, tg)
		authFake(srv).identity.TelegramID = tg

		resp := authCodeTokens(t, srv, mux)
		c := claimsOf(t, resp["access_token"].(string))
		want := ""
		if srv == bound {
			want = toolprofile.CoreReadonly
		}
		if c.Profile != want {
			t.Fatalf("server %d: auth-code token prf = %q, want %q", i, c.Profile, want)
		}
		scopes[i] = c.Scopes

		access, _ := refreshFor(t, mux, resp["refresh_token"].(string), "claude.ai")
		if got := claimsOf(t, access).Profile; got != want {
			t.Fatalf("server %d: refreshed token prf = %q, want %q", i, got, want)
		}
	}
	if !slices.Equal(scopes[0], scopes[1]) {
		t.Fatalf("binding a profile changed the granted scopes: unbound %v, bound %v", scopes[0], scopes[1])
	}
}

// TestRefresh_ReResolvesProfile: the profile is not frozen into the refresh
// token family. A binding added after the grant applies at the next
// refresh, and one removed stops applying at the next refresh.
func TestRefresh_ReResolvesProfile(t *testing.T) {
	const tg int64 = 555000111
	srv := newTestServer(t, func(c *Config) {
		c.ClientTelegramIDs = map[int64]bool{tg: true}
		c.ClientProfiles = map[string]string{}
	})
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, tg)
	authFake(srv).identity.TelegramID = tg

	resp := authCodeTokens(t, srv, mux)
	if got := claimsOf(t, resp["access_token"].(string)).Profile; got != "" {
		t.Fatalf("unbound client got prf %q", got)
	}

	srv.cfg.ClientProfiles["claude.ai"] = toolprofile.CoreReadonly
	access, next := refreshFor(t, mux, resp["refresh_token"].(string), "claude.ai")
	if got := claimsOf(t, access).Profile; got != toolprofile.CoreReadonly {
		t.Fatalf("binding added after the grant: refreshed prf = %q, want %q", got, toolprofile.CoreReadonly)
	}

	delete(srv.cfg.ClientProfiles, "claude.ai")
	access, _ = refreshFor(t, mux, next, "claude.ai")
	if got := claimsOf(t, access).Profile; got != "" {
		t.Fatalf("binding removed: refreshed prf = %q, want none", got)
	}
}

// TestAccessToken_ProfileBindsOnlyItsClient: the binding is keyed by the
// exact client_id; another client of the same user is unaffected.
func TestAccessToken_ProfileBindsOnlyItsClient(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.ClientProfiles = map[string]string{"other.example": toolprofile.CoreReadonly}
	})
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, authFake(srv).identity.TelegramID)

	resp := authCodeTokens(t, srv, mux)
	if got := claimsOf(t, resp["access_token"].(string)).Profile; got != "" {
		t.Fatalf("claude.ai token carries prf %q bound to another client", got)
	}
}

// TestConnectClientIDIsReservedFromProfiles: the self-connect client's token
// is the manage page's cookie, and a profiled credential is refused outside
// /mcp, so MCP_CLIENT_PROFILES must refuse to bind it. toolprofile cannot
// import this package, so it keeps its own copy of the id; this pins the two
// together.
func TestConnectClientIDIsReservedFromProfiles(t *testing.T) {
	if !toolprofile.Reserved(ConnectClientID) {
		t.Fatalf("toolprofile does not reserve %q: a binding for it would lock users out of the manage page", ConnectClientID)
	}
}
