package oauth

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
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
		c.ClientProfiles = toolprofile.Bindings{ByClientID: map[string]string{"claude.ai": toolprofile.CoreReadonly}}
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
		c.ClientProfiles = toolprofile.Bindings{ByClientID: map[string]string{}}
	})
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, tg)
	authFake(srv).identity.TelegramID = tg

	resp := authCodeTokens(t, srv, mux)
	if got := claimsOf(t, resp["access_token"].(string)).Profile; got != "" {
		t.Fatalf("unbound client got prf %q", got)
	}

	srv.cfg.ClientProfiles.ByClientID["claude.ai"] = toolprofile.CoreReadonly
	access, next := refreshFor(t, mux, resp["refresh_token"].(string), "claude.ai")
	if got := claimsOf(t, access).Profile; got != toolprofile.CoreReadonly {
		t.Fatalf("binding added after the grant: refreshed prf = %q, want %q", got, toolprofile.CoreReadonly)
	}

	delete(srv.cfg.ClientProfiles.ByClientID, "claude.ai")
	access, _ = refreshFor(t, mux, next, "claude.ai")
	if got := claimsOf(t, access).Profile; got != "" {
		t.Fatalf("binding removed: refreshed prf = %q, want none", got)
	}
}

// TestAccessToken_ProfileBindsOnlyItsClient: the binding is keyed by the
// exact client_id; another client of the same user is unaffected.
func TestAccessToken_ProfileBindsOnlyItsClient(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.ClientProfiles = toolprofile.Bindings{ByClientID: map[string]string{"other.example": toolprofile.CoreReadonly}}
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

// redirectBound is a binding table with one redirect_uri record: the
// callback authCodeTokens uses.
func redirectBound(profile string) toolprofile.Bindings {
	return toolprofile.Bindings{ByRedirectURI: map[string]string{"https://claude.ai/cb": profile}}
}

// TestAccessToken_RedirectURIBinding: a redirect_uri binding stamps the
// profile into the code-exchange token and keeps it there through every
// rotation, because the family carries the redirect_uri; the profile is
// re-resolved at each refresh, so removing the binding lifts it.
func TestAccessToken_RedirectURIBinding(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.ClientProfiles = redirectBound(toolprofile.CoreReply) })
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, authFake(srv).identity.TelegramID)

	resp := authCodeTokens(t, srv, mux)
	if got := claimsOf(t, resp["access_token"].(string)).Profile; got != toolprofile.CoreReply {
		t.Fatalf("auth-code token prf = %q, want %q", got, toolprofile.CoreReply)
	}
	next := resp["refresh_token"].(string)
	for i := 0; i < 2; i++ {
		var access string
		access, next = refreshFor(t, mux, next, "claude.ai")
		if got := claimsOf(t, access).Profile; got != toolprofile.CoreReply {
			t.Fatalf("refresh %d: prf = %q, want %q", i+1, got, toolprofile.CoreReply)
		}
	}

	delete(srv.cfg.ClientProfiles.ByRedirectURI, "https://claude.ai/cb")
	access, _ := refreshFor(t, mux, next, "claude.ai")
	if got := claimsOf(t, access).Profile; got != "" {
		t.Fatalf("binding removed: refreshed prf = %q, want none", got)
	}
}

// TestAccessToken_ClientIDBindingWinsOverRedirectURI: with both kinds of
// record matching, the client_id record decides.
func TestAccessToken_ClientIDBindingWinsOverRedirectURI(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.ClientProfiles = redirectBound(toolprofile.CoreReply)
		c.ClientProfiles.ByClientID = map[string]string{"claude.ai": toolprofile.CoreReadonly}
	})
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, authFake(srv).identity.TelegramID)

	resp := authCodeTokens(t, srv, mux)
	if got := claimsOf(t, resp["access_token"].(string)).Profile; got != toolprofile.CoreReadonly {
		t.Fatalf("prf = %q, want the client_id binding %q", got, toolprofile.CoreReadonly)
	}
	access, _ := refreshFor(t, mux, resp["refresh_token"].(string), "claude.ai")
	if got := claimsOf(t, access).Profile; got != toolprofile.CoreReadonly {
		t.Fatalf("refreshed prf = %q, want the client_id binding %q", got, toolprofile.CoreReadonly)
	}
}

// seedLegacyFamily stores a refresh token the way a release before the
// redirect_uri column did: no redirect_uri at all (NULL).
func seedLegacyFamily(t *testing.T, srv *Server) string {
	t.Helper()
	ctx := context.Background()
	const tg int64 = 500100101
	uid, err := srv.store.EnsureUserByTelegramID(ctx, tg, "dana_tg", "Dana")
	if err != nil {
		t.Fatal(err)
	}
	const plaintext = "legacy-family-refresh-token-0001"
	if err := srv.store.SaveRefreshToken(ctx, plaintext, db.RefreshToken{
		FamilyID: "legacy-family", UserID: uid, ClientID: "claude.ai", ClientName: "Claude",
		TelegramID: tg, TelegramUsername: "dana_tg", Scope: "telegram:dialogs:read telegram:messages:read",
		ExpiresAt: srv.clock().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	rt, err := srv.store.LookupRefreshToken(ctx, plaintext)
	if err != nil || rt.RedirectURIKnown {
		t.Fatalf("seeded family: %+v, %v; want an unknown redirect_uri", rt, err)
	}
	return plaintext
}

// TestRefresh_UnknownRedirectURIIsNotUnbound: a family issued before the
// redirect_uri was stored cannot be matched against a redirect_uri binding.
// While any such binding exists it is refused rather than minted an
// unprofiled token, since it may belong to the restricted client; with none
// it refreshes as before, and rotation keeps it unknown rather than "".
func TestRefresh_UnknownRedirectURIIsNotUnbound(t *testing.T) {
	t.Run("refused while a redirect_uri binding exists", func(t *testing.T) {
		srv := newTestServer(t, func(c *Config) { c.ClientProfiles = redirectBound(toolprofile.CoreReadonly) })
		mux := newMockRouter()
		srv.Register(mux)
		tok := seedLegacyFamily(t, srv)
		rec := doTokenRequest(t, mux, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}, "client_id": {"claude.ai"}})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") ||
			!strings.Contains(rec.Body.String(), "authorize again") {
			t.Fatalf("legacy refresh = %d %s, want invalid_grant asking to authorize again", rec.Code, rec.Body.String())
		}
	})
	t.Run("a client_id binding still decides", func(t *testing.T) {
		srv := newTestServer(t, func(c *Config) {
			c.ClientProfiles = redirectBound(toolprofile.CoreReply)
			c.ClientProfiles.ByClientID = map[string]string{"claude.ai": toolprofile.CoreReadonly}
		})
		mux := newMockRouter()
		srv.Register(mux)
		access, _ := refreshFor(t, mux, seedLegacyFamily(t, srv), "claude.ai")
		if got := claimsOf(t, access).Profile; got != toolprofile.CoreReadonly {
			t.Fatalf("prf = %q, want %q", got, toolprofile.CoreReadonly)
		}
	})
	t.Run("refreshes as before with no redirect_uri binding", func(t *testing.T) {
		srv := newTestServer(t)
		mux := newMockRouter()
		srv.Register(mux)
		legacy := seedLegacyFamily(t, srv)
		access, next := refreshFor(t, mux, legacy, "claude.ai")
		if got := claimsOf(t, access).Profile; got != "" {
			t.Fatalf("prf = %q, want none", got)
		}
		rt, err := srv.store.LookupRefreshToken(context.Background(), next)
		if err != nil {
			t.Fatal(err)
		}
		if rt.RedirectURIKnown {
			t.Fatalf("rotation turned an unknown redirect_uri into %q", rt.RedirectURI)
		}
		// The rotated successor is still unknown, so a binding added later
		// refuses it too instead of reading "" as unbound -- on a grace
		// replay of its predecessor as on a plain refresh. Each answer is
		// invalid_grant asking to authorize again, never a server_error
		// the client would retry forever.
		srv.cfg.ClientProfiles = redirectBound(toolprofile.CoreReadonly)
		for name, tok := range map[string]string{"grace replay of the predecessor": legacy, "successor": next} {
			rec := doTokenRequest(t, mux, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok}, "client_id": {"claude.ai"}})
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "authorize again") {
				t.Fatalf("%s after a binding = %d %s, want invalid_grant asking to authorize again", name, rec.Code, rec.Body.String())
			}
		}
	})
}

// TestRefreshFamilyStoresRedirectURI: the code exchange records the
// authorization's redirect_uri on the family, and rotation copies it.
func TestRefreshFamilyStoresRedirectURI(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, authFake(srv).identity.TelegramID)
	resp := authCodeTokens(t, srv, mux)
	first := resp["refresh_token"].(string)
	_, second := refreshFor(t, mux, first, "claude.ai")
	for i, tok := range []string{first, second} {
		rt, err := srv.store.LookupRefreshToken(context.Background(), tok)
		if err != nil {
			t.Fatal(err)
		}
		if !rt.RedirectURIKnown || rt.RedirectURI != "https://claude.ai/cb" {
			t.Fatalf("token %d: redirect_uri = %q (known %v), want https://claude.ai/cb", i, rt.RedirectURI, rt.RedirectURIKnown)
		}
	}
}

// TestRedirectURIBindingOnGraceReplay: a grace-window replay re-mints from
// the live successor, which carries the redirect_uri, so the recovered
// token keeps the profile.
func TestRedirectURIBindingOnGraceReplay(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.ClientProfiles = redirectBound(toolprofile.CoreReadonly) })
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, authFake(srv).identity.TelegramID)
	original := authCodeTokens(t, srv, mux)["refresh_token"].(string)
	refreshFor(t, mux, original, "claude.ai")
	access, _ := refreshFor(t, mux, original, "claude.ai")
	if got := claimsOf(t, access).Profile; got != toolprofile.CoreReadonly {
		t.Fatalf("grace-replay prf = %q, want %q", got, toolprofile.CoreReadonly)
	}
}

// TestSelfConnectRedirectURIIsReservedFromProfiles: a redirect_uri binding
// on the self-connect client's callback would profile the manage page's
// cookie and lock every user out of it, so New refuses it.
func TestSelfConnectRedirectURIIsReservedFromProfiles(t *testing.T) {
	_, err := New(context.Background(), Config{
		Issuer: testIssuer, JWTSecret: testJWTSecret, TelegramOIDC: newFakeAuthenticator(),
		AccessTokenTTL: time.Hour, CodeTTL: time.Minute,
		ClientProfiles: toolprofile.Bindings{ByRedirectURI: map[string]string{testIssuer + "/telegram/connect/done": toolprofile.CoreReadonly}},
	}, newTestStore(t))
	if err == nil || !strings.Contains(err.Error(), "self-connect") {
		t.Fatalf("New = %v, want the self-connect refusal", err)
	}
}

// TestUnacceptableRedirectURIBindingFailsStartup: a redirect_uri binding the
// authorize endpoint could never accept would match nothing and leave the
// client unrestricted, so New refuses it.
func TestUnacceptableRedirectURIBindingFailsStartup(t *testing.T) {
	for _, uri := range []string{
		"ftp://town.example.test/cb",
		"http://town.example.test/cb",
		"https://user@town.example.test/cb",
		`https://town.example.test\cb`,
	} {
		_, err := New(context.Background(), Config{
			Issuer: testIssuer, JWTSecret: testJWTSecret, TelegramOIDC: newFakeAuthenticator(),
			AccessTokenTTL: time.Hour, CodeTTL: time.Minute,
			ClientProfiles: toolprofile.Bindings{ByRedirectURI: map[string]string{uri: toolprofile.CoreReadonly}},
		}, newTestStore(t))
		if err == nil || !strings.Contains(err.Error(), "can never match an authorization") {
			t.Fatalf("%s: New = %v, want a startup refusal", uri, err)
		}
	}
	if _, err := New(context.Background(), Config{
		Issuer: testIssuer, JWTSecret: testJWTSecret, TelegramOIDC: newFakeAuthenticator(),
		AccessTokenTTL: time.Hour, CodeTTL: time.Minute,
		ClientProfiles: toolprofile.Bindings{ByRedirectURI: map[string]string{"http://127.0.0.1:8976/cb": toolprofile.CoreReadonly}},
	}, newTestStore(t)); err != nil {
		t.Fatalf("a loopback http binding was refused: %v", err)
	}
}
