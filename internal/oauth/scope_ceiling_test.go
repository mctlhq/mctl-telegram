package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/mcp"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

// Scope ceiling tests (#1326, threat model T8). The ceiling client stands in
// for the Personal Assistant: a preregistered client whose tokens must carry
// exactly the two read scopes, whatever the principal is entitled to.
const (
	ceilingClientID = "pa-assistant-test"
	ceilingCallback = "https://pa.example.test/oauth/callback"
	ceilingTwoRead  = "telegram:dialogs:read telegram:messages:read"

	// carolTelegramID is Carol, a client-tier principal promoted to every
	// admin membership between grants. The id is Carol's elsewhere in this
	// package (refresh_test.go).
	carolTelegramID int64 = 777000333
)

// withCeilingClient registers the ceiling client and bounds it to the two
// read scopes. claude.ai stays an implicit client without a ceiling, so the
// same server shows both behaviours.
func withCeilingClient(c *Config) {
	c.PreregisteredClients = append(c.PreregisteredClients, PreregisteredClient{
		ClientID:     ceilingClientID,
		ClientName:   "Example Assistant",
		RedirectURIs: []string{ceilingCallback},
	})
	c.ClientProfiles.ScopeCeilingByClientID = map[string][]string{
		ceilingClientID: strings.Fields(ceilingTwoRead),
	}
}

// withDanaInEveryAdminMembership makes Dana a member of TG_LOGIN_ADMINS,
// TG_LOGIN_LOOKUP_ADMINS and BROADCAST_OPERATORS at once.
func withDanaInEveryAdminMembership(c *Config) {
	c.AdminTelegramIDs = map[int64]bool{danaTelegramID: true}
	c.LookupAdminTelegramIDs = map[int64]bool{danaTelegramID: true}
	c.BroadcastOperatorTelegramIDs = map[int64]bool{danaTelegramID: true}
}

// adminEntitlement is what ResolveScopes grants Dana under
// withDanaInEveryAdminMembership: the full-admin tier wins over the lookup
// tier, and the operator membership adds admin:broadcast.
var adminEntitlement = []string{
	"telegram:dialogs:read", "telegram:messages:read", "telegram:messages:send",
	"telegram:messages:pin", "admin:users", "account:manage", "admin:broadcast",
}

// tokenFor drives authorize, the Telegram callback and the code exchange for
// identity as clientID and returns the decoded token response.
func tokenFor(t *testing.T, srv *Server, mux *mockRouter, tg int64, username, clientID, redirectURI, requested string) map[string]any {
	t.Helper()
	authFake(srv).identity = &telegramoidc.Identity{TelegramID: tg, Username: username}
	return scopedAuthCodeTokensFor(t, mux, clientID, redirectURI, requested)
}

func refreshResp(t *testing.T, mux *mockRouter, refreshTok, clientID string) (status int, body []byte) {
	t.Helper()
	rec := doTokenRequest(t, mux, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshTok}, "client_id": {clientID}})
	return rec.Code, rec.Body.Bytes()
}

// assertCeilingToken checks a token response from the ceiling client: the
// response scope, the JWT's scopes and the JWT's groups.
func assertCeilingToken(t *testing.T, where, responseScope, access string) *localjwt.Claims {
	t.Helper()
	if responseScope != ceilingTwoRead {
		t.Fatalf("%s: response scope = %q, want exactly %q", where, responseScope, ceilingTwoRead)
	}
	c := claimsOf(t, access)
	if got := strings.Join(c.Scopes, " "); got != ceilingTwoRead {
		t.Fatalf("%s: token scopes = %q, want exactly %q", where, got, ceilingTwoRead)
	}
	if len(c.Groups) != 0 {
		t.Fatalf("%s: token groups = %v, want none", where, c.Groups)
	}
	return c
}

// identityOf authenticates access through the real local-jwt provider, the
// one /mcp uses, so the tool-scope check below sees exactly what a request
// carrying this token would.
func identityOf(t *testing.T, srv *Server, access string) *auth.Identity {
	t.Helper()
	p, err := localjwt.NewProvider(srv.store, localjwt.ProviderConfig{Secret: []byte(testJWTSecret), ExpectedIssuer: testIssuer})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+access)
	id, err := p.Authenticate(r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	return id
}

// refusedForReadOnly are the tools S1-T8 names: the operator lookups, an
// operator write, the credential mint, every broadcast tool and the send.
var refusedForReadOnly = []string{
	"list_telegram_identities", "get_user_audit_log", "set_telegram_access", "mint_worker_token",
	"prepare_broadcast", "list_broadcasts", "get_broadcast", "cancel_broadcast",
	"send_message",
}

// toolRefusedByScope reports whether tg's tool-scope filter refused the call
// before any handler ran. mcp-go answers a filtered tool with a JSON-RPC
// error naming it as not found; a handler that ran (and failed, here, for
// want of a Telegram pool) answers a result instead.
func toolRefusedByScope(t *testing.T, s *mcp.Server, id *auth.Identity, tool string) bool {
	t.Helper()
	_, err := s.CallToolInProcess(context.Background(), id, tool, map[string]any{})
	return err != nil && strings.Contains(err.Error(), "not found")
}

// TestScopeCeiling_S1T8_AdminGetsOnlyReadsAtTokenEndpoint is S1-T8 on the
// token endpoint's code exchange: Dana, in all three admin memberships,
// signs in as the ceiling client and gets exactly the two read scopes and
// no groups, whether the client asks for the reads or for nothing (an
// empty request is the full entitlement before the ceiling). tg's own
// tool-scope enforcement then refuses every admin, broadcast and send tool
// for that token, while the same admin through claude.ai is not refused.
func TestScopeCeiling_S1T8_AdminGetsOnlyReadsAtTokenEndpoint(t *testing.T) {
	srv := newTestServer(t, withDanaInEveryAdminMembership, withCeilingClient)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, danaTelegramID)

	if _, entitled, err := srv.ResolveScopes(context.Background(), danaTelegramID); err != nil || !slices.Equal(entitled, adminEntitlement) {
		t.Fatalf("precondition: Dana's entitlement = %v, %v; want %v", entitled, err, adminEntitlement)
	}

	tools := mcp.New(srv.store, nil, false)
	for _, requested := range []string{ceilingTwoRead, ""} {
		resp := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", ceilingClientID, ceilingCallback, requested)
		access, _ := resp["access_token"].(string)
		scope, _ := resp["scope"].(string)
		assertCeilingToken(t, "requested "+strconvQuote(requested), scope, access)

		id := identityOf(t, srv, access)
		for _, tool := range refusedForReadOnly {
			if !toolRefusedByScope(t, tools, id, tool) {
				t.Errorf("requested %q: ceiling token was not refused %s by tg's tool scopes", requested, tool)
			}
		}
		if toolRefusedByScope(t, tools, id, "get_my_identity") {
			t.Errorf("requested %q: ceiling token was refused get_my_identity, which needs no scope", requested)
		}
	}

	// Positive control: without the ceiling the same admin reaches every
	// one of those tools past the scope filter, so the refusals above are
	// the ceiling's doing and not a tool that is refused to everybody.
	resp := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", "claude.ai", "https://claude.ai/cb", "")
	admin := identityOf(t, srv, resp["access_token"].(string))
	for _, tool := range refusedForReadOnly {
		if toolRefusedByScope(t, tools, admin, tool) {
			t.Errorf("control: an unbounded admin token was refused %s by tool scopes", tool)
		}
	}
}

func strconvQuote(s string) string { return `"` + s + `"` }

// TestScopeCeiling_S1T8_InProcessExchangeIsBounded is S1-T8 on the other
// code-exchange path, ExchangeConnect. Its client_id is reserved from
// MCP_CLIENT_PROFILES, so no deployed configuration bounds it; the table is
// built in code here to prove that path applies the ceiling as well.
func TestScopeCeiling_S1T8_InProcessExchangeIsBounded(t *testing.T) {
	srv := newTestServer(t, withDanaInEveryAdminMembership, func(c *Config) {
		c.ClientProfiles.ScopeCeilingByClientID = map[string][]string{ConnectClientID: strings.Fields(ceilingTwoRead)}
	})
	mux := newMockRouter()
	srv.Register(mux)

	verifier, challenge := pkceVerifierAndChallenge()
	connectRedirect := testIssuer + "/telegram/connect/done"
	cs := obtainAuthorizationCodeFor(t, srv, mux, challenge, ConnectClientID, connectRedirect)
	tok, err := srv.ExchangeConnect(context.Background(), cs.code, verifier, ConnectClientID, connectRedirect)
	if err != nil {
		t.Fatalf("ExchangeConnect: %v", err)
	}
	c := claimsOf(t, tok)
	if got := strings.Join(c.Scopes, " "); got != ceilingTwoRead {
		t.Fatalf("connect token scopes = %q, want exactly %q", got, ceilingTwoRead)
	}
	if len(c.Groups) != 0 {
		t.Fatalf("connect token groups = %v, want none", c.Groups)
	}
}

// TestScopeCeiling_RefreshNeverWidensAfterPromotion: Carol signs in as the
// ceiling client while client-tier, is then added to every admin
// membership, and refreshes twice. Each refreshed token keeps exactly the
// two reads and no groups: the promotion reaches neither the scopes nor the
// "platform-admins" tier label.
func TestScopeCeiling_RefreshNeverWidensAfterPromotion(t *testing.T) {
	srv := newTestServer(t, withCeilingClient, func(c *Config) {
		c.ClientTelegramIDs = map[int64]bool{carolTelegramID: true}
	})
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, carolTelegramID)

	resp := tokenFor(t, srv, mux, carolTelegramID, "carol", ceilingClientID, ceilingCallback, "")
	assertCeilingToken(t, "code exchange", resp["scope"].(string), resp["access_token"].(string))

	srv.cfg.AdminTelegramIDs = map[int64]bool{carolTelegramID: true}
	srv.cfg.LookupAdminTelegramIDs = map[int64]bool{carolTelegramID: true}
	srv.cfg.BroadcastOperatorTelegramIDs = map[int64]bool{carolTelegramID: true}

	next := resp["refresh_token"].(string)
	for i := 1; i <= 2; i++ {
		status, body := refreshResp(t, mux, next, ceilingClientID)
		if status != http.StatusOK {
			t.Fatalf("refresh %d after promotion = %d %s", i, status, body)
		}
		assertCeilingToken(t, "refresh after promotion", jsonField(t, body, "scope"), jsonField(t, body, "access_token"))
		next = jsonField(t, body, "refresh_token")
	}
}

// seedWideCeilingFamily stores a refresh-token family for the ceiling client
// that carries Dana's whole admin entitlement: a family issued before the
// ceiling was configured. Returns the plaintext refresh token.
func seedWideCeilingFamily(t *testing.T, srv *Server, family string) (string, db.RefreshToken) {
	t.Helper()
	uid, err := srv.store.EnsureUserByTelegramID(context.Background(), danaTelegramID, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	rt := db.RefreshToken{
		FamilyID:         family,
		UserID:           uid,
		ClientID:         ceilingClientID,
		TelegramID:       danaTelegramID,
		TelegramUsername: "dana_tg",
		Scope:            strings.Join(adminEntitlement, " "),
		RedirectURI:      ceilingCallback,
		RedirectURIKnown: true,
		ExpiresAt:        time.Now().Add(time.Hour),
	}
	plain := family + "-token"
	if err := srv.store.SaveRefreshToken(context.Background(), plain, rt); err != nil {
		t.Fatalf("save refresh token: %v", err)
	}
	return plain, rt
}

// TestScopeCeiling_RefreshBoundsAFamilyIssuedBeforeTheCeiling: a family
// whose stored grant is Dana's full admin entitlement refreshes to exactly
// the two reads and no groups. boundRefreshGrant alone would keep the
// stored grant, so this is the ceiling on the refresh path.
func TestScopeCeiling_RefreshBoundsAFamilyIssuedBeforeTheCeiling(t *testing.T) {
	srv := newTestServer(t, withDanaInEveryAdminMembership, withCeilingClient)
	mux := newMockRouter()
	srv.Register(mux)
	plain, _ := seedWideCeilingFamily(t, srv, "wide-family")

	status, body := refreshResp(t, mux, plain, ceilingClientID)
	if status != http.StatusOK {
		t.Fatalf("refresh = %d %s", status, body)
	}
	assertCeilingToken(t, "refresh of a wide family", jsonField(t, body, "scope"), jsonField(t, body, "access_token"))

	// The rotated row stores the bounded grant, so the family stays narrow
	// even if the ceiling is later removed.
	next, err := srv.store.LookupRefreshToken(context.Background(), jsonField(t, body, "refresh_token"))
	if err != nil {
		t.Fatalf("lookup successor: %v", err)
	}
	if next.Scope != ceilingTwoRead {
		t.Fatalf("successor stored scope = %q, want %q", next.Scope, ceilingTwoRead)
	}
}

// TestScopeCeiling_GraceReplayIsBounded: the grace-window replay path
// re-issues an access token for the live successor. With a successor that
// still carries the wide grant (rotated before the ceiling existed), the
// re-issued token must still be bounded.
func TestScopeCeiling_GraceReplayIsBounded(t *testing.T) {
	srv := newTestServer(t, withDanaInEveryAdminMembership, withCeilingClient)
	mux := newMockRouter()
	srv.Register(mux)
	plain, rt := seedWideCeilingFamily(t, srv, "wide-grace-family")
	successor := deriveSuccessorRefreshToken(srv.cfg.JWTSecret, plain)
	if err := srv.store.RotateRefreshToken(context.Background(), plain, successor, rt); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	status, body := refreshResp(t, mux, plain, ceilingClientID)
	if status != http.StatusOK {
		t.Fatalf("grace replay = %d %s", status, body)
	}
	if got := jsonField(t, body, "refresh_token"); got != successor {
		t.Fatal("the replay did not take the grace path: it returned a refresh token other than the existing successor")
	}
	assertCeilingToken(t, "grace replay", jsonField(t, body, "scope"), jsonField(t, body, "access_token"))
}

// TestScopeCeiling_S1T11_ClientWithoutCeilingKeepsTodaysGrant: a client id
// with no ceiling record gets exactly what it gets on a server with no
// ceiling configured at all, scopes and groups alike, on the code exchange
// and on refresh. This is the regression guard for existing clients.
func TestScopeCeiling_S1T11_ClientWithoutCeilingKeepsTodaysGrant(t *testing.T) {
	type grant struct{ scopes, groups, refreshed string }
	run := func(opts ...func(*Config)) map[string]grant {
		srv := newTestServer(t, append([]func(*Config){withDanaInEveryAdminMembership}, opts...)...)
		mux := newMockRouter()
		srv.Register(mux)
		seedSession(t, srv, danaTelegramID)
		out := map[string]grant{}
		for _, requested := range []string{ceilingTwoRead, ""} {
			resp := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", "claude.ai", "https://claude.ai/cb", requested)
			c := claimsOf(t, resp["access_token"].(string))
			status, body := refreshResp(t, mux, resp["refresh_token"].(string), "claude.ai")
			if status != http.StatusOK {
				t.Fatalf("refresh = %d %s", status, body)
			}
			out[requested] = grant{strings.Join(c.Scopes, " "), strings.Join(c.Groups, ","), jsonField(t, body, "scope")}
		}
		return out
	}
	without := run()
	with := run(withCeilingClient)
	for requested, want := range without {
		if got := with[requested]; got != want {
			t.Errorf("requested %q: claude.ai grant changed by another client's ceiling: got %+v, want %+v", requested, got, want)
		}
	}
	// Pin today's grant itself, so the comparison cannot pass by both
	// sides regressing together: the membership scopes and the tier
	// groups survive narrowGrant for a client without a ceiling.
	if got, want := without[ceilingTwoRead], (grant{ceilingTwoRead + " admin:users admin:broadcast", "platform-admins,admins", ceilingTwoRead + " admin:users admin:broadcast"}); got != want {
		t.Fatalf("today's narrowed admin grant = %+v, want %+v", got, want)
	}
	if got := without[""].scopes; got != strings.Join(adminEntitlement, " ") {
		t.Fatalf("today's unnarrowed admin grant = %q, want %q", got, strings.Join(adminEntitlement, " "))
	}
}

// TestScopeCeiling_MintRefusesATokenWiderThanTheCeiling pins the mint-time
// assertion: a grant path that skipped applyClientScopeCeiling gets an
// error, not a token. It is a backstop for a future grant path.
func TestScopeCeiling_MintRefusesATokenWiderThanTheCeiling(t *testing.T) {
	srv := newTestServer(t, withCeilingClient)
	origin := tokenOrigin{ClientID: ceilingClientID, RedirectURI: ceilingCallback, RedirectURIKnown: true}
	for name, tc := range map[string]struct{ groups, scopes []string }{
		"extra scope":   {nil, adminEntitlement},
		"tier groups":   {[]string{"platform-admins", "admins"}, strings.Fields(ceilingTwoRead)},
		"unknown scope": {nil, []string{"telegram:dialogs:read", "future:scope"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := srv.mintAccessToken(origin, danaTelegramID, "dana_tg", tc.groups, tc.scopes); !errors.Is(err, errScopeCeilingViolated) {
				t.Fatalf("mint = %v, want errScopeCeilingViolated", err)
			}
		})
	}
	if _, err := srv.mintAccessToken(origin, danaTelegramID, "dana_tg", nil, strings.Fields(ceilingTwoRead)); err != nil {
		t.Fatalf("a token within the ceiling: %v", err)
	}
	if _, err := srv.mintAccessToken(tokenOrigin{ClientID: "claude.ai", RedirectURIKnown: true}, danaTelegramID, "dana_tg", []string{"platform-admins"}, adminEntitlement); err != nil {
		t.Fatalf("a client without a ceiling: %v", err)
	}
}

// TestScopeCeiling_MalformedCeilingFailsConstruction: what ParseBindings
// cannot know, the authorization server checks at construction, and
// refuses to start on.
func TestScopeCeiling_MalformedCeilingFailsConstruction(t *testing.T) {
	for name, tc := range map[string]struct {
		ceiling []string
		want    string
	}{
		"unknown scope":  {[]string{"telegram:dialogs:read", "telegram:dialog:read"}, `names "telegram:dialog:read"`},
		"retired scope":  {[]string{"mctl"}, `names "mctl"`},
		"empty in code":  {[]string{}, "is empty"},
		"nil in code":    {nil, "is empty"},
		"whitespace tok": {[]string{"telegram:dialogs:read telegram:messages:read"}, "never grants"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), Config{
				Issuer: testIssuer, JWTSecret: testJWTSecret, TelegramOIDC: newFakeAuthenticator(),
				ClientProfiles: toolprofile.Bindings{ScopeCeilingByClientID: map[string][]string{ceilingClientID: tc.ceiling}},
			}, newTestStore(t))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error containing %q", err, tc.want)
			}
		})
	}

	// The same table through the real parser: a well-formed ceiling of
	// grantable scopes constructs, so the refusals above are about content.
	b, err := toolprofile.ParseBindings(`[{"client_id":"` + ceilingClientID + `","scope_ceiling":["telegram:dialogs:read","telegram:messages:read"]}]`)
	if err != nil {
		t.Fatalf("ParseBindings: %v", err)
	}
	if _, err := New(context.Background(), Config{
		Issuer: testIssuer, JWTSecret: testJWTSecret, TelegramOIDC: newFakeAuthenticator(), ClientProfiles: *b,
	}, newTestStore(t)); err != nil {
		t.Fatalf("New with a valid ceiling: %v", err)
	}
}

// TestGrantableScopesCoverResolveScopes keeps grantableScope in step with
// ResolveScopes: a scope a tier grants but grantableScope does not know
// would make a ceiling naming it fail startup, and would mean the list the
// ceiling is checked against has drifted from what tokens can carry.
func TestGrantableScopesCoverResolveScopes(t *testing.T) {
	const admin, lookup, client = 1001, 1003, 1004
	srv := newTestServer(t, func(c *Config) {
		c.AdminTelegramIDs = map[int64]bool{admin: true}
		c.LookupAdminTelegramIDs = map[int64]bool{lookup: true}
		c.ClientTelegramIDs = map[int64]bool{client: true}
		c.BroadcastOperatorTelegramIDs = map[int64]bool{admin: true}
	})
	for _, tg := range []int64{admin, lookup, client} {
		_, scopes, err := srv.ResolveScopes(context.Background(), tg)
		if err != nil {
			t.Fatal(err)
		}
		for _, sc := range scopes {
			if !grantableScope(sc) {
				t.Errorf("tg %d is granted %q, which grantableScope does not know", tg, sc)
			}
		}
	}
}
