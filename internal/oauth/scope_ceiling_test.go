package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/mcp"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
	"github.com/mctlhq/mctl-telegram/internal/workertoken"
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
// operator write, the credential mint, every broadcast tool, the message
// writes (send, edit, forward, delete, pin) and the account-destroying
// tools (account:manage).
var refusedForReadOnly = []string{
	"list_telegram_identities", "get_user_audit_log", "set_telegram_access", "mint_worker_token",
	"prepare_broadcast", "list_broadcasts", "get_broadcast", "cancel_broadcast",
	"send_message", "edit_message", "forward_messages", "delete_messages", "pin_message",
	"disconnect_telegram_account", "delete_telegram_account",
}

// allowedForReadOnly are the reads the two-scope ceiling exists to keep:
// telegram:dialogs:read (list_dialogs, list_folders) and
// telegram:messages:read (list_topics, get_messages, search_messages).
var allowedForReadOnly = []string{"list_dialogs", "list_folders", "list_topics", "get_messages", "search_messages"}

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
	srv := newTestServer(t, withDanaInEveryAdminMembership, withCeilingClient, func(c *Config) {
		c.LookupAdminTelegramIDs[bobTelegramID] = true // the allowed-reads negative control
	})
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, danaTelegramID)
	seedSession(t, srv, bobTelegramID)

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
		for _, tool := range allowedForReadOnly {
			if toolRefusedByScope(t, tools, id, tool) {
				t.Errorf("requested %q: ceiling token was refused %s, which its two reads allow", requested, tool)
			}
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

	// Negative control for the allowed reads: a token without them (Bob,
	// lookup admin only, through claude.ai: admin:users:read) is refused
	// each one, so "allowed" above is the reads' doing and not a filter
	// that lets every tool through.
	bob := identityOf(t, srv, tokenFor(t, srv, mux, bobTelegramID, "bob", "claude.ai", "https://claude.ai/cb", "")["access_token"].(string))
	for _, tool := range allowedForReadOnly {
		if !toolRefusedByScope(t, tools, bob, tool) {
			t.Errorf("control: a token without the reads was not refused %s", tool)
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
		// The backstop for a grant path that forgot its own empty check.
		"no scope":  {nil, nil},
		"empty set": {nil, []string{}},
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

const (
	// bobTelegramID is Bob, a member of TG_LOGIN_LOOKUP_ADMINS only: his
	// whole entitlement is admin:users:read. The id is Bob's lookup-admin
	// role elsewhere in this package (refresh_test.go).
	bobTelegramID int64 = 777000222
	// aliceTelegramID is Alice, in no tier at all. The id is Alice's
	// scopeless principal in refresh_test.go.
	aliceTelegramID int64 = 777000555
)

// codeExchangeFor is tokenFor without the success assertion: it returns the
// token endpoint's recorder for the code exchange.
func codeExchangeFor(t *testing.T, srv *Server, mux *mockRouter, tg int64, username, clientID, redirectURI string) *httptest.ResponseRecorder {
	t.Helper()
	authFake(srv).identity = &telegramoidc.Identity{TelegramID: tg, Username: username}
	verifier, challenge := pkceVerifierAndChallenge()
	state := stateFromAuthorizeFor(t, mux, challenge, clientID, redirectURI)
	code := authCodeRedirect(t, callbackWithState(t, mux, state)).Query().Get("code")
	if code == "" {
		t.Fatal("no authorization code")
	}
	return doTokenRequest(t, mux, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	})
}

func assertCeilingRefusal(t *testing.T, where string, status int, body []byte, wantError string) {
	t.Helper()
	if status != http.StatusBadRequest || jsonField(t, body, "error") != wantError ||
		jsonField(t, body, "error_description") != ceilingLeavesNoScopeDescription {
		t.Fatalf("%s = %d %s, want 400 %s %q", where, status, body, wantError, ceilingLeavesNoScopeDescription)
	}
	if strings.Contains(string(body), "access_token") {
		t.Fatalf("%s: a refusal carried a token: %s", where, body)
	}
}

// TestScopeCeiling_LookupAdminGetsNoTokenAtCodeExchange: Bob's entitlement
// (admin:users:read) intersects the read ceiling to nothing. The outcome is
// defined, not a scopeless token: the code exchange answers invalid_scope.
// Through claude.ai, without a ceiling, Bob keeps today's grant.
func TestScopeCeiling_LookupAdminGetsNoTokenAtCodeExchange(t *testing.T) {
	srv := newTestServer(t, withCeilingClient, func(c *Config) {
		c.LookupAdminTelegramIDs = map[int64]bool{bobTelegramID: true}
	})
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, bobTelegramID)

	rec := codeExchangeFor(t, srv, mux, bobTelegramID, "bob", ceilingClientID, ceilingCallback)
	assertCeilingRefusal(t, "lookup admin code exchange", rec.Code, rec.Body.Bytes(), "invalid_scope")

	resp := tokenFor(t, srv, mux, bobTelegramID, "bob", "claude.ai", "https://claude.ai/cb", "")
	if got := resp["scope"]; got != "admin:users:read" {
		t.Fatalf("control: Bob through claude.ai scope = %v, want admin:users:read", got)
	}
}

// TestScopeCeiling_LookupAdminGetsNoTokenAtInProcessExchange is the same on
// ExchangeConnect, whose ceiling is built in code (see
// TestScopeCeiling_S1T8_InProcessExchangeIsBounded).
func TestScopeCeiling_LookupAdminGetsNoTokenAtInProcessExchange(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.LookupAdminTelegramIDs = map[int64]bool{bobTelegramID: true}
		c.ClientProfiles.ScopeCeilingByClientID = map[string][]string{ConnectClientID: strings.Fields(ceilingTwoRead)}
	})
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, bobTelegramID)
	authFake(srv).identity = &telegramoidc.Identity{TelegramID: bobTelegramID, Username: "bob"}

	verifier, challenge := pkceVerifierAndChallenge()
	connectRedirect := testIssuer + "/telegram/connect/done"
	state := stateFromAuthorizeFor(t, mux, challenge, ConnectClientID, connectRedirect)
	code := authCodeRedirect(t, callbackWithState(t, mux, state)).Query().Get("code")
	tok, err := srv.ExchangeConnect(context.Background(), code, verifier, ConnectClientID, connectRedirect)
	if err == nil || !strings.Contains(err.Error(), "invalid_scope") || tok != "" {
		t.Fatalf("ExchangeConnect = %q, %v; want no token and invalid_scope", tok, err)
	}
}

// seedCeilingFamily stores a refresh-token family for the ceiling client.
func seedCeilingFamily(t *testing.T, srv *Server, tg int64, username, family, scope string) (string, db.RefreshToken) {
	t.Helper()
	uid, err := srv.store.EnsureUserByTelegramID(context.Background(), tg, username, "")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	rt := db.RefreshToken{
		FamilyID: family, UserID: uid, ClientID: ceilingClientID, TelegramID: tg, TelegramUsername: username,
		Scope: scope, RedirectURI: ceilingCallback, RedirectURIKnown: true, ExpiresAt: time.Now().Add(time.Hour),
	}
	plain := family + "-token"
	if err := srv.store.SaveRefreshToken(context.Background(), plain, rt); err != nil {
		t.Fatalf("save refresh token: %v", err)
	}
	return plain, rt
}

// TestScopeCeiling_RefreshWithNothingWithinTheCeilingIsRefused pins the
// refresh outcome when the bounded grant is empty:
//   - Bob's family from before the ceiling, holding admin:users:read;
//   - Alice's family that never held a scope. Without a ceiling such a
//     family keeps refreshing scopeless (#584); for a ceiling client it is
//     refused, so this case is what the ceiling's own empty check decides.
//
// Both answer invalid_grant with the ceiling's description and no token.
func TestScopeCeiling_RefreshWithNothingWithinTheCeilingIsRefused(t *testing.T) {
	srv := newTestServer(t, withCeilingClient, func(c *Config) {
		c.LookupAdminTelegramIDs = map[int64]bool{bobTelegramID: true}
		c.AutoApproveClients = false
	})
	mux := newMockRouter()
	srv.Register(mux)

	bob, _ := seedCeilingFamily(t, srv, bobTelegramID, "bob", "bob-lookup-family", "admin:users:read")
	status, body := refreshResp(t, mux, bob, ceilingClientID)
	assertCeilingRefusal(t, "lookup admin refresh", status, body, "invalid_grant")

	alice, _ := seedCeilingFamily(t, srv, aliceTelegramID, "alice", "alice-scopeless-family", "")
	status, body = refreshResp(t, mux, alice, ceilingClientID)
	assertCeilingRefusal(t, "scopeless family refresh", status, body, "invalid_grant")
}

// TestScopeCeiling_GraceReplayWithNothingWithinTheCeilingIsRefused is the
// same on the grace-window replay path, with Alice's scopeless family.
func TestScopeCeiling_GraceReplayWithNothingWithinTheCeilingIsRefused(t *testing.T) {
	srv := newTestServer(t, withCeilingClient, func(c *Config) { c.AutoApproveClients = false })
	mux := newMockRouter()
	srv.Register(mux)
	plain, rt := seedCeilingFamily(t, srv, aliceTelegramID, "alice", "alice-grace-family", "")
	if err := srv.store.RotateRefreshToken(context.Background(), plain, deriveSuccessorRefreshToken(srv.cfg.JWTSecret, plain), rt); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	status, body := refreshResp(t, mux, plain, ceilingClientID)
	assertCeilingRefusal(t, "scopeless grace replay", status, body, "invalid_grant")
}

// TestScopeCeiling_TokenCannotMintAWorkerToken: a ceiling token, even for
// Dana in every admin membership, is refused at the HTTP worker-token mint
// (403) through the same middleware and handler the server mounts, while
// Dana's unbounded claude.ai token is admitted there.
func TestScopeCeiling_TokenCannotMintAWorkerToken(t *testing.T) {
	srv := newTestServer(t, withDanaInEveryAdminMembership, withCeilingClient)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, danaTelegramID)

	p, err := localjwt.NewProvider(srv.store, localjwt.ProviderConfig{Secret: []byte(testJWTSecret), ExpectedIssuer: testIssuer})
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	mint := auth.Middleware(p, true, nil, auth.ResourceMetadata{})(workertoken.NewHandler([]byte(testJWTSecret), testIssuer, ""))
	post := func(access string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/mcp/worker-token",
			strings.NewReader(`{"telegram_id":`+strconv.FormatInt(danaTelegramID, 10)+`,"scopes":["telegram:dialogs:read"]}`))
		r.Header.Set("Authorization", "Bearer "+access)
		r.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mint.ServeHTTP(rec, r)
		return rec
	}

	ceiling := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", ceilingClientID, ceilingCallback, "")
	// The body pins which gate refused it: the handler's admin-scope check,
	// not some unrelated 403 earlier in the chain.
	if rec := post(ceiling["access_token"].(string)); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin scope required") {
		t.Fatalf("ceiling token at /api/mcp/worker-token = %d %s, want 403 admin scope required", rec.Code, rec.Body.String())
	}
	admin := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", "claude.ai", "https://claude.ai/cb", "")
	if rec := post(admin["access_token"].(string)); rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("control: unbounded admin token at /api/mcp/worker-token = %d %s, want admitted past the scope check", rec.Code, rec.Body.String())
	}
}

const refreshGrantLine = "oauth: token refresh_token grant"

// TestScopeCeiling_RefreshGrantIsLoggedOnlyWhenATokenIsIssued: the refresh
// audit line saying "grant" is written only after the token is minted and
// the family rotated. Three ceiling refreshes, against one captured log:
//   - one the mint refuses after the ceiling has bounded a non-empty grant
//     (a family that predates redirect_uri storage while a redirect_uri
//     profile binding exists: errProfileUnresolvable);
//   - one refused for an empty bounded grant, which logs its own Warn;
//   - one that succeeds, the control proving the line is written at all.
func TestScopeCeiling_RefreshGrantIsLoggedOnlyWhenATokenIsIssued(t *testing.T) {
	srv := newTestServer(t, withDanaInEveryAdminMembership, withCeilingClient, func(c *Config) {
		c.ClientProfiles.ByRedirectURI = map[string]string{"https://other.example.test/cb": "core-readonly"}
		c.AutoApproveClients = false
	})
	mux := newMockRouter()
	srv.Register(mux)
	logs := captureServerLogFor(t, srv)

	// Refused by the mint, after the ceiling applied.
	_, unknown := seedCeilingFamily(t, srv, danaTelegramID, "dana_tg", "dana-unknown-redirect", ceilingTwoRead)
	unknown.RedirectURI, unknown.RedirectURIKnown = "", false
	unknownPlain := "dana-unknown-redirect-legacy-token"
	if err := srv.store.SaveRefreshToken(context.Background(), unknownPlain, unknown); err != nil {
		t.Fatalf("save refresh token: %v", err)
	}
	status, body := refreshResp(t, mux, unknownPlain, ceilingClientID)
	if status != http.StatusBadRequest || jsonField(t, body, "error_description") != profileUnresolvableDescription {
		t.Fatalf("refresh of a family without a stored redirect_uri = %d %s, want 400 %q", status, body, profileUnresolvableDescription)
	}
	if strings.Contains(logs.String(), refreshGrantLine) {
		t.Fatalf("a refresh the mint refused logged a grant:\n%s", logs.String())
	}

	// Refused for an empty bounded grant.
	empty, _ := seedCeilingFamily(t, srv, aliceTelegramID, "alice", "alice-empty-ceiling", "")
	status, body = refreshResp(t, mux, empty, ceilingClientID)
	assertCeilingRefusal(t, "empty bounded refresh", status, body, "invalid_grant")
	if strings.Contains(logs.String(), refreshGrantLine) {
		t.Fatalf("an empty-grant refusal logged a grant:\n%s", logs.String())
	}
	if !strings.Contains(logs.String(), "nothing within the client's scope ceiling") {
		t.Fatalf("the empty-grant refusal logged no warning:\n%s", logs.String())
	}

	// Control: a refresh that issues a token logs the grant, once.
	ok, _ := seedCeilingFamily(t, srv, danaTelegramID, "dana_tg", "dana-ok", ceilingTwoRead)
	if status, body = refreshResp(t, mux, ok, ceilingClientID); status != http.StatusOK {
		t.Fatalf("control refresh = %d %s, want 200", status, body)
	}
	if got := strings.Count(logs.String(), refreshGrantLine); got != 1 {
		t.Fatalf("a successful ceiling refresh logged %d grant lines, want 1:\n%s", got, logs.String())
	}
}

// TestScopeCeiling_GraceEmptyRefusalIsLogged: the grace-replay path warns
// on an empty bounded grant like the other three paths.
func TestScopeCeiling_GraceEmptyRefusalIsLogged(t *testing.T) {
	srv := newTestServer(t, withCeilingClient, func(c *Config) { c.AutoApproveClients = false })
	mux := newMockRouter()
	srv.Register(mux)
	logs := captureServerLogFor(t, srv)
	plain, rt := seedCeilingFamily(t, srv, aliceTelegramID, "alice", "alice-grace-warn", "")
	if err := srv.store.RotateRefreshToken(context.Background(), plain, deriveSuccessorRefreshToken(srv.cfg.JWTSecret, plain), rt); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	status, body := refreshResp(t, mux, plain, ceilingClientID)
	assertCeilingRefusal(t, "grace replay", status, body, "invalid_grant")
	out := logs.String()
	if !strings.Contains(out, "nothing within the client's scope ceiling") || !strings.Contains(out, "path=grace_replay") ||
		!strings.Contains(out, "family_id=alice-grace-warn") || !strings.Contains(out, "client_id="+ceilingClientID) {
		t.Fatalf("grace-replay empty refusal not logged with client_id, family_id and path:\n%s", out)
	}
}

func TestWorkspaceEndpointOAuthCeilingAndIdentity(t *testing.T) {
	reads := strings.Fields(ceilingTwoRead)
	srv := newTestServer(t, func(c *Config) {
		c.EndpointScopeCeiling = reads
		c.EndpointTelegramID = danaTelegramID
	})
	origin := tokenOrigin{ClientID: "claude.ai", RedirectURIKnown: true}
	adminGroups := []string{"platform-admins", "admins"}
	groups, scopes, bounded := srv.applyClientScopeCeiling(origin.ClientID, origin.RedirectURI, adminGroups, adminEntitlement)
	if !bounded || len(groups) != 0 || strings.Join(scopes, " ") != ceilingTwoRead {
		t.Fatalf("workspace grant groups=%v scopes=%v bounded=%v", groups, scopes, bounded)
	}
	if _, err := srv.mintAccessToken(origin, danaTelegramID, "dana_tg", adminGroups, adminEntitlement); !errors.Is(err, errScopeCeilingViolated) {
		t.Fatalf("unbounded mint error = %v", err)
	}
	if _, err := srv.mintAccessToken(origin, 0, "", groups, scopes); err == nil {
		t.Fatal("minted token for an identity outside the workspace")
	}
	if _, err := srv.mintAccessToken(origin, danaTelegramID, "dana_tg", groups, scopes); err != nil {
		t.Fatalf("bounded mint failed: %v", err)
	}
}
