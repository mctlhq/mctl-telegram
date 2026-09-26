package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Synthetic stand-ins for the two callbacks the Cloudflare MCP portal claims
// when it registers in automatic (DCR) mode: its shared servers-callback and
// the dashboard's per-server admin callback. As in preregistered_test.go, the
// real production values are never baked into this repository; an operator
// copies them into OAUTH_DCR_REDIRECT_URIS.
const (
	dcrPortalCallback = "https://portal.example.test/servers-callback"
	dcrDashCallback   = "https://dash.example.test/0000aaaa/one/access-controls/ai-controls/mcp-server/oauth-callback/tg"
)

func withDCRAllowlist(c *Config) {
	c.DCRRedirectURIs = []string{dcrPortalCallback, dcrDashCallback}
}

// registerRaw POSTs body to /oauth/register from its own client IP (so the
// per-IP rate limit never interferes across subtests) and returns the
// recorder.
func registerRaw(t *testing.T, mux *mockRouter, body, remoteIP string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteIP + ":1234"
	rec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/register", rec, req)
	return rec
}

// registerURIs registers redirect_uris and decodes the response body.
func registerURIs(t *testing.T, mux *mockRouter, remoteIP string, uris ...string) (int, map[string]any) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"client_name": "Example Portal", "redirect_uris": uris})
	if err != nil {
		t.Fatal(err)
	}
	rec := registerRaw(t, mux, string(b), remoteIP)
	var resp map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	return rec.Code, resp
}

// TestDCRAllowlist_ExactSetAccepted: the portal's full registration — both
// callbacks, neither of whose hosts is on the implicit list — is accepted, and
// the resulting client authorizes against each callback. AllowImplicitClient
// is off to prove nothing here leans on the implicit path.
func TestDCRAllowlist_ExactSetAccepted(t *testing.T) {
	srv := newTestServer(t, withDCRAllowlist, func(c *Config) { c.AllowImplicitClient = false })
	mux := newMockRouter()
	srv.Register(mux)

	code, resp := registerURIs(t, mux, "203.0.113.1", dcrPortalCallback, dcrDashCallback)
	if code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %v", code, resp)
	}
	clientID, _ := resp["client_id"].(string)
	if !strings.HasPrefix(clientID, db.PinnedClientIDPrefix) {
		t.Fatalf("client_id = %q, want the pinned prefix %q", clientID, db.PinnedClientIDPrefix)
	}
	for _, cb := range []string{dcrPortalCallback, dcrDashCallback} {
		if err := srv.validateClient(context.Background(), clientID, cb); err != nil {
			t.Fatalf("validateClient(%q): %v", cb, err)
		}
	}

	// A single listed callback on its own is a valid set too.
	if code, resp := registerURIs(t, mux, "203.0.113.2", dcrPortalCallback); code != http.StatusCreated {
		t.Fatalf("single-callback register status = %d, body = %v", code, resp)
	}
}

// TestDCRAllowlist_OneForeignRedirectRejected: a registration naming a listed
// callback and anything else is refused, even when the other URI would pass
// the implicit-host check alone (claude.ai), so a portal-class registration
// can never carry a second destination.
func TestDCRAllowlist_OneForeignRedirectRejected(t *testing.T) {
	srv := newTestServer(t, withDCRAllowlist)
	mux := newMockRouter()
	srv.Register(mux)

	for i, foreign := range []string{
		"https://claude.ai/cb",
		"https://evil.example.test/servers-callback",
		dcrPortalCallback + "/extra",
	} {
		code, resp := registerURIs(t, mux, fmt.Sprintf("203.0.113.%d", 10+i), dcrPortalCallback, dcrDashCallback, foreign)
		if code != http.StatusBadRequest {
			t.Fatalf("[%s] status = %d, want 400, body = %v", foreign, code, resp)
		}
		if resp["error"] != "invalid_redirect_uri" {
			t.Fatalf("[%s] error = %v, want invalid_redirect_uri", foreign, resp["error"])
		}
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for id := range srv.clients {
		if isPinnedClientID(id) {
			t.Fatalf("a rejected registration left a pinned client %q behind", id)
		}
	}
}

// TestDCRAllowlist_NearMissesRejected: matching is byte for byte. Each variant
// is neither on the exact list nor on the implicit host list, so every one of
// them is refused.
func TestDCRAllowlist_NearMissesRejected(t *testing.T) {
	srv := newTestServer(t, withDCRAllowlist)
	mux := newMockRouter()
	srv.Register(mux)

	for i, uri := range []string{
		"https://portal.example.test/servers",                 // prefix of a listed URI
		dcrPortalCallback + "/",                               // trailing slash
		dcrPortalCallback + "-evil",                           // listed URI as a prefix
		dcrPortalCallback + "?next=1",                         // query appended
		dcrPortalCallback + "#x",                              // fragment appended
		"https://portal.example.test:8443/servers-callback",   // explicit port
		"https://PORTAL.example.test/servers-callback",        // host case changed
		"http://portal.example.test/servers-callback",         // scheme downgraded
		"https://portal.example.test/Servers-Callback",        // path case changed
		strings.TrimSuffix(dcrDashCallback, "/tg") + "/other", // another server id
		" " + dcrPortalCallback,                               // leading whitespace
	} {
		code, resp := registerURIs(t, mux, fmt.Sprintf("198.51.100.%d", 10+i), uri)
		if code != http.StatusBadRequest {
			t.Fatalf("[%q] status = %d, want 400, body = %v", uri, code, resp)
		}
		if resp["error"] != "invalid_redirect_uri" {
			t.Fatalf("[%q] error = %v, want invalid_redirect_uri", uri, resp["error"])
		}
	}
}

// TestDCRAllowlist_EmptyListKeepsPreviousBehaviour: with no allowlist the
// portal's callbacks are refused exactly as before (their hosts are not on the
// implicit list), and a claude.ai registration still mints a random client_id.
// With the list set, a registration naming no listed URI still takes the
// unchanged implicit path.
func TestDCRAllowlist_EmptyListKeepsPreviousBehaviour(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		srv := newTestServer(t)
		mux := newMockRouter()
		srv.Register(mux)
		code, resp := registerURIs(t, mux, "192.0.2.1", dcrPortalCallback, dcrDashCallback)
		if code != http.StatusBadRequest || resp["error"] != "invalid_redirect_uri" {
			t.Fatalf("status = %d body = %v, want 400 invalid_redirect_uri", code, resp)
		}
		if desc, _ := resp["error_description"].(string); !strings.Contains(desc, "is not in the allowlist") {
			t.Fatalf("error_description = %q, want the unchanged implicit-host message", desc)
		}
		code, resp = registerURIs(t, mux, "192.0.2.2", "https://claude.ai/cb")
		if code != http.StatusCreated {
			t.Fatalf("claude.ai register status = %d, body = %v", code, resp)
		}
		if id, _ := resp["client_id"].(string); !strings.HasPrefix(id, "tgmcp_") {
			t.Fatalf("client_id = %q, want a random tgmcp_ id", id)
		}
	})
	t.Run("list set, implicit-path registration", func(t *testing.T) {
		srv := newTestServer(t, withDCRAllowlist)
		mux := newMockRouter()
		srv.Register(mux)
		code, resp := registerURIs(t, mux, "192.0.2.3", "https://claude.ai/cb")
		if code != http.StatusCreated {
			t.Fatalf("claude.ai register status = %d, body = %v", code, resp)
		}
		id, _ := resp["client_id"].(string)
		if !strings.HasPrefix(id, "tgmcp_") {
			t.Fatalf("client_id = %q, want a random tgmcp_ id", id)
		}
		code, resp = registerURIs(t, mux, "192.0.2.4", "https://evil.example.test/cb")
		if code != http.StatusBadRequest {
			t.Fatalf("foreign host register status = %d, want 400, body = %v", code, resp)
		}
	})
}

// TestDCRAllowlist_IdempotentAndBounded: repeating the portal's registration —
// in another order, with a duplicate entry — returns the same client_id and
// adds no row, so an unauthenticated caller replaying it cannot grow storage.
func TestDCRAllowlist_IdempotentAndBounded(t *testing.T) {
	srv := newTestServer(t, withDCRAllowlist)
	mux := newMockRouter()
	srv.Register(mux)

	_, first := registerURIs(t, mux, "203.0.113.30", dcrPortalCallback, dcrDashCallback)
	_, second := registerURIs(t, mux, "203.0.113.31", dcrDashCallback, dcrPortalCallback, dcrDashCallback)
	if first["client_id"] == nil || first["client_id"] != second["client_id"] {
		t.Fatalf("client_id differs across identical registrations: %v vs %v", first["client_id"], second["client_id"])
	}
	// Server-assigned name: registerURIs sends "Example Portal" and this
	// replay another name; neither is stored or answered.
	third := registerRaw(t, mux, `{"client_name":"Totally Official Telegram","redirect_uris":["`+dcrPortalCallback+`","`+dcrDashCallback+`"]}`, "203.0.113.32")
	var thirdResp map[string]any
	_ = json.NewDecoder(third.Body).Decode(&thirdResp)
	if first["client_name"] != db.PinnedClientName || thirdResp["client_name"] != db.PinnedClientName {
		t.Fatalf("echoed client_name = %v / %v, want %q", first["client_name"], thirdResp["client_name"], db.PinnedClientName)
	}
	srv.mu.Lock()
	storedName := srv.clients[first["client_id"].(string)].ClientName
	srv.mu.Unlock()
	if storedName != db.PinnedClientName {
		t.Fatalf("stored client_name = %q, want %q", storedName, db.PinnedClientName)
	}
	uris, _ := second["redirect_uris"].([]any)
	if len(uris) != 2 {
		t.Fatalf("redirect_uris = %v, want the deduplicated pair", second["redirect_uris"])
	}
	srv.mu.Lock()
	var pinned int
	for id := range srv.clients {
		if isPinnedClientID(id) {
			pinned++
		}
	}
	srv.mu.Unlock()
	if pinned != 1 {
		t.Fatalf("pinned clients = %d, want 1", pinned)
	}
}

// TestDCRAllowlist_PinnedSurvivesSweepAndCap: the portal registers once and
// keeps using the client_id, so a pinned registration outlives the 24h TTL
// sweep and is never the entry the registration cap evicts.
func TestDCRAllowlist_PinnedSurvivesSweepAndCap(t *testing.T) {
	srv := newTestServer(t, withDCRAllowlist, func(c *Config) { c.MaxRegisteredClients = 1 })
	mux := newMockRouter()
	srv.Register(mux)
	t0 := time.Now()
	srv.clock = func() time.Time { return t0 }

	_, resp := registerURIs(t, mux, "203.0.113.40", dcrPortalCallback, dcrDashCallback)
	pinnedID, _ := resp["client_id"].(string)
	var randomIDs []string
	for i, ip := range []string{"203.0.113.41", "203.0.113.42"} {
		srv.clock = func() time.Time { return t0.Add(time.Duration(i+1) * time.Second) }
		code, r := registerURIs(t, mux, ip, "https://claude.ai/cb")
		if code != http.StatusCreated {
			t.Fatalf("random register status = %d, body = %v", code, r)
		}
		id, _ := r["client_id"].(string)
		randomIDs = append(randomIDs, id)
	}
	srv.mu.Lock()
	_, pinnedKept := srv.clients[pinnedID]
	_, firstRandomKept := srv.clients[randomIDs[0]]
	srv.mu.Unlock()
	if !pinnedKept {
		t.Fatal("the registration cap evicted the pinned client")
	}
	if firstRandomKept {
		t.Fatal("the cap did not evict the oldest random client (the pinned one must not count)")
	}

	srv.sweep(t0.Add(srv.cfg.ClientRegistrationTTL + time.Hour))
	srv.mu.Lock()
	_, pinnedKept = srv.clients[pinnedID]
	_, lastRandomKept := srv.clients[randomIDs[1]]
	srv.mu.Unlock()
	if !pinnedKept {
		t.Fatal("the TTL sweep removed the pinned client")
	}
	if lastRandomKept {
		t.Fatal("the TTL sweep kept an expired random client")
	}
}

// TestDCRAllowlist_RemovedURIStopsAuthorizing: a pinned registration outlives
// the sweep, so the CURRENT allowlist is re-applied at authorize time; dropping
// a URI from OAUTH_DCR_REDIRECT_URIS revokes it without touching storage.
func TestDCRAllowlist_RemovedURIStopsAuthorizing(t *testing.T) {
	srv := newTestServer(t, withDCRAllowlist)
	mux := newMockRouter()
	srv.Register(mux)
	_, resp := registerURIs(t, mux, "203.0.113.50", dcrPortalCallback, dcrDashCallback)
	clientID, _ := resp["client_id"].(string)

	delete(srv.dcrRedirectURIs, dcrDashCallback) // the operator removed it
	if err := srv.validateClient(context.Background(), clientID, dcrDashCallback); err == nil {
		t.Fatal("a callback removed from the allowlist still authorizes")
	}
	if err := srv.validateClient(context.Background(), clientID, dcrPortalCallback); err != nil {
		t.Fatalf("the callback still on the list stopped authorizing: %v", err)
	}
}

// TestNew_RejectsBadDCRRedirectURIs: the allowlist bypasses the implicit host
// check, so its entries get the same fail-closed validation as preregistered
// clients' redirect_uris.
func TestNew_RejectsBadDCRRedirectURIs(t *testing.T) {
	for _, bad := range []string{
		"http://portal.example.test/cb",
		"https://portal.example.test/cb#frag",
		"https:///cb",
		"https://evil.example.test@portal.example.test/cb",
		`https://portal.example.test\@evil.example.test/cb`,
		"not a url\x7f",
	} {
		cfg := Config{
			Issuer:          testIssuer,
			JWTSecret:       testJWTSecret,
			TelegramOIDC:    newFakeAuthenticator(),
			DCRRedirectURIs: []string{dcrPortalCallback, bad},
		}
		if _, err := New(context.Background(), cfg, newTestStore(t)); err == nil {
			t.Fatalf("New accepted DCR redirect URI %q", bad)
		}
	}
}

// TestDCRAllowlist_NoScopeGetsFullNegotiableScopes pins mctlhq/.github#137
// rule 3 for this server: a client registered through the DCR allowlist that
// names no scope at /oauth/authorize is granted every DCRNegotiableScopes
// entry (for a principal entitled to them), because in automatic mode the
// portal's scope cannot be pinned. A client that names scopes still gets
// exactly those.
func TestDCRAllowlist_NoScopeGetsFullNegotiableScopes(t *testing.T) {
	setup := func(t *testing.T) (*mockRouter, string) {
		srv := newTestServer(t, withDCRAllowlist, func(c *Config) {
			c.ClientTelegramIDs = map[int64]bool{555000111: true}
		})
		mux := newMockRouter()
		srv.Register(mux)
		authFake(srv).identity = &telegramoidc.Identity{TelegramID: 555000111, Username: "pilot_b"}
		seedSession(t, srv, 555000111)
		// No scope in the registration body either: the portal's automatic
		// mode names none anywhere.
		code, resp := registerURIs(t, mux, "203.0.113.60", dcrPortalCallback, dcrDashCallback)
		if code != http.StatusCreated {
			t.Fatalf("register status = %d, body = %v", code, resp)
		}
		id, _ := resp["client_id"].(string)
		return mux, id
	}

	t.Run("no scope", func(t *testing.T) {
		mux, clientID := setup(t)
		resp := scopedAuthCodeTokensFor(t, mux, clientID, dcrPortalCallback, "")
		want := "telegram:dialogs:read telegram:messages:read telegram:messages:send telegram:messages:pin account:manage"
		if got := resp["scope"]; got != want {
			t.Fatalf("scope = %v, want the full negotiable set %q", got, want)
		}
		if strings.Join(DCRNegotiableScopes, " ") != want {
			t.Fatalf("DCRNegotiableScopes changed (%v); update this test and the portal's expectations together", DCRNegotiableScopes)
		}
	})
	t.Run("named scopes are honoured exactly", func(t *testing.T) {
		mux, clientID := setup(t)
		const twoRead = "telegram:dialogs:read telegram:messages:read"
		resp := scopedAuthCodeTokensFor(t, mux, clientID, dcrPortalCallback, twoRead)
		if got := resp["scope"]; got != twoRead {
			t.Fatalf("scope = %v, want exactly %q", got, twoRead)
		}
	})
}
