package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
)

// TestNarrowGrant pins the rule at the unit level so the integration tests
// below can concentrate on the wiring.
func TestNarrowGrant(t *testing.T) {
	admin := []string{"telegram:dialogs:read", "telegram:messages:read", "telegram:messages:send", "telegram:messages:pin", "admin:users", "account:manage"}
	client := []string{"telegram:dialogs:read", "telegram:messages:read", "telegram:messages:send", "telegram:messages:pin", "account:manage"}
	for _, tc := range []struct {
		name      string
		entitled  []string
		requested string
		want      []string
	}{
		{"empty request keeps the entitled set", client, "", client},
		{"whitespace-only request keeps the entitled set", admin, "   ", admin},
		{"client asking for two read scopes gets exactly those", client, "telegram:dialogs:read telegram:messages:read",
			[]string{"telegram:dialogs:read", "telegram:messages:read"}},
		{"admin asking for two read scopes keeps the non-negotiable admin scope, loses send/pin/manage", admin, "telegram:dialogs:read telegram:messages:read",
			[]string{"telegram:dialogs:read", "telegram:messages:read", "admin:users"}},
		{"a scope the identity is not entitled to is not granted", client, "telegram:dialogs:read admin:users",
			[]string{"telegram:dialogs:read"}},
		{"an unknown scope is ignored, not granted", client, "mctl telegram:messages:read",
			[]string{"telegram:messages:read"}},
		{"order follows the entitled list, not the request", client, "telegram:messages:read telegram:dialogs:read",
			[]string{"telegram:dialogs:read", "telegram:messages:read"}},
		{"asking for everything grants everything entitled", client, strings.Join(DCRNegotiableScopes, " "), client},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := narrowGrant(tc.entitled, tc.requested); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("narrowGrant(%v, %q) = %v, want %v", tc.entitled, tc.requested, got, tc.want)
			}
		})
	}
}

// scopedAuthCodeTokens drives authorize (with a scope parameter) → Telegram
// callback → token for the identity the fake authenticator currently returns.
func scopedAuthCodeTokens(t *testing.T, srv *Server, mux *mockRouter, requested string) map[string]any {
	t.Helper()
	verifier, challenge := pkceVerifierAndChallenge()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"claude.ai"},
		"redirect_uri":          {"https://claude.ai/cb"},
		"state":                 {"s"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if requested != "" {
		q.Set("scope", requested)
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, body = %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize redirect: %v", err)
	}
	code := authCodeRedirect(t, callbackWithState(t, mux, loc.Query().Get("state"))).Query().Get("code")
	if code == "" {
		t.Fatal("no authorization code")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", "claude.ai")
	form.Set("redirect_uri", "https://claude.ai/cb")
	form.Set("code_verifier", verifier)
	tokRec := doTokenRequest(t, mux, form)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", tokRec.Code, tokRec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(tokRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

// TestToken_GrantIsNarrowedToRequestedScope is #607 end to end: the token
// endpoint's scope field, which is what the JWT carries, must not contain a
// negotiable scope the client did not ask for — for a client-tier principal
// and for an admin.
func TestToken_GrantIsNarrowedToRequestedScope(t *testing.T) {
	const twoRead = "telegram:dialogs:read telegram:messages:read"

	t.Run("client tier", func(t *testing.T) {
		srv := newTestServer(t, func(c *Config) {
			c.ClientTelegramIDs = map[int64]bool{555000111: true}
		})
		mux := newMockRouter()
		srv.Register(mux)
		authFake(srv).identity = &telegramoidc.Identity{TelegramID: 555000111, Username: "pilot_b"}
		seedSession(t, srv, 555000111)

		resp := scopedAuthCodeTokens(t, srv, mux, twoRead)
		if got := resp["scope"]; got != twoRead {
			t.Fatalf("scope = %v, want exactly %q", got, twoRead)
		}
	})

	t.Run("admin keeps only the non-negotiable admin scope on top", func(t *testing.T) {
		srv := newTestServer(t)
		mux := newMockRouter()
		srv.Register(mux)
		seedSession(t, srv, 500100101)

		resp := scopedAuthCodeTokens(t, srv, mux, twoRead)
		want := twoRead + " admin:users"
		if got := resp["scope"]; got != want {
			t.Fatalf("scope = %v, want %q", got, want)
		}
	})

	t.Run("no scope requested keeps the full entitlement", func(t *testing.T) {
		srv := newTestServer(t, func(c *Config) {
			c.ClientTelegramIDs = map[int64]bool{555000111: true}
		})
		mux := newMockRouter()
		srv.Register(mux)
		authFake(srv).identity = &telegramoidc.Identity{TelegramID: 555000111, Username: "pilot_b"}
		seedSession(t, srv, 555000111)

		resp := scopedAuthCodeTokens(t, srv, mux, "")
		want := strings.Join(DCRNegotiableScopes, " ")
		if got := resp["scope"]; got != want {
			t.Fatalf("scope = %v, want %q", got, want)
		}
	})
}

// TestToken_RefreshDoesNotWidenANarrowedGrant closes the loop with the
// existing refresh bound: a refresh of a narrowed grant returns the narrowed
// set, not the entitlement the identity still holds.
func TestToken_RefreshDoesNotWidenANarrowedGrant(t *testing.T) {
	const twoRead = "telegram:dialogs:read telegram:messages:read"
	srv := newTestServer(t, func(c *Config) {
		c.ClientTelegramIDs = map[int64]bool{555000111: true}
	})
	mux := newMockRouter()
	srv.Register(mux)
	authFake(srv).identity = &telegramoidc.Identity{TelegramID: 555000111, Username: "pilot_b"}
	seedSession(t, srv, 555000111)

	first := scopedAuthCodeTokens(t, srv, mux, twoRead)
	refreshTok, _ := first["refresh_token"].(string)
	if refreshTok == "" {
		t.Fatal("no refresh_token")
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshTok)
	form.Set("client_id", "claude.ai")
	rec := doTokenRequest(t, mux, form)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := resp["scope"]; got != twoRead {
		t.Fatalf("refreshed scope = %v, want exactly %q", got, twoRead)
	}
}
