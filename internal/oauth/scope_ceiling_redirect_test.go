package oauth

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

// A scope ceiling keyed by redirect_uri bounds every client that authorizes
// with that exact callback, which is how a client without a stable client_id
// (ChatGPT's per-install CIMD ids, DCR) gets a ceiling.
const redirectCeilingCallback = "https://claude.ai/cb"

func withRedirectCeiling(c *Config) {
	c.ClientProfiles.ScopeCeilingByRedirectURI = map[string][]string{
		redirectCeilingCallback: strings.Fields(ceilingTwoRead),
	}
}

func TestScopeCeilingByRedirect_BoundsExchangeAndRefresh(t *testing.T) {
	srv := newTestServer(t, withDanaInEveryAdminMembership, withRedirectCeiling)
	mux := newMockRouter()
	srv.Register(mux)
	logs := captureServerLogFor(t, srv)
	seedSession(t, srv, danaTelegramID)

	// An admin account signing in through the bound callback holds only the
	// ceiling: no membership scope, no tier group.
	bound := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", "claude.ai", redirectCeilingCallback, "")
	c := claimsOf(t, bound["access_token"].(string))
	if got := strings.Join(c.Scopes, " "); got != ceilingTwoRead {
		t.Fatalf("bound exchange scopes = %q, want %q", got, ceilingTwoRead)
	}
	if len(c.Groups) != 0 {
		t.Fatalf("bound exchange groups = %v, want none", c.Groups)
	}

	// Control: the same account and client_id through another callback keeps
	// today's grant, so the bound result is the ceiling's doing.
	other := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", "claude.ai", "https://claude.ai/other", "")
	if got := claimsOf(t, other["access_token"].(string)).Scopes; !strings.Contains(strings.Join(got, " "), "admin:users") {
		t.Fatalf("control scopes = %v, want the membership scopes kept off the bound callback", got)
	}

	// The ceiling is re-applied at refresh.
	status, body := refreshResp(t, mux, bound["refresh_token"].(string), "claude.ai")
	if status != http.StatusOK {
		t.Fatalf("refresh = %d %s", status, body)
	}
	if got := jsonField(t, body, "scope"); got != ceilingTwoRead {
		t.Fatalf("refreshed scope = %q, want %q", got, ceilingTwoRead)
	}
	if !strings.Contains(logs.String(), "scope_ceiling_applied=true") {
		t.Fatalf("no grant line reports the ceiling as applied:\n%s", logs.String())
	}
}

// A refresh family that predates redirect_uri storage cannot be matched
// against a redirect_uri ceiling, so it is refused rather than minted wider
// than the operator allowed.
func TestScopeCeilingByRedirect_UnknownRedirectIsRefused(t *testing.T) {
	srv := newTestServer(t, withDanaInEveryAdminMembership, withRedirectCeiling)
	mux := newMockRouter()
	srv.Register(mux)
	uid, err := srv.store.EnsureUserByTelegramID(context.Background(), danaTelegramID, "dana_tg", "")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	rt := db.RefreshToken{
		FamilyID: "legacy-redirect-ceiling", UserID: uid, ClientID: "claude.ai", TelegramID: danaTelegramID, TelegramUsername: "dana_tg",
		Scope: "telegram:dialogs:read admin:users", RedirectURIKnown: false, ExpiresAt: time.Now().Add(time.Hour),
	}
	const plain = "legacy-redirect-ceiling-token"
	if err := srv.store.SaveRefreshToken(context.Background(), plain, rt); err != nil {
		t.Fatalf("save refresh token: %v", err)
	}
	status, body := refreshResp(t, mux, plain, "claude.ai")
	if status != http.StatusBadRequest || jsonField(t, body, "error_description") != profileUnresolvableDescription {
		t.Fatalf("refresh of a family with no stored redirect_uri = %d %s, want 400 %q", status, body, profileUnresolvableDescription)
	}
}

// An unmapped CIMD client is "mapped" once a redirect_uri ceiling names its
// callback, so OAUTH_CIMD_UNMAPPED_POLICY=refuse lets it through.
func TestScopeCeilingByRedirect_CountsAsMappedForCIMD(t *testing.T) {
	stub := &stubCIMD{}
	stub.set(platformDoc(), nil)
	build := func(opts ...func(*Config)) *Server {
		all := append([]func(*Config){withCIMD(stub), func(c *Config) { c.CIMDUnmappedPolicy = CIMDPolicyRefuse }}, opts...)
		return newTestServer(t, all...)
	}
	if err := build().validateClient(context.Background(), cimdClientID, cimdCallback); err == nil {
		t.Fatal("control: an unmapped CIMD client was admitted under the refuse policy")
	}
	mapped := build(func(c *Config) {
		c.ClientProfiles.ScopeCeilingByRedirectURI = map[string][]string{cimdCallback: strings.Fields(ceilingTwoRead)}
	})
	if err := mapped.validateClient(context.Background(), cimdClientID, cimdCallback); err != nil {
		t.Fatalf("a CIMD client whose callback has a redirect_uri ceiling was refused: %v", err)
	}
}

func TestScopeCeilingByRedirect_MalformedFailsConstruction(t *testing.T) {
	for name, tc := range map[string]struct {
		uri     string
		ceiling []string
		want    string
	}{
		"unknown scope":    {redirectCeilingCallback, []string{"telegram:dialog:read"}, `names "telegram:dialog:read"`},
		"empty":            {redirectCeilingCallback, []string{}, "is empty"},
		"self-connect uri": {testIssuer + "/telegram/connect/done", strings.Fields(ceilingTwoRead), "self-connect"},
		"unacceptable uri": {"http://claude.example.test/cb", strings.Fields(ceilingTwoRead), "can never match"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), Config{
				Issuer: testIssuer, JWTSecret: testJWTSecret, TelegramOIDC: newFakeAuthenticator(),
				ClientProfiles: toolprofile.Bindings{ScopeCeilingByRedirectURI: map[string][]string{tc.uri: tc.ceiling}},
			}, newTestStore(t))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
