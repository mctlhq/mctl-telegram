package oauth

import (
	"net/http"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Dynamically registered clients and membership scopes. A client that
// registered itself through /oauth/register is not one the operator vetted,
// so it must not hold admin:users, admin:broadcast or tier groups merely
// because an admin signed it in; only a scope_ceiling record that names
// them grants those, exactly as for an unmapped CIMD client (#1414).

const (
	dcrRandomClientID = "tgmcp_example0123456789ab"
	dcrPinnedClientID = db.PinnedClientIDPrefix + "example0123456789ab"
	dcrCallback       = "https://claude.ai/cb"
)

func dcrAdminGrant(t *testing.T, clientID string, opts ...func(*Config)) (scope string, groups []string, refreshed string) {
	t.Helper()
	srv := newTestServer(t, append([]func(*Config){withDanaInEveryAdminMembership}, opts...)...)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, danaTelegramID)
	resp := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", clientID, dcrCallback, "telegram:dialogs:read")
	c := claimsOf(t, resp["access_token"].(string))
	status, body := refreshResp(t, mux, resp["refresh_token"].(string), clientID)
	if status != http.StatusOK {
		t.Fatalf("refresh = %d %s", status, body)
	}
	return strings.Join(c.Scopes, " "), c.Groups, jsonField(t, body, "scope")
}

func TestDCRClient_AdminGetsNoMembershipScopes(t *testing.T) {
	for name, id := range map[string]string{"random": dcrRandomClientID, "pinned": dcrPinnedClientID} {
		scope, groups, refreshed := dcrAdminGrant(t, id)
		if scope != "telegram:dialogs:read" || refreshed != "telegram:dialogs:read" {
			t.Errorf("%s DCR admin grant scopes = %q refreshed = %q, want only the requested read scope", name, scope, refreshed)
		}
		if len(groups) != 0 {
			t.Errorf("%s DCR admin grant groups = %v, want none", name, groups)
		}
	}
}

// A ceiling record is the operator naming the client, so it is the one way a
// dynamic client keeps a membership scope: the portal is listed this way.
func TestDCRClient_CeilingByRedirectURIKeepsMembership(t *testing.T) {
	scope, _, refreshed := dcrAdminGrant(t, dcrPinnedClientID, func(c *Config) {
		c.ClientProfiles.ScopeCeilingByRedirectURI = map[string][]string{
			dcrCallback: {"telegram:dialogs:read", "admin:users"},
		}
	})
	if !strings.Contains(scope, "admin:users") || !strings.Contains(refreshed, "admin:users") {
		t.Fatalf("listed DCR client scopes = %q refreshed = %q, want admin:users kept", scope, refreshed)
	}
}

// The strip keys on the issued prefix, not on "not a known client": the
// built-in self-connect client and ordinary static client ids are untouched
// (TestScopeCeiling_S1T11 pins today's grant for a client id like claude.ai).
func TestIsDynamicClientID(t *testing.T) {
	for id, want := range map[string]bool{
		dcrRandomClientID:       true,
		dcrPinnedClientID:       true,
		ConnectClientID:         false,
		"claude.ai":             false,
		ceilingClientID:         false,
		"https://x.test/c.json": false,
		"":                      false,
	} {
		if got := isDynamicClientID(id); got != want {
			t.Errorf("isDynamicClientID(%q) = %v, want %v", id, got, want)
		}
	}
}
