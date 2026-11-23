package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// Unmapped CIMD client tests (#1414). A CIMD client no MCP_CLIENT_PROFILES
// record names must never hold membership scopes, whatever the account is,
// and OAUTH_CIMD_UNMAPPED_POLICY=refuse must stop it at /oauth/authorize.

func cimdAdminToken(t *testing.T, opts ...func(*Config)) (scope string, groups []string, refreshedScope string) {
	t.Helper()
	stub := &stubCIMD{}
	stub.set(platformDoc(), nil)
	all := append([]func(*Config){withCIMD(stub), withDanaInEveryAdminMembership}, opts...)
	srv := newTestServer(t, all...)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, danaTelegramID)
	resp := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", cimdClientID, cimdCallback, "telegram:dialogs:read")
	c := claimsOf(t, resp["access_token"].(string))
	status, body := refreshResp(t, mux, resp["refresh_token"].(string), cimdClientID)
	if status != http.StatusOK {
		t.Fatalf("refresh = %d %s", status, body)
	}
	return strings.Join(c.Scopes, " "), c.Groups, jsonField(t, body, "scope")
}

func TestCIMDUnmapped_AdminGetsNoMembershipScopes(t *testing.T) {
	scope, groups, refreshed := cimdAdminToken(t)
	if scope != "telegram:dialogs:read" {
		t.Fatalf("unmapped CIMD admin token scopes = %q, want only the requested read scope", scope)
	}
	if len(groups) != 0 {
		t.Fatalf("unmapped CIMD admin token groups = %v, want none", groups)
	}
	if refreshed != "telegram:dialogs:read" {
		t.Fatalf("refreshed scope = %q, want only the requested read scope", refreshed)
	}
}

// A scope ceiling that names a membership scope is the only way a CIMD
// client holds it: the operator wrote that record.
func TestCIMDUnmapped_CeilingCanStillGrantMembership(t *testing.T) {
	scope, _, _ := cimdAdminToken(t, func(c *Config) {
		c.ClientProfiles.ScopeCeilingByClientID = map[string][]string{
			cimdClientID: {"telegram:dialogs:read", "admin:users"},
		}
	})
	if !strings.Contains(scope, "admin:users") {
		t.Fatalf("ceiling naming admin:users: token scopes = %q, want admin:users kept", scope)
	}
}

// Non-CIMD clients keep today's grant exactly (TestScopeCeiling_S1T11 pins
// it for claude.ai); this pins that the new rule keys on the URL client_id.
func TestCIMDUnmapped_NonCIMDClientUnchanged(t *testing.T) {
	srv := newTestServer(t, withDanaInEveryAdminMembership)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, danaTelegramID)
	resp := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", "claude.ai", "https://claude.ai/cb", "telegram:dialogs:read")
	if got := strings.Join(claimsOf(t, resp["access_token"].(string)).Scopes, " "); !strings.Contains(got, "admin:users") {
		t.Fatalf("non-CIMD client scopes = %q, want today's membership scopes kept", got)
	}
}

func TestCIMDUnmapped_RefusePolicyAtAuthorize(t *testing.T) {
	ctx := context.Background()
	validate := func(policy string, opts ...func(*Config)) error {
		stub := &stubCIMD{}
		stub.set(platformDoc(), nil)
		all := append([]func(*Config){withCIMD(stub), func(c *Config) { c.CIMDUnmappedPolicy = policy }}, opts...)
		return newTestServer(t, all...).validateClient(ctx, cimdClientID, cimdCallback)
	}
	if err := validate("refuse"); !errors.Is(err, errCIMDRefused) {
		t.Fatalf("refuse policy, unmapped client: err = %v, want errCIMDRefused", err)
	}
	for _, policy := range []string{"default-scope", ""} {
		if err := validate(policy); err != nil {
			t.Fatalf("policy %q refused an unmapped client: %v", policy, err)
		}
	}
	mapped := map[string]func(*Config){
		"scope ceiling": func(c *Config) {
			c.ClientProfiles.ScopeCeilingByClientID = map[string][]string{cimdClientID: {"telegram:dialogs:read"}}
		},
		"client_id profile": func(c *Config) {
			c.ClientProfiles.ByClientID = map[string]string{cimdClientID: "core-readonly"}
		},
		"redirect_uri profile": func(c *Config) {
			c.ClientProfiles.ByRedirectURI = map[string]string{cimdCallback: "core-readonly"}
		},
	}
	for name, opt := range mapped {
		if err := validate("refuse", opt); err != nil {
			t.Fatalf("refuse policy refused a client mapped by %s: %v", name, err)
		}
	}
}

// TestRefreshGrantLogCoversClientsWithoutACeiling: the refresh audit line used
// to be written only for ceiling clients, so a refresh by a DCR or unmapped
// CIMD client left no trace of what it held afterwards. It is now written for
// every client, with the groups and whether a ceiling applied.
func TestRefreshGrantLogCoversClientsWithoutACeiling(t *testing.T) {
	stub := &stubCIMD{}
	stub.set(platformDoc(), nil)
	srv := newTestServer(t, withCIMD(stub), withDanaInEveryAdminMembership)
	mux := newMockRouter()
	srv.Register(mux)
	logs := captureServerLogFor(t, srv)
	seedSession(t, srv, danaTelegramID)

	resp := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", cimdClientID, cimdCallback, "telegram:dialogs:read")
	if status, body := refreshResp(t, mux, resp["refresh_token"].(string), cimdClientID); status != http.StatusOK {
		t.Fatalf("refresh = %d %s", status, body)
	}
	out := logs.String()
	if got := strings.Count(out, refreshGrantLine); got != 1 {
		t.Fatalf("a refresh by an unmapped CIMD client logged %d grant lines, want 1:\n%s", got, out)
	}
	var line string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, refreshGrantLine) {
			line = l
		}
	}
	for _, want := range []string{"client_id=" + cimdClientID, "granted_scope=telegram:dialogs:read", `groups=""`, "scope_ceiling_applied=false"} {
		if !strings.Contains(line, want) {
			t.Fatalf("refresh grant line lacks %s:\n%s", want, line)
		}
	}
}
