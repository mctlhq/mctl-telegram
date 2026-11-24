package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/oauth/cimd"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

// ChatGPT registers one CIMD client per connector: both the client_id and the
// callback carry the connector's id, so neither is shared between installs.
// These are the shapes its metadata documents had on 2026-11-23.
const (
	chatGPTClientID = "https://chatgpt.com/oauth/pXY-test/client.json"
	chatGPTCallback = "https://chatgpt.com/connector/oauth/pXY-test"
	fiveUserScopes  = "telegram:dialogs:read telegram:messages:read telegram:messages:send telegram:messages:pin account:manage"
)

func chatGPTDoc() cimd.Document {
	return cimd.Document{
		ClientID:     chatGPTClientID,
		ClientName:   "ChatGPT",
		RedirectURIs: []string{chatGPTCallback},
		AuthMethod:   cimd.AuthMethodNone,
	}
}

func fiveScopeRecord(key, value string) string {
	return `{"` + key + `":"` + value + `","scope_ceiling":["` + strings.Join(strings.Fields(fiveUserScopes), `","`) + `"]}`
}

func withBindings(t *testing.T, raw string) func(*Config) {
	t.Helper()
	b, err := toolprofile.ParseBindings(raw)
	if err != nil {
		t.Fatalf("ParseBindings: %v", err)
	}
	return func(c *Config) { c.ClientProfiles = *b }
}

// chatGPTGrantLines signs an admin account in through a ChatGPT connector,
// refreshes once, and returns the access-token scopes and groups, the
// refreshed scope and the two grant log lines.
func chatGPTGrantLines(t *testing.T, bindings string) (scope string, groups []string, refreshed string, lines []string) {
	t.Helper()
	stub := &stubCIMD{}
	stub.set(chatGPTDoc(), nil)
	srv := newTestServer(t, withCIMD(stub), withDanaInEveryAdminMembership, withBindings(t, bindings))
	mux := newMockRouter()
	srv.Register(mux)
	logs := captureServerLogFor(t, srv)
	seedSession(t, srv, danaTelegramID)
	resp := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", chatGPTClientID, chatGPTCallback, "")
	c := claimsOf(t, resp["access_token"].(string))
	status, body := refreshResp(t, mux, resp["refresh_token"].(string), chatGPTClientID)
	if status != http.StatusOK {
		t.Fatalf("refresh = %d %s", status, body)
	}
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "scope_ceiling_applied=") {
			lines = append(lines, l)
		}
	}
	return strings.Join(c.Scopes, " "), c.Groups, jsonField(t, body, "scope"), lines
}

// The record gitops#2983 shipped for ChatGPT named a callback no connector
// uses, and no single redirect_uri record can name the one they do use: it
// differs per connector. Pinned so the reason for client_id_prefix stays
// visible.
func TestScopeCeiling_RedirectRecordMissesPerConnectorCallback(t *testing.T) {
	_, _, _, lines := chatGPTGrantLines(t, "["+fiveScopeRecord("redirect_uri", "https://chatgpt.com/connector_platform_oauth_redirect")+"]")
	if len(lines) != 2 {
		t.Fatalf("grant lines = %d, want the code exchange and the refresh:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	for _, l := range lines {
		if !strings.Contains(l, "scope_ceiling_applied=false") {
			t.Fatalf("a ChatGPT connector was bounded by a redirect_uri record for another callback:\n%s", l)
		}
	}
}

func prefixRecord(prefix, scopes string) string {
	return `[{"client_id_prefix":"` + prefix + `","scope_ceiling":["` + strings.Join(strings.Fields(scopes), `","`) + `"]}]`
}

// A client_id_prefix ceiling bounds a per-connector client on the code
// exchange and on refresh, for an account that holds every admin membership.
func TestScopeCeilingByClientIDPrefix_BoundsExchangeAndRefresh(t *testing.T) {
	scope, groups, refreshed, lines := chatGPTGrantLines(t, prefixRecord("https://chatgpt.com/oauth/", ceilingTwoRead))
	if scope != ceilingTwoRead {
		t.Fatalf("exchange scopes = %q, want the ceiling %q", scope, ceilingTwoRead)
	}
	if len(groups) != 0 {
		t.Fatalf("exchange groups = %v, want none", groups)
	}
	if refreshed != ceilingTwoRead {
		t.Fatalf("refreshed scope = %q, want the ceiling %q", refreshed, ceilingTwoRead)
	}
	if len(lines) != 2 {
		t.Fatalf("grant lines = %d, want the code exchange and the refresh:\n%s", len(lines), strings.Join(lines, "\n"))
	}
	for _, l := range lines {
		if !strings.Contains(l, "scope_ceiling_applied=true") {
			t.Fatalf("a grant below the prefix is not reported as bounded:\n%s", l)
		}
	}
}

// Control for the test above: a prefix the client is not below leaves it on
// the unmapped CIMD policy, so the bound result there is the prefix's doing.
func TestScopeCeilingByClientIDPrefix_OtherPrefixDoesNotBound(t *testing.T) {
	for name, prefix := range map[string]string{
		"sibling path": "https://chatgpt.com/oauthx/",
		"other host":   "https://chat.example.test/oauth/",
	} {
		t.Run(name, func(t *testing.T) {
			scope, _, _, lines := chatGPTGrantLines(t, prefixRecord(prefix, ceilingTwoRead))
			if scope == ceilingTwoRead {
				t.Fatalf("a client outside %s was bounded by its ceiling", prefix)
			}
			if strings.Contains(scope, "admin:") {
				t.Fatalf("an unmapped CIMD client holds a membership scope: %q", scope)
			}
			for _, l := range lines {
				if !strings.Contains(l, "scope_ceiling_applied=false") {
					t.Fatalf("a grant outside the prefix is reported as bounded:\n%s", l)
				}
			}
		})
	}
}

// The ceiling is an allowlist the operator wrote, not the unmapped-CIMD strip
// under another name: a membership scope it names is granted.
func TestScopeCeilingByClientIDPrefix_IsTheCeilingNotTheUnmappedStrip(t *testing.T) {
	scope, _, _, _ := chatGPTGrantLines(t, prefixRecord("https://chatgpt.com/oauth/", "telegram:dialogs:read admin:users"))
	if scope != "telegram:dialogs:read admin:users" {
		t.Fatalf("scopes = %q, want exactly the ceiling", scope)
	}
}

// A ceiling the client_id selects needs no redirect_uri, so a family stored
// before the redirect_uri was kept still refreshes under a prefix ceiling
// while a redirect_uri ceiling exists for someone else. Without a ceiling of
// its own such a family is refused (TestScopeCeilingByRedirect_UnknownRedirectIsRefused).
func TestScopeCeilingByClientIDPrefix_UnknownRedirectStillRefreshes(t *testing.T) {
	stub := &stubCIMD{}
	stub.set(chatGPTDoc(), nil)
	seed := func(t *testing.T, srv *Server) string {
		t.Helper()
		uid, err := srv.store.EnsureUserByTelegramID(context.Background(), danaTelegramID, "dana_tg", "")
		if err != nil {
			t.Fatalf("ensure user: %v", err)
		}
		rt := db.RefreshToken{
			FamilyID: "legacy-prefix", UserID: uid, ClientID: chatGPTClientID, TelegramID: danaTelegramID, TelegramUsername: "dana_tg",
			Scope: "telegram:dialogs:read admin:users", RedirectURIKnown: false, ExpiresAt: time.Now().Add(time.Hour),
		}
		if err := srv.store.SaveRefreshToken(context.Background(), "legacy-prefix-token", rt); err != nil {
			t.Fatalf("save refresh token: %v", err)
		}
		return "legacy-prefix-token"
	}
	t.Run("below the prefix", func(t *testing.T) {
		srv := newTestServer(t, withCIMD(stub), withDanaInEveryAdminMembership, withRedirectCeiling, func(c *Config) {
			c.ClientProfiles.ScopeCeilingByClientIDPrefix = map[string][]string{"https://chatgpt.com/oauth/": strings.Fields(ceilingTwoRead)}
		})
		mux := newMockRouter()
		srv.Register(mux)
		seedSession(t, srv, danaTelegramID)
		status, body := refreshResp(t, mux, seed(t, srv), chatGPTClientID)
		if status != http.StatusOK {
			t.Fatalf("refresh = %d %s, want 200 under the prefix ceiling", status, body)
		}
		if got := jsonField(t, body, "scope"); got != "telegram:dialogs:read" {
			t.Fatalf("scope = %q, want the family's read scope within the ceiling", got)
		}
	})
	t.Run("control: no prefix ceiling", func(t *testing.T) {
		srv := newTestServer(t, withCIMD(stub), withDanaInEveryAdminMembership, withRedirectCeiling)
		mux := newMockRouter()
		srv.Register(mux)
		status, body := refreshResp(t, mux, seed(t, srv), chatGPTClientID)
		if status != http.StatusBadRequest || jsonField(t, body, "error_description") != profileUnresolvableDescription {
			t.Fatalf("refresh = %d %s, want 400 %q", status, body, profileUnresolvableDescription)
		}
	})
}

// OAUTH_CIMD_UNMAPPED_POLICY=refuse admits a CIMD client a prefix ceiling
// names: the operator wrote a record for it.
func TestScopeCeilingByClientIDPrefix_CountsAsMappedForCIMD(t *testing.T) {
	stub := &stubCIMD{}
	stub.set(chatGPTDoc(), nil)
	build := func(prefix string) *Server {
		return newTestServer(t, withCIMD(stub), func(c *Config) {
			c.CIMDUnmappedPolicy = CIMDPolicyRefuse
			c.ClientProfiles.ScopeCeilingByClientIDPrefix = map[string][]string{prefix: strings.Fields(ceilingTwoRead)}
		})
	}
	if err := build("https://chatgpt.com/oauthx/").validateClient(context.Background(), chatGPTClientID, chatGPTCallback); err == nil {
		t.Fatal("control: a CIMD client below no prefix was admitted under the refuse policy")
	}
	if err := build("https://chatgpt.com/oauth/").validateClient(context.Background(), chatGPTClientID, chatGPTCallback); err != nil {
		t.Fatalf("a CIMD client below a prefix ceiling was refused: %v", err)
	}
}

// The mint refuses a token wider than a prefix ceiling, like any other.
func TestScopeCeilingByClientIDPrefix_MintRefusesAWiderToken(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.ClientProfiles.ScopeCeilingByClientIDPrefix = map[string][]string{"https://chatgpt.com/oauth/": strings.Fields(ceilingTwoRead)}
	})
	origin := tokenOrigin{ClientID: chatGPTClientID, RedirectURI: chatGPTCallback, RedirectURIKnown: true}
	if _, err := srv.mintAccessToken(origin, danaTelegramID, "dana_tg", nil, []string{"telegram:dialogs:read", "admin:users"}); !errors.Is(err, errScopeCeilingViolated) {
		t.Fatalf("mint of a token wider than the prefix ceiling = %v, want errScopeCeilingViolated", err)
	}
	if _, err := srv.mintAccessToken(origin, danaTelegramID, "dana_tg", nil, strings.Fields(ceilingTwoRead)); err != nil {
		t.Fatalf("mint within the prefix ceiling: %v", err)
	}
}

func TestScopeCeilingByClientIDPrefix_MalformedFailsConstruction(t *testing.T) {
	for name, tc := range map[string]struct {
		prefix  string
		ceiling []string
		want    string
	}{
		"unknown scope": {"https://chatgpt.com/oauth/", []string{"telegram:dialog:read"}, `names "telegram:dialog:read"`},
		"empty":         {"https://chatgpt.com/oauth/", []string{}, "is empty"},
		"not a prefix":  {"https://chatgpt.com/oauth", strings.Fields(ceilingTwoRead), `must end with "/"`},
		"http":          {"http://chatgpt.com/oauth/", strings.Fields(ceilingTwoRead), "must start with https://"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(context.Background(), Config{
				Issuer: testIssuer, JWTSecret: testJWTSecret, TelegramOIDC: newFakeAuthenticator(),
				ClientProfiles: toolprofile.Bindings{ScopeCeilingByClientIDPrefix: map[string][]string{tc.prefix: tc.ceiling}},
			}, newTestStore(t))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
