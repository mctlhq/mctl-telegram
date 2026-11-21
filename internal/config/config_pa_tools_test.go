package config

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// Synthetic values only: example hosts, a key of 32 zero-free test bytes.
var testPAKEKKey = base64.StdEncoding.EncodeToString([]byte("pa-tools-test-kek-not-real-32byt"))

// paToolsEnv is a complete, valid tools configuration with tg enabled.
func paToolsEnv() map[string]string {
	return map[string]string{
		"ENV":                                 "preview",
		"PA_KEK_MODE":                         "local",
		"PA_KEK_LOCAL_KEY":                    testPAKEKKey,
		"PA_BOT_USERNAME":                     "pa_example_bot",
		"PA_MINI_APP_NAME":                    "link",
		"PA_APP_URL":                          "https://pa.example/pa/link/app",
		"PA_SERVER_TG_ENABLED":                "true",
		"PA_SERVER_TG_CLIENT_ID":              "pa-preview",
		"PA_SERVER_TG_ISSUER":                 "https://tg.example",
		"PA_SERVER_TG_AUTHORIZATION_ENDPOINT": "https://tg.example/oauth/authorize",
		"PA_SERVER_TG_TOKEN_ENDPOINT":         "https://tg.example/oauth/token",
		"PA_SERVER_TG_REVOCATION_ENDPOINT":    "https://tg.example/oauth/revoke",
		"PA_SERVER_TG_MCP_URL":                "https://tg.example/mcp",
		"PA_SERVER_TG_RESOURCE":               "https://tg.example/mcp",
		"PA_SERVER_TG_ALLOWED_HOSTS":          "tg.example",
	}
}

func paToolsConfig() *Config {
	return &Config{PAEnabled: true, PublicBaseURL: "https://pa.example"}
}

func getenvFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadPATools_Valid(t *testing.T) {
	got, err := LoadPATools(paToolsConfig(), getenvFrom(paToolsEnv()))
	if err != nil {
		t.Fatalf("LoadPATools: %v", err)
	}
	tg := got.Servers[connection.ServerTG]
	if !tg.Enabled || tg.RedirectURI != "https://pa.example/pa/oauth/callback/tg" || tg.ClientID != "pa-preview" ||
		tg.RevocationEndpoint != "https://tg.example/oauth/revoke" || len(tg.AllowedHosts) != 1 || tg.PromptConsent {
		t.Fatalf("tg = %+v", tg)
	}
	if got.Servers[connection.ServerAlice].Enabled {
		t.Fatal("alice enabled")
	}
	if got.KEK.Mode != connection.KEKModeLocal || len(got.KEK.LocalKey) != 32 || got.AppURL != "https://pa.example/pa/link/app" {
		t.Fatalf("kek/app = %+v %q", got.KEK.Mode, got.AppURL)
	}
}

// With PA_ENABLED off nothing is read, not even a malformed flag.
func TestLoadPATools_InertWithoutPAEnabled(t *testing.T) {
	read := 0
	got, err := LoadPATools(&Config{}, func(string) string { read++; return "garbage" })
	if err != nil || got != nil || read != 0 {
		t.Fatalf("LoadPATools with PA off = %v, %v, %d reads", got, err, read)
	}
}

// A disabled server needs nothing, and nothing else of it is read: with
// every server off, only the flags are read.
func TestLoadPATools_DisabledServerNeedsNothing(t *testing.T) {
	var reads []string
	got, err := LoadPATools(paToolsConfig(), func(k string) string {
		reads = append(reads, k)
		if k == "PA_SERVER_TG_ENABLED" {
			return "false"
		}
		return ""
	})
	if err != nil || got.AnyEnabled() {
		t.Fatalf("LoadPATools = %+v, %v", got, err)
	}
	for _, k := range reads {
		if !strings.HasSuffix(k, "_ENABLED") {
			t.Errorf("read %s with every server disabled", k)
		}
	}
}

// Every missing or malformed setting of an enabled configuration refuses
// to load, naming the variable and never the value.
func TestLoadPATools_FailClosed(t *testing.T) {
	const secretish = "VALUE-MUST-NOT-LEAK"
	cases := []struct {
		name string
		set  map[string]string
		want string
	}{
		{"malformed flag", map[string]string{"PA_SERVER_TG_ENABLED": "yes"}, "PA_SERVER_TG_ENABLED"},
		{"malformed alice flag", map[string]string{"PA_SERVER_ALICE_ENABLED": "1"}, "PA_SERVER_ALICE_ENABLED"},
		{"alice enabled", map[string]string{"PA_SERVER_ALICE_ENABLED": "true"}, "PA_SERVER_ALICE_ENABLED"},
		// A complete alice registration is still refused: there is no
		// account source to verify its links.
		{"alice fully configured", map[string]string{
			"PA_SERVER_ALICE_ENABLED":                "true",
			"PA_SERVER_ALICE_CLIENT_ID":              "pa-preview",
			"PA_SERVER_ALICE_ISSUER":                 "https://alice.example",
			"PA_SERVER_ALICE_AUTHORIZATION_ENDPOINT": "https://alice.example/oauth/authorize",
			"PA_SERVER_ALICE_TOKEN_ENDPOINT":         "https://alice.example/oauth/token",
			"PA_SERVER_ALICE_MCP_URL":                "https://alice.example/mcp",
			"PA_SERVER_ALICE_RESOURCE":               "https://alice.example/mcp",
			"PA_SERVER_ALICE_ALLOWED_HOSTS":          "alice.example",
		}, "alice has no account source"},
		{"no kek mode", map[string]string{"PA_KEK_MODE": ""}, "PA_KEK_MODE"},
		{"unknown kek mode", map[string]string{"PA_KEK_MODE": secretish}, "PA_KEK_MODE"},
		{"transit kek", map[string]string{"PA_KEK_MODE": "transit"}, "transit"},
		{"local kek outside preview", map[string]string{"ENV": ""}, "PA_KEK_MODE=local"},
		{"local kek short", map[string]string{"PA_KEK_LOCAL_KEY": base64.StdEncoding.EncodeToString([]byte(secretish))}, "PA_KEK_LOCAL_KEY"},
		{"local kek not base64", map[string]string{"PA_KEK_LOCAL_KEY": secretish + "!!"}, "PA_KEK_LOCAL_KEY"},
		{"no bot username", map[string]string{"PA_BOT_USERNAME": ""}, "PA_BOT_USERNAME"},
		{"bad bot username", map[string]string{"PA_BOT_USERNAME": secretish}, "PA_BOT_USERNAME"},
		{"no mini app", map[string]string{"PA_MINI_APP_NAME": ""}, "PA_MINI_APP_NAME"},
		{"no client id", map[string]string{"PA_SERVER_TG_CLIENT_ID": ""}, "PA_SERVER_TG_CLIENT_ID"},
		{"no issuer", map[string]string{"PA_SERVER_TG_ISSUER": ""}, "PA_SERVER_TG_ISSUER"},
		{"http issuer", map[string]string{"PA_SERVER_TG_ISSUER": "http://tg.example/" + secretish}, "PA_SERVER_TG_ISSUER"},
		{"issuer with query", map[string]string{"PA_SERVER_TG_ISSUER": "https://tg.example/?" + secretish}, "PA_SERVER_TG_ISSUER"},
		{"no authorization endpoint", map[string]string{"PA_SERVER_TG_AUTHORIZATION_ENDPOINT": ""}, "PA_SERVER_TG_AUTHORIZATION_ENDPOINT"},
		{"no token endpoint", map[string]string{"PA_SERVER_TG_TOKEN_ENDPOINT": ""}, "PA_SERVER_TG_TOKEN_ENDPOINT"},
		{"token endpoint userinfo", map[string]string{"PA_SERVER_TG_TOKEN_ENDPOINT": "https://" + secretish + "@tg.example/t"}, "PA_SERVER_TG_TOKEN_ENDPOINT"},
		{"token endpoint port", map[string]string{"PA_SERVER_TG_TOKEN_ENDPOINT": "https://tg.example:8443/t"}, "PA_SERVER_TG_TOKEN_ENDPOINT"},
		{"token host off allowlist", map[string]string{"PA_SERVER_TG_TOKEN_ENDPOINT": "https://other.example/t"}, "PA_SERVER_TG_TOKEN_ENDPOINT"},
		{"revocation host off allowlist", map[string]string{"PA_SERVER_TG_REVOCATION_ENDPOINT": "https://other.example/r"}, "PA_SERVER_TG_REVOCATION_ENDPOINT"},
		{"revocation fragment", map[string]string{"PA_SERVER_TG_REVOCATION_ENDPOINT": "https://tg.example/r#" + secretish}, "PA_SERVER_TG_REVOCATION_ENDPOINT"},
		{"no mcp url", map[string]string{"PA_SERVER_TG_MCP_URL": ""}, "PA_SERVER_TG_MCP_URL"},
		{"mcp host off allowlist", map[string]string{"PA_SERVER_TG_MCP_URL": "https://other.example/mcp"}, "PA_SERVER_TG_MCP_URL"},
		{"issuer host off allowlist", map[string]string{"PA_SERVER_TG_ISSUER": "https://other.example"}, "PA_SERVER_TG_ISSUER"},
		{"no resource", map[string]string{"PA_SERVER_TG_RESOURCE": ""}, "PA_SERVER_TG_RESOURCE"},
		{"no allowed hosts", map[string]string{"PA_SERVER_TG_ALLOWED_HOSTS": ""}, "PA_SERVER_TG_ALLOWED_HOSTS"},
		{"allowed host with port", map[string]string{"PA_SERVER_TG_ALLOWED_HOSTS": "tg.example:443"}, "PA_SERVER_TG_ALLOWED_HOSTS"},
		{"allowed host wildcard", map[string]string{"PA_SERVER_TG_ALLOWED_HOSTS": "*.example"}, "PA_SERVER_TG_ALLOWED_HOSTS"},
		{"allowed host empty entry", map[string]string{"PA_SERVER_TG_ALLOWED_HOSTS": "tg.example,"}, "PA_SERVER_TG_ALLOWED_HOSTS"},
		{"malformed prompt consent", map[string]string{"PA_SERVER_TG_PROMPT_CONSENT": secretish}, "PA_SERVER_TG_PROMPT_CONSENT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := paToolsEnv()
			for k, v := range tc.set {
				env[k] = v
			}
			got, err := LoadPATools(paToolsConfig(), getenvFrom(env))
			if err == nil {
				t.Fatalf("loaded %+v, want a refusal naming %s", got, tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %s", err, tc.want)
			}
			if strings.Contains(err.Error(), secretish) || strings.Contains(err.Error(), "tg.example") || strings.Contains(err.Error(), testPAKEKKey) {
				t.Errorf("error %q carries a value", err)
			}
		})
	}
}

// PA_APP_URL must be exactly PUBLIC_BASE_URL + /pa/link/app, the URL the
// web_app button may carry; PUBLIC_BASE_URL must be an https origin.
func TestLoadPATools_AppURLMustBeOrigin(t *testing.T) {
	for _, app := range []string{
		"", "https://pa.example/pa/link/app/", "https://pa.example/pa/link/app?x=1", "http://pa.example/pa/link/app",
		"https://other.example/pa/link/app", "https://PA.example/pa/link/app", "https://pa.example/pa/link/APP",
	} {
		env := paToolsEnv()
		env["PA_APP_URL"] = app
		if _, err := LoadPATools(paToolsConfig(), getenvFrom(env)); err == nil || !strings.Contains(err.Error(), "PA_APP_URL") {
			t.Errorf("PA_APP_URL %q: err = %v", app, err)
		}
	}
	// A trailing slash on the base is not part of the origin.
	c := paToolsConfig()
	c.PublicBaseURL = "https://pa.example/"
	if _, err := LoadPATools(c, getenvFrom(paToolsEnv())); err != nil {
		t.Errorf("base with trailing slash: %v", err)
	}
	for _, base := range []string{"http://pa.example", "https://pa.example/sub", "https://pa.example?x", ""} {
		c := paToolsConfig()
		c.PublicBaseURL = base
		if _, err := LoadPATools(c, getenvFrom(paToolsEnv())); err == nil || !strings.Contains(err.Error(), "PUBLIC_BASE_URL") {
			t.Errorf("PUBLIC_BASE_URL %q: err = %v", base, err)
		}
	}
}

// A revocation endpoint is optional (RFC 7009 is not universal).
func TestLoadPATools_RevocationOptional(t *testing.T) {
	env := paToolsEnv()
	delete(env, "PA_SERVER_TG_REVOCATION_ENDPOINT")
	got, err := LoadPATools(paToolsConfig(), getenvFrom(env))
	if err != nil || got.Servers[connection.ServerTG].RevocationEndpoint != "" {
		t.Fatalf("without revocation endpoint: %+v, %v", got, err)
	}
}
