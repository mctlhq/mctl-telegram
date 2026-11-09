package config

import (
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func valid() map[string]string {
	return map[string]string{
		"GLOVO_MCP_ENABLED":             "true",
		"GLOVO_MCP_PUBLIC_BASE_URL":     "https://glovo.mctl.ai",
		"GLOVO_MCP_ISSUER":              "https://api.mctl.ai",
		"GLOVO_MCP_JWKS_URL":            "https://api.mctl.ai/jwks.json",
		"GLOVO_MCP_API_BASE_URL":        "https://api.mctl.ai",
		"GLOVO_MCP_API_CREDENTIAL_FILE": "/run/secrets/cred",
	}
}

func TestDefaultsDisabled(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled || c.RatePerMin != 30 || c.Burst != 10 || c.MaxInflight != 64 || c.Addr != ":8080" {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestValid(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Resource != ContractResource || c.AuthorizationServer != "https://api.mctl.ai" {
		t.Fatalf("derived values: %+v", c)
	}
}

func TestInvalid(t *testing.T) {
	cases := map[string]func(m map[string]string){
		"missing base":         func(m map[string]string) { delete(m, "GLOVO_MCP_PUBLIC_BASE_URL") },
		"missing issuer":       func(m map[string]string) { delete(m, "GLOVO_MCP_ISSUER") },
		"missing jwks":         func(m map[string]string) { delete(m, "GLOVO_MCP_JWKS_URL") },
		"missing api":          func(m map[string]string) { delete(m, "GLOVO_MCP_API_BASE_URL") },
		"missing cred":         func(m map[string]string) { delete(m, "GLOVO_MCP_API_CREDENTIAL_FILE") },
		"http jwks":            func(m map[string]string) { m["GLOVO_MCP_JWKS_URL"] = "http://api.mctl.ai/jwks.json" },
		"http loopback no dev": func(m map[string]string) { m["GLOVO_MCP_API_BASE_URL"] = "http://127.0.0.1:9" },
		"http dev non-loop": func(m map[string]string) {
			m["GLOVO_MCP_DEV"] = "true"
			m["GLOVO_MCP_API_BASE_URL"] = "http://api.mctl.ai"
		},
		"query in url":   func(m map[string]string) { m["GLOVO_MCP_ISSUER"] = "https://api.mctl.ai?x=1" },
		"wrong resource": func(m map[string]string) { m["GLOVO_MCP_RESOURCE"] = "https://tg.mctl.ai/mcp" },
		"bad bool":       func(m map[string]string) { m["GLOVO_MCP_ENABLED"] = "maybe" },
		"bad rate":       func(m map[string]string) { m["GLOVO_MCP_RATE_PER_MIN"] = "0" },
		"bad cidr":       func(m map[string]string) { m["GLOVO_MCP_METRICS_ALLOW_CIDR"] = "nope" },
	}
	for name, mut := range cases {
		m := valid()
		mut(m)
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDevLoopbackAndResourceOverride(t *testing.T) {
	m := valid()
	m["GLOVO_MCP_DEV"] = "true"
	m["GLOVO_MCP_API_BASE_URL"] = "http://127.0.0.1:9000"
	m["GLOVO_MCP_JWKS_URL"] = "http://localhost:9000/jwks.json"
	m["GLOVO_MCP_PUBLIC_BASE_URL"] = "http://127.0.0.1:8080"
	if _, err := Load(env(m)); err != nil {
		t.Fatal(err)
	}
}

func TestNoTenantEnv(t *testing.T) {
	// The loader has no tenant-bearing field and ignores a stray variable.
	m := valid()
	m["GLOVO_MCP_TENANT"] = "labs"
	c, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(c.Issuer+c.Resource+c.APIBaseURL), "labs") {
		t.Fatal("tenant env leaked into config")
	}
}
