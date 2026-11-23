package cimd

import (
	"errors"
	"net/url"
	"testing"
)

func TestParseAllowedHostsPathScoped(t *testing.T) {
	got, err := ParseAllowedHosts("Pods.Example.Test/oauth/mcp/clients/pod-a/,plat.example.test")
	if err != nil || got[0] != "pods.example.test/oauth/mcp/clients/pod-a/" {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{
		"pods.example.test/x", "pods.example.test/", "pods.example.test//x/",
		"pods.example.test/a/../b/", "pods.example.test/./a/", "pods.example.test/a%2fb/",
		"pods.example.test/%2e%2e/", "pods.example.test:443/a/", "user@pods.example.test/a/",
		"pods.example.test/a/?q/", "pods.example.test/a/#f/", ".example.test/a/", "1.2.3.4/a/",
	} {
		if _, err := ParseAllowedHosts(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestPathScopedMatch(t *testing.T) {
	r := NewResolver(Options{AllowedHosts: []string{"pods.example.test/oauth/mcp/clients/pod-a/"}})
	cases := map[string]bool{
		"https://pods.example.test/oauth/mcp/clients/pod-a/server.json":        true,
		"https://PODS.example.test:443/oauth/mcp/clients/pod-a/server.json":    true,
		"https://pods.example.test/oauth/mcp/clients/pod-b/server.json":        false,
		"https://pods.example.test/oauth/mcp/clients/pod-ab/server.json":       false,
		"https://pods.example.test/oauth/mcp/clients/pod-a":                    false,
		"https://pods.example.test/oauth/mcp/clients/pod-a%2fserver.json":      false,
		"https://pods.example.test/oauth/mcp/clients/pod-a/%252e%252e/pod-b/x": false,
		"https://pods.example.test/OAUTH/mcp/clients/pod-a/x.json":             false,
		"https://pods.example.test/other.json":                                 false,
	}
	for raw, want := range cases {
		u, _ := url.Parse(raw)
		if _, ok := r.match(u); ok != want {
			t.Errorf("%s: got %v want %v", raw, ok, want)
		}
	}
	u, _ := url.Parse("https://pods.example.test/other.json")
	if err := r.missError(u); !errors.Is(err, ErrNotAllowed) {
		t.Fatal(err)
	}
}
