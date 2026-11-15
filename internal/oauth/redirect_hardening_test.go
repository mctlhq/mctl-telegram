package oauth

import (
	"context"
	"strings"
	"testing"
)

// Implicit clients are an explicit opt-in (OAUTH_ALLOW_IMPLICIT_CLIENT
// defaults to false). These cases turn implicit clients on so
// validateClient's host allowlist is what stands between an unregistered
// caller and an arbitrary redirect target. They pin the shapes where the
// host this code approves is not the host a browser would dial — the split
// that turns a host allowlist into an open redirect.
func TestValidateClientRejectsHostSpoofingShapes(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.AllowImplicitClient = true
		c.AllowedImplicitHosts = []string{"claude.ai"}
	})
	ctx := context.Background()

	rejected := []struct {
		name string
		uri  string
	}{
		{"userinfo hides the real host behind an allowlisted one", "https://evil.com@claude.ai/cb"},
		{"userinfo hides the real host behind loopback", "http://evil.com@localhost/cb"},
		{"credentials form", "http://user:pass@127.0.0.1/cb"},
		{"backslash, parsers disagree on the authority", `http://evil.com\@localhost/cb`},
		{"encoded backslash", "http://evil.com%5C@localhost/cb"},
		{"plainly remote", "https://evil.com/cb"},
		{"suffix trick against the allowlist", "https://claude.ai.evil.com/cb"},
		{"loopback-looking suffix", "http://localhost.evil.com/cb"},
		{"http on a non-loopback host", "http://claude.ai/cb"},
	}

	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			if err := srv.validateClient(ctx, "unregistered-client", tc.uri); err == nil {
				t.Errorf("validateClient accepted %q, want rejection", tc.uri)
			}
		})
	}
}

// The hardening must not turn away the callers it exists to serve.
func TestValidateClientAcceptsLegitimateImplicitRedirects(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.AllowImplicitClient = true
		c.AllowedImplicitHosts = []string{"claude.ai"}
	})
	ctx := context.Background()

	accepted := []string{
		"https://claude.ai/api/mcp/auth_callback",
		"http://localhost:3118/callback",
		"http://127.0.0.1:54321/callback",
		"http://[::1]:9000/callback",
		"http://LOCALHOST:3118/callback", // host names are case-insensitive
		"http://LocalHost/cb",
	}

	for _, uri := range accepted {
		if err := srv.validateClient(ctx, "unregistered-client", uri); err != nil {
			t.Errorf("validateClient rejected %q: %v", uri, err)
		}
	}
}

// A registered client is still bound to the exact URIs it registered, and the
// hardening above must not have loosened that.
func TestValidateClientStillScopesRegisteredURIsToTheirClient(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.AllowImplicitClient = false })
	ctx := context.Background()

	if err := srv.validateClient(ctx, "never-registered", "https://claude.ai/cb"); err == nil {
		t.Error("unregistered client accepted while implicit clients are off")
	} else if !strings.Contains(err.Error(), "unknown client_id") {
		t.Errorf("unexpected error for unregistered client: %v", err)
	}
}

// The register endpoint is the other door into the same policy. Hardening only
// the implicit branch of validateClient left this bypass: register the spoofed
// URI, and validateClient's exact-match path for registered clients then
// accepts it verbatim without re-running any host check.
func TestValidateImplicitRedirectURIRejectsTheSameShapes(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.AllowImplicitClient = true
		c.AllowedImplicitHosts = []string{"claude.ai"}
	})

	for _, uri := range []string{
		"https://evil.com@claude.ai/cb",
		"http://evil.com@localhost/cb",
		"http://user:pass@127.0.0.1/cb",
		`http://evil.com\@localhost/cb`,
		"http://evil.com%5C@localhost/cb",
		"https://evil.com/cb",
	} {
		if err := srv.validateImplicitRedirectURI(uri); err == nil {
			t.Errorf("validateImplicitRedirectURI accepted %q — registerable, then exact-matched at authorize", uri)
		}
	}

	for _, uri := range []string{
		"https://claude.ai/api/mcp/auth_callback",
		"http://localhost:3118/callback",
		"http://LOCALHOST:3118/callback",
	} {
		if err := srv.validateImplicitRedirectURI(uri); err != nil {
			t.Errorf("validateImplicitRedirectURI rejected %q: %v", uri, err)
		}
	}
}

func TestValidateImplicitRedirectURIPathPrefix(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.AllowImplicitClient = true
		c.AllowedImplicitHosts = []string{
			"claude.ai",
			"oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-",
			"example.com/oauth/callback",
			"example.test:8443/auth/",
		}
	})

	// Valid path prefix cases
	for _, uri := range []string{
		"https://claude.ai/anything",
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-synthetic0123456789abcdef",
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-anotherhash",
		"https://example.com/oauth/callback",
		"https://example.com/oauth/callback/",
		"https://example.com/oauth/callback/sub",
		"https://example.test:8443/auth/callback",
		"https://example.test:8443/auth/",
		"http://localhost:3000/callback",
	} {
		if err := srv.validateImplicitRedirectURI(uri); err != nil {
			t.Errorf("validateImplicitRedirectURI unexpectedly rejected %q: %v", uri, err)
		}
	}

	// Invalid / rejected cases
	for _, uri := range []string{
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-", // bare prefix without suffix
		"https://oauth-redirect.googleusercontent.com/r/attacker_project",
		"https://oauth-redirect.googleusercontent.com/r/",
		"https://oauth-redirect.googleusercontent.com/",
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-foo/../../evil",
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-foo/%2e%2e/evil",
		"https://oauth-redirect.googleusercontent.com/r/user_bound_custom-mcp-foo/./sub",
		"https://evil.com/r/user_bound_custom-mcp-synthetic0123456789abcdef",
		"https://example.com/oauth/callback_evil",
		"https://example.com/oauth",
		"https://example.com/",
		"https://example.test:8443/auth", // missing trailing slash when prefix has trailing slash
		"https://example.test:8443/evil",
		"https://example.test:9443/auth/callback",
	} {
		if err := srv.validateImplicitRedirectURI(uri); err == nil {
			t.Errorf("validateImplicitRedirectURI unexpectedly accepted %q", uri)
		}
	}
}
