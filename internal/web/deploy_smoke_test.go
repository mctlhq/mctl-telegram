//go:build smoke

package web

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// smokeClient bounds every probe so a stalled host fails the run instead of
// hanging the CI job until the runner kills it.
var smokeClient = &http.Client{Timeout: 15 * time.Second}

// fetch GETs base+path and returns the status code and body, failing the test
// on transport errors.
func fetch(t *testing.T, base, path string) (int, []byte) {
	t.Helper()
	resp, err := smokeClient.Get(base + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp.StatusCode, body
}

// TestPublicPagesSmoke verifies all public pages return 200 and key submission
// content is present. Run against a live server with:
//
//	SMOKE_BASE_URL=https://tg.mctl.ai go test -tags=smoke ./internal/web/ -run TestPublicPagesSmoke -count=1
func TestPublicPagesSmoke(t *testing.T) {
	base := strings.TrimRight(strings.TrimSpace(getenv("SMOKE_BASE_URL", "http://127.0.0.1:8080")), "/")

	// Landing is checked separately below for content; the rest just need 200.
	for _, p := range []string{"/privacy", "/security", "/docs"} {
		if code, _ := fetch(t, base, p); code != http.StatusOK {
			t.Fatalf("GET %s: status %d", p, code)
		}
	}

	// OAuth discovery: the protected-resource document is served in every
	// AUTH_MODE and advertises the authorization server. On the hosted
	// local-jwt deployment the authorization-server metadata is on this host
	// too; assert both resolve and parse as JSON with the expected keys.
	code, body := fetch(t, base, "/.well-known/oauth-protected-resource")
	if code != http.StatusOK {
		t.Fatalf("GET /.well-known/oauth-protected-resource: status %d", code)
	}
	var prMeta struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.Unmarshal(body, &prMeta); err != nil {
		t.Fatalf("protected-resource metadata is not valid JSON: %v", err)
	}
	if len(prMeta.AuthorizationServers) == 0 {
		t.Fatal("protected-resource metadata advertises no authorization_servers")
	}

	code, body = fetch(t, base, "/.well-known/oauth-authorization-server")
	if code != http.StatusOK {
		t.Fatalf("GET /.well-known/oauth-authorization-server: status %d (expected on local-jwt hosts)", code)
	}
	var asMeta struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(body, &asMeta); err != nil {
		t.Fatalf("authorization-server metadata is not valid JSON: %v", err)
	}
	if asMeta.Issuer == "" || asMeta.TokenEndpoint == "" {
		t.Fatalf("authorization-server metadata missing issuer/token_endpoint: %+v", asMeta)
	}

	// OpenAI Apps domain verification: the submission flow pings this origin-root
	// well-known path and expects the verification token back as plain text.
	if code, body := fetch(t, base, "/.well-known/openai-apps-challenge"); code != http.StatusOK {
		t.Fatalf("GET /.well-known/openai-apps-challenge: status %d", code)
	} else if got := strings.TrimSpace(string(body)); got == "" {
		t.Fatal("openai-apps-challenge returned an empty token")
	}

	code, body = fetch(t, base, "/")
	if code != http.StatusOK {
		t.Fatalf("GET /: status %d", code)
	}
	landing := string(body)
	// Do not assert on the support email literal: Cloudflare Email Obfuscation
	// rewrites mailto addresses into /cdn-cgi/l/email-protection blobs on the
	// live host, so "support@mctl.ai" never appears verbatim. Assert on stable
	// structural markers instead.
	for _, must := range []string{`id="chatgpt"`, `id="support"`, "Settings &#8594; Apps"} {
		if !strings.Contains(landing, must) {
			t.Fatalf("landing missing %q", must)
		}
	}
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
