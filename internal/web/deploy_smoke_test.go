//go:build smoke

package web

import (
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// TestPublicPagesSmoke verifies all public pages return 200 and key submission
// content is present. Run against a live server with:
//
//	SMOKE_BASE_URL=https://tg.mctl.ai go test -tags=smoke ./internal/web/ -run TestPublicPagesSmoke -count=1
func TestPublicPagesSmoke(t *testing.T) {
	base := strings.TrimRight(strings.TrimSpace(getenv("SMOKE_BASE_URL", "http://127.0.0.1:8080")), "/")
	paths := []string{"/", "/privacy", "/security", "/docs", "/.well-known/oauth-protected-resource"}
	for _, p := range paths {
		resp, err := http.Get(base + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d", p, resp.StatusCode)
		}
	}
	resp, err := http.Get(base + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(body)
	for _, must := range []string{"support@mctl.ai", `id="chatgpt"`, "Settings &#8594; Apps"} {
		if !strings.Contains(s, must) {
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
