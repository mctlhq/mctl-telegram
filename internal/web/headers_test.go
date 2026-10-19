package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityHeaders_HTTPSOrigin(t *testing.T) {
	h := SecurityHeaders("https://tg.mctl.ai")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/mcp", nil))
	for k, want := range map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("middleware must pass the request through; code=%d", rec.Code)
	}
}

// A plain-http dev origin must not pin browsers to TLS it does not serve.
func TestSecurityHeaders_NoHSTSOnHTTP(t *testing.T) {
	h := SecurityHeaders("http://127.0.0.1:8080")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("HSTS must be absent on http origin, got %q", got)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("nosniff must be set regardless of scheme")
	}
}

// Every shared-chrome page carries the content-page CSP, and the CSP admits
// exactly the third-party origins the chrome actually references.
func TestChromePages_CarryCSP(t *testing.T) {
	pages := map[string]http.Handler{
		"/":         Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true),
		"/docs":     Docs("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true),
		"/security": Security("https://tg.mctl.ai", true),
		"/privacy":  Privacy("https://tg.mctl.ai", true),
		"/terms":    Terms("https://tg.mctl.ai", true),
		"/demo":     Demo("https://tg.mctl.ai", "", true),
	}
	for path, h := range pages {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: code %d", path, rec.Code)
		}
		if got := rec.Header().Get("Content-Security-Policy"); got != chromeCSP {
			t.Errorf("%s: CSP = %q", path, got)
		}
		body := rec.Body.String()
		for _, origin := range []string{"https://ui.mctl.ai", "https://fonts.googleapis.com", "https://stats.mctl.ai"} {
			if strings.Contains(body, origin) && !strings.Contains(chromeCSP, origin) {
				t.Errorf("%s references %s but chromeCSP does not allow it", path, origin)
			}
		}
	}
}

func TestLanding_CanonicalAndSingleDescription(t *testing.T) {
	rec := httptest.NewRecorder()
	Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `<link rel="canonical" href="https://tg.mctl.ai/">`) {
		t.Error("landing must emit a canonical link")
	}
	if n := strings.Count(body, `<meta name="description"`); n != 1 {
		t.Errorf("landing must have exactly one meta description, got %d", n)
	}
}
