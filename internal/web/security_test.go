package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurity_ServesHTML(t *testing.T) {
	w := httptest.NewRecorder()
	Security().ServeHTTP(w, httptest.NewRequest("GET", "/security", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected text/html, got %q", ct)
	}
	body := w.Body.String()
	for _, must := range []string{
		"Not zero-knowledge",
		"Cryptographic invariants",
		"dmitri+security@mctl.ai",
		"Tamper-evident audit log",
		"Prompt-injection content boundary",
		"Session TTL",
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/security missing %q", must)
		}
	}
}

func TestPrivacy_ServesHTML(t *testing.T) {
	w := httptest.NewRecorder()
	Privacy().ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, must := range []string{
		"Data inventory",
		"What is NOT stored",
		"Self-service controls",
		"audit/verify",
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/privacy missing %q", must)
		}
	}
}

func TestLanding_HasTransparencySections(t *testing.T) {
	w := httptest.NewRecorder()
	Landing("https://tg.mctl.ai", "/mcp").ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, must := range []string{
		"What this is — and what it isn't",
		"not a zero-knowledge service",
		"What we store",
		"Your controls",
		"disconnect_telegram_account",
		`href="/security"`,
		`href="/privacy"`,
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("landing missing %q", must)
		}
	}
}
