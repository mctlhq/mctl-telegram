package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurity_ServesHTML(t *testing.T) {
	w := httptest.NewRecorder()
	Security("https://tg.mctl.ai").ServeHTTP(w, httptest.NewRequest("GET", "/security", nil))
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
		"security@mctl.ai",
		"support@mctl.ai",
		"End-user support",
		"ChatGPT / Claude / MCP clients",
		"ALLOW_SEND=false",
		"Tamper-evident audit log",
		"Prompt-injection content boundary",
		"Session TTL",
		// shared chrome — unified with landing/docs
		`class="topbar"`,
		"accent-swatch",
		`<a href="/security" class="active">security</a>`,
		// mobile: wide table must sit in a horizontal-scroll wrapper
		`class="table-scroll"`,
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/security missing %q", must)
		}
	}
}

func TestPrivacy_ServesHTML(t *testing.T) {
	w := httptest.NewRecorder()
	Privacy("https://tg.mctl.ai").ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, must := range []string{
		"ChatGPT Apps users",
		"Data inventory",
		"What is NOT stored",
		"Self-service controls",
		"audit/verify",
		"privacy@mctl.ai",
		"support@mctl.ai",
		// shared chrome — unified with landing/docs
		`class="topbar"`,
		"accent-swatch",
		`<a href="/privacy" class="active">privacy</a>`,
		// mobile: wide table must sit in a horizontal-scroll wrapper
		`class="table-scroll"`,
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/privacy missing %q", must)
		}
	}
}

func TestLanding_HasTransparencySections(t *testing.T) {
	w := httptest.NewRecorder()
	Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai").ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, must := range []string{
		"Your Telegram,",
		"inside your AI assistant",
		"Install in ChatGPT",
		"Copy MCP URL",
		`id="chatgpt"`,
		`id="support"`,
		"Settings &#8594; Apps",
		"support@mctl.ai",
		`id="connect"`,
		"How it works",
		`href="/security"`,
		`href="/privacy"`,
		"Common questions",
		"What data does ChatGPT see?",
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("landing missing %q", must)
		}
	}
}

func TestDocs_ServesHTML(t *testing.T) {
	w := httptest.NewRecorder()
	Docs("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai").ServeHTTP(w, httptest.NewRequest("GET", "/docs", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected text/html, got %q", ct)
	}
	body := w.Body.String()
	for _, must := range []string{
		"Available tools",
		"https://tg.mctl.ai/mcp",
		"Apps SDK readiness checklist",
		"chatgpt-setup",
		"support@mctl.ai",
		"ALLOW_SEND=false",
		// mobile: wide tables must sit in horizontal-scroll wrappers
		`class="table-scroll"`,
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/docs missing %q", must)
		}
	}
}

func TestPrivacy_HasSupportContact(t *testing.T) {
	w := httptest.NewRecorder()
	Privacy("https://tg.mctl.ai").ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	body := w.Body.String()
	if !strings.Contains(body, "support@mctl.ai") {
		t.Fatal("/privacy missing support@mctl.ai")
	}
	if !strings.Contains(body, "ChatGPT Apps users") {
		t.Fatal("/privacy missing ChatGPT Apps users section")
	}
}

func TestSecurity_MentionsChatGPTOrMCPClients(t *testing.T) {
	w := httptest.NewRecorder()
	Security("https://tg.mctl.ai").ServeHTTP(w, httptest.NewRequest("GET", "/security", nil))
	body := w.Body.String()
	if strings.Contains(body, "Claude.ai →") {
		t.Fatal("/security still uses Claude-only inbound boundary label")
	}
	if !strings.Contains(body, "ChatGPT") {
		t.Fatal("/security missing ChatGPT in inbound boundary")
	}
}

func TestSecurity_NoStaleAuthModel(t *testing.T) {
	w := httptest.NewRecorder()
	Security("https://tg.mctl.ai").ServeHTTP(w, httptest.NewRequest("GET", "/security", nil))
	body := w.Body.String()
	if strings.Contains(body, "api.mctl.ai, verified via shared HMAC") {
		t.Fatal("/security still contains stale trust boundary description: \"api.mctl.ai, verified via shared HMAC\"")
	}
}

func TestPrivacy_NoStaleAuthModel(t *testing.T) {
	w := httptest.NewRecorder()
	Privacy("https://tg.mctl.ai").ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	body := w.Body.String()
	if strings.Contains(body, "GitHub OAuth login proxied through") {
		t.Fatal("/privacy still contains stale GitHub OAuth reference: \"GitHub OAuth login proxied through\"")
	}
	if strings.Contains(body, "api.mctl.ai") {
		t.Fatal("/privacy still references api.mctl.ai as identity provider")
	}
}
