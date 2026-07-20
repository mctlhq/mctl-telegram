package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurity_ServesHTML(t *testing.T) {
	w := httptest.NewRecorder()
	Security("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/security", nil))
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
		"Communication Agent safety boundary",
		"Crash-safe ingestion",
		"Saved Messages privacy",
		"Human takeover",
		"AGENT_RETENTION_DAYS",
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
	Privacy("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, must := range []string{
		"ChatGPT Apps and MCP users",
		"Data inventory",
		"Communication Agent controls",
		"incoming_events",
		"conversation_messages",
		"agent_actions",
		"AGENT_RETENTION_DAYS",
		"What is NOT stored in logs or audit history",
		"Self-service controls",
		"A human reply marks the conversation",
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

func TestTerms_ServesHTML(t *testing.T) {
	w := httptest.NewRecorder()
	Terms("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/terms", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected text/html, got %q", ct)
	}
	body := w.Body.String()
	for _, must := range []string{
		"Terms of",
		"not affiliated with, endorsed by, or operated by Telegram or OpenAI",
		"your own",
		"gated and dry-run by default",
		"spam",
		"without warranties of any kind",
		"support@mctl.ai",
		// shared chrome — unified with landing/docs
		`class="topbar"`,
		`<a href="/terms" class="active">terms</a>`,
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/terms missing %q", must)
		}
	}
}

func TestLanding_HasTransparencySections(t *testing.T) {
	w := httptest.NewRecorder()
	Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
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
	Docs("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/docs", nil))
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
	Privacy("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	body := w.Body.String()
	if !strings.Contains(body, "support@mctl.ai") {
		t.Fatal("/privacy missing support@mctl.ai")
	}
	if !strings.Contains(body, "ChatGPT Apps and MCP users") {
		t.Fatal("/privacy missing MCP users section")
	}
}

func TestSecurity_MentionsChatGPTOrMCPClients(t *testing.T) {
	w := httptest.NewRecorder()
	Security("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/security", nil))
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
	Security("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/security", nil))
	body := w.Body.String()
	if strings.Contains(body, "api.mctl.ai, verified via shared HMAC") {
		t.Fatal("/security still contains stale trust boundary description")
	}
}

func TestPrivacy_NoStaleAuthModel(t *testing.T) {
	w := httptest.NewRecorder()
	Privacy("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	body := w.Body.String()
	if strings.Contains(body, "GitHub OAuth login proxied through") {
		t.Fatal("/privacy still contains stale GitHub OAuth reference")
	}
	if strings.Contains(body, "api.mctl.ai") {
		t.Fatal("/privacy still references api.mctl.ai as identity provider")
	}
}

func TestAgentPrivacyClaimsDoNotPromiseNoDiskStorage(t *testing.T) {
	w := httptest.NewRecorder()
	Privacy("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	body := w.Body.String()
	for _, stale := range []string{
		"The plaintext of any message you send or receive",
		"Freed when the goroutine returns; never written to disk",
	} {
		if strings.Contains(body, stale) {
			t.Fatalf("/privacy contains stale no-storage claim %q", stale)
		}
	}
	for _, must := range []string{
		"message content is stored in encrypted agent tables",
		"default 30 days",
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/privacy missing agent storage disclosure %q", must)
		}
	}
}

func TestSecuritySeparatesAuditFromAgentContent(t *testing.T) {
	w := httptest.NewRecorder()
	Security("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/security", nil))
	body := w.Body.String()
	for _, must := range []string{
		"Audit rows do not contain Telegram message bodies",
		"Communication Agent message/action tables intentionally store encrypted content",
		"observe",
		"guarded",
		"global kill switch",
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/security missing safety disclosure %q", must)
		}
	}
}

// TestLanding_ManageLinkGatedByShowManage confirms the "manage" nav/footer
// link only renders when showManage is true — /telegram/connect/manage is
// only mounted in local-jwt mode, so a shared-hmac deployment must not link
// to a route that 404s.
func TestLanding_ManageLinkGatedByShowManage(t *testing.T) {
	w := httptest.NewRecorder()
	Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(w.Body.String(), `/telegram/connect/manage`) {
		t.Fatal("showManage=true should render the manage link")
	}

	w = httptest.NewRecorder()
	Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", false).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if strings.Contains(w.Body.String(), `/telegram/connect/manage`) {
		t.Fatal("showManage=false must not render a link to the unmounted manage route")
	}
}