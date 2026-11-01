package web

import (
	"net/http"
	"net/http/httptest"
	"os"
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
		// contact cards, in-page nav, and the callout's anchor to Local Bridge
		`<a href="mailto:security@mctl.ai">security@mctl.ai</a>`,
		`<nav class="page-nav" aria-label="On this page">`,
		`id="local-bridge-mode"`,
		`<a href="#local-bridge-mode">Local Bridge mode</a>`,
		"under one App ID",
		// #853
		`id="account-risk"`,
		"The server does not retry a frozen account's refusals.",
		"recover@telegram.org",
		"Cryptographic invariants",
		"security@mctl.ai",
		"support@mctl.ai",
		"End-user support",
		"Claude / ChatGPT / MCP clients",
		"Communication Agent safety boundary",
		"Crash-safe ingestion",
		"Saved Messages privacy",
		"Human takeover",
		"AGENT_RETENTION_DAYS",
		"starts read-only",
		"Tamper-evident audit log",
		"Prompt-injection content boundary",
		"Session TTL",
		// shared chrome — unified with landing/docs
		`class="mctl-site-header"`,
		`class="theme-toggle"`,
		// legal pages left the top nav; the footer still links them
		`<a href="/security">Security</a>`,
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
		"Claude, ChatGPT, and other MCP users",
		"Data inventory",
		`<table class="inventory">`,
		`<col class="col-where">`,
		`<div class="callout">`,
		"Communication Agent controls",
		"incoming_events",
		"conversation_messages",
		"agent_actions",
		"AGENT_RETENTION_DAYS",
		"What is NOT stored in logs or audit history",
		"Self-service controls",
		"A human reply marks the conversation",
		"audit/verify",
		// Telegram API terms §1.5 and §2.2 (#852)
		`id="ai-use"`,
		`<meta name="robots" content="noindex, follow">`,
		"never uses message content, or anything derived from it, to train",
		"switch off any setting that lets the provider use your conversations",
		"MCTL Assistant, an unofficial third-party connector using the Telegram API",
		"privacy@mctl.ai",
		"support@mctl.ai",
		// shared chrome — unified with landing/docs
		`class="mctl-site-header"`,
		`class="theme-toggle"`,
		// legal pages left the top nav; the footer still links them
		`<a href="/privacy">Privacy</a>`,
		// mobile: wide table must sit in a horizontal-scroll wrapper
		`class="table-scroll"`,
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/privacy missing %q", must)
		}
	}
}

// TestPrivacy_DisclosesNotificationState pins the privacy matrix against the
// state issue #438 introduced. Two tables started holding data about a
// person -- which categories they consented to and whether the bot can reach
// them -- and the inventory has to name them, or the page understates what is
// stored. It also pins the two claims that make the consent model meaningful:
// reachability is never learned from a probe, and both tables are removed by
// account deletion.
//
// Separate from TestPrivacy_ServesHTML so a failure says which contract broke.
func TestPrivacy_DisclosesNotificationState(t *testing.T) {
	w := httptest.NewRecorder()
	Privacy("https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/privacy", nil))
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, must := range []string{
		// inventory rows
		"client_notification_prefs",
		"client_bot_reachability",
		// the four reachability states, named rather than summarized
		"cannot_initiate",
		// the no-probe rule, which is the reason reachability is allowed to
		// exist at all
		"no message is ever sent merely to test reachability",
		// deletion, stated per row
		"Removed by account deletion",
		// the consent model
		"never counted as marketing consent",
		// the self-service surfaces, including the no-JavaScript one
		"/api/account/notifications",
		"/telegram/connect/manage",
		"needs no JavaScript",
		"get_my_notification_preferences",
		"set_my_notification_preferences",
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("/privacy does not disclose notification state: missing %q", must)
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
		"not affiliated with, endorsed by, or operated by Telegram, OpenAI, or Anthropic",
		// Telegram API terms §2.2 and §1.5 (#852)
		"unofficial third-party connector using the Telegram API (MTProto)",
		"must not use it to train or fine-tune AI models",
		"your own",
		"read-only by default",
		`<meta name="robots" content="noindex, follow">`,
		"spam",
		"without warranties of any kind",
		"support@mctl.ai",
		// shared chrome — unified with landing/docs
		`class="mctl-site-header"`,
		// legal pages left the top nav; the footer still links them
		`<a href="/terms">Terms</a>`,
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
		"inside Claude</span></h1>",
		"Connect in Claude",
		"MCTL Assistant · Unofficial third-party connector using the Telegram API",
		`id="claude"`,
		"Customize &#8594; Connectors",
		"Add custom connector",
		"claude mcp add --transport http",
		"Read + send",
		"Copy MCP URL",
		// old ChatGPT anchor kept so existing links still land somewhere
		`id="chatgpt"`,
		`id="support"`,
		"Add custom MCP server",
		"chatgpt.com/plugins?directoryTab=personal",
		"claude.ai/new#customize/connectors/yours",
		"MCTL Assistant</code>",
		"support@mctl.ai",
		`id="connect"`,
		"How it works",
		`href="/security"`,
		`href="/privacy"`,
		"Common questions",
		"What does my AI assistant see?",
	} {
		if !strings.Contains(body, must) {
			t.Fatalf("landing missing %q", must)
		}
	}
	// The connector steps both clients replaced: ChatGPT's Settings -> Apps /
	// Developer Mode path and Claude's old /customize/connectors URL.
	for _, gone := range []string{"Settings &#8594; Apps", "Developer Mode", `href="https://claude.ai/customize/connectors"`} {
		if strings.Contains(body, gone) {
			t.Fatalf("landing still has the outdated connector step %q", gone)
		}
	}
}

func TestDocs_ServesHTML(t *testing.T) {
	w := httptest.NewRecorder()
	Docs("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true, false).ServeHTTP(w, httptest.NewRequest("GET", "/docs", nil))
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
		"Connect a client",
		`id="chatgpt-setup"`,
		`id="first-login"`,
		"draft_reply",
		"core-reply",
		"tool-descriptors.json",
		"support@mctl.ai",
		"send_enabled=false",
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
	if !strings.Contains(body, "Claude, ChatGPT, and other MCP users") {
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

// TestLanding_ClaudeFirst pins the client order: the primary call to action
// and the first setup section are Claude's, and ChatGPT is one entry among
// the other clients rather than its own leading section.
func TestLanding_ClaudeFirst(t *testing.T) {
	w := httptest.NewRecorder()
	Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	body := w.Body.String()
	// The primary control is Copy MCP URL, followed by the Claude connectors
	// link (owner decision, 2026-11-01); the Claude setup section still leads
	// the page body below the hero.
	copyAt := strings.Index(body, `<button class="cta-btn" type="button" id="copy-mcp-url"`)
	connectorsAt := strings.Index(body, `href="https://claude.ai/new#customize/connectors/yours"`)
	if copyAt < 0 || connectorsAt < 0 || copyAt > connectorsAt {
		t.Fatalf("hero actions must be Copy MCP URL then Open Claude connectors (copy=%d connectors=%d)", copyAt, connectorsAt)
	}
	claude, chatgpt := strings.Index(body, `id="claude"`), strings.Index(body, `id="chatgpt"`)
	if claude < 0 || chatgpt < 0 || claude > chatgpt {
		t.Fatalf("Claude section must precede ChatGPT (claude=%d chatgpt=%d)", claude, chatgpt)
	}
	if strings.Contains(body, "Connect in ChatGPT") {
		t.Fatal("landing still leads with a ChatGPT section")
	}
}

// TestDocs_NoSubmissionChecklist keeps App Directory submission notes off the
// public reference: they belong in the runbook, and the reviewer-login item
// advertised a password sign-in path to every visitor.
func TestDocs_NoSubmissionChecklist(t *testing.T) {
	w := httptest.NewRecorder()
	Docs("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true, false).ServeHTTP(w, httptest.NewRequest("GET", "/docs", nil))
	body := w.Body.String()
	for _, banned := range []string{
		"Deployment pre-flight checklist",
		"OpenAI Platform Dashboard",
		"password-gated reviewer login",
		"phone &#8594; SMS code",
		"every tool call returns 403",
	} {
		if strings.Contains(body, banned) {
			t.Fatalf("/docs still contains %q", banned)
		}
	}
}

// TestSendGateCopy_PreviewVsError pins the send-gate wording on every page that
// restates it: only send_message and send_media return a dry-run preview; the
// other write tools return a tool error (internal/mcp/tools.go). An earlier
// revision claimed every write tool returned a preview.
func TestSendGateCopy_PreviewVsError(t *testing.T) {
	render := func(h http.HandlerFunc, path string) string {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w.Body.String()
	}
	pages := map[string]string{
		"/":         render(Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true), "/"),
		"/security": render(Security("https://tg.mctl.ai", true), "/security"),
		"/terms":    render(Terms("https://tg.mctl.ai", true), "/terms"),
	}
	for path, body := range pages {
		if !strings.Contains(body, "<code>send_message</code> and <code>send_media</code> return a") {
			t.Errorf("%s: preview claim is not scoped to send_message and send_media", path)
		}
		for _, banned := range []string{"write tools return a preview", "write tools such as <code>send_message</code> return a preview"} {
			if strings.Contains(body, banned) {
				t.Errorf("%s: still contains %q", path, banned)
			}
		}
	}
	if !strings.Contains(pages["/security"], "returns a tool error naming the condition") {
		t.Error("/security: the error path for the other write tools is not stated")
	}
}

// TestLanding_UntestedClientsLabelled keeps support claims to clients with a
// verified sign-in against tg.mctl.ai; the rest carry "not yet tested".
func TestLanding_UntestedClientsLabelled(t *testing.T) {
	w := httptest.NewRecorder()
	Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	body := w.Body.String()
	for _, label := range []string{
		"<strong>Cursor</strong> (not yet tested)",
		"<strong>VS Code</strong> (not yet tested)",
		"<strong>Windsurf and others</strong> (not yet tested)",
	} {
		if !strings.Contains(body, label) {
			t.Errorf("landing missing %q", label)
		}
	}
}

// TestUntestedClients_LabelledEverywhere requires every mention of an
// untested client to sit in the same block (paragraph, list item or FAQ
// answer) as "not yet tested", on the public pages and in README.md and
// LLMS.md, so a reworded support claim cannot slip in unlabelled. It also
// keeps Claude named before ChatGPT in the repository docs, as on the pages.
func TestUntestedClients_LabelledEverywhere(t *testing.T) {
	render := func(h http.HandlerFunc, path string) string {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w.Body.String()
	}
	htmlBlocks := func(s string) []string {
		return strings.FieldsFunc(strings.NewReplacer("</li>", "\x00", "</p>", "\x00", "</dd>", "\x00", "</h1>", "\x00", "</h2>", "\x00", "</h3>", "\x00").Replace(s), func(r rune) bool { return r == 0 })
	}
	mdBlocks := func(s string) []string {
		return strings.Split(strings.NewReplacer("\n- ", "\n\n", "\n* ", "\n\n").Replace(s), "\n\n")
	}
	sources := map[string][]string{
		"/":     htmlBlocks(render(Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true), "/")),
		"/docs": htmlBlocks(render(Docs("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true, false), "/docs")),
	}
	for _, name := range []string{"README.md", "LLMS.md"} {
		b, err := os.ReadFile("../../" + name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		doc := string(b)
		sources[name] = mdBlocks(doc)
		if c, g := strings.Index(doc, "Claude"), strings.Index(doc, "ChatGPT"); c < 0 || (g >= 0 && g < c) {
			t.Errorf("%s: Claude is not named before ChatGPT", name)
		}
	}
	for src, blocks := range sources {
		for _, block := range blocks {
			block = strings.Join(strings.Fields(block), " ")
			for _, client := range []string{"Cursor", "VS Code", "Windsurf"} {
				if strings.Contains(block, client) && !strings.Contains(block, "not yet tested") {
					t.Errorf("%s: %s is named without \"not yet tested\" in: %s", src, client, block)
				}
			}
		}
	}
}
