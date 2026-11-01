package web

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

var inlineScriptRE = regexp.MustCompile(`(?s)<script>(.*?)</script>`)

// The success page carries a Copy MCP URL button, and its CSP allows exactly
// the inline script the page renders, by hash, and nothing else.
func TestConnectSuccess_CopyButtonScriptMatchesCSP(t *testing.T) {
	rec := httptest.NewRecorder()
	renderConnectSuccess(rec, connectSuccessData{ClaudeURL: "https://claude.test", MCPURL: "https://tg.test/mcp"})
	body := rec.Body.String()

	if !strings.Contains(body, `id="copy-mcp-url" data-url="https://tg.test/mcp"`) {
		t.Fatalf("copy button with the MCP URL missing:\n%s", body)
	}
	scripts := inlineScriptRE.FindAllStringSubmatch(body, -1)
	if len(scripts) != 1 {
		t.Fatalf("want exactly 1 inline script, got %d", len(scripts))
	}
	sum := sha256.Sum256([]byte(scripts[0][1]))
	want := "script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, want) {
		t.Errorf("CSP does not pin the rendered script.\nCSP:  %s\nwant: %s", csp, want)
	}
	if strings.Count(csp, "script-src") != 1 || strings.Contains(csp, "script-src 'unsafe") {
		t.Errorf("script-src must be the single hash source: %s", csp)
	}
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("default-src 'none' lost: %s", csp)
	}
}

// Every other connect page keeps a script-free CSP.
func TestConnectOtherPages_NoScriptSrc(t *testing.T) {
	rec := httptest.NewRecorder()
	renderConnectError(rec, "x", "/telegram/connect")
	if csp := rec.Header().Get("Content-Security-Policy"); strings.Contains(csp, "script-src") {
		t.Errorf("error page CSP allows script: %s", csp)
	}
	if strings.Contains(rec.Body.String(), "<script") {
		t.Error("error page renders a script")
	}
}

// The success page joins the MCP URL and its copy button in one bar, keeps
// the Active Sessions note after the first-prompt hint, and makes the
// notifications link a secondary button.
func TestConnectSuccess_Layout(t *testing.T) {
	rec := httptest.NewRecorder()
	renderConnectSuccess(rec, connectSuccessData{ClaudeURL: "https://claude.test", MCPURL: "https://tg.test/mcp"})
	body := rec.Body.String()
	for _, want := range []string{
		`<div class="url-group">`,
		`<input type="text" id="mcp-url" readonly value="https://tg.test/mcp">`,
		`<a class="btn-secondary" href="/telegram/connect/manage?onboarding=1#notifications">Configure bot notifications</a>`,
		"uses to\n       access your account under the permissions you selected.",
		"<li>Sign in</li>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("success page lacks %q", want)
		}
	}
	hint := strings.Index(body, "list my recent Telegram chats")
	note := strings.Index(body, `<p class="note">A new session called`)
	if hint < 0 || note < 0 || note < hint {
		t.Errorf("Active Sessions note must follow the first-prompt hint (hint %d, note %d)", hint, note)
	}
	if strings.Contains(body, "Use this MCP URL") || strings.Contains(body, "read your messages") {
		t.Error("success page keeps replaced copy")
	}
}
