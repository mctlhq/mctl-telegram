package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The embedded copy exists only because go:embed cannot reach ../../docs.
// Nothing stops the two files from drifting except this test, and a setup
// guide that disagrees with the repository is worse than no page at all —
// the reader has no way to tell which half is stale.
func TestLocalBridgeMarkdownMatchesDocs(t *testing.T) {
	canonical, err := os.ReadFile("../../docs/local-bridge.md")
	if err != nil {
		t.Fatalf("read canonical doc: %v", err)
	}
	if string(canonical) != localBridgeMD {
		t.Fatalf("internal/web/local-bridge.md has drifted from docs/local-bridge.md.\n" +
			"docs/local-bridge.md is the source; refresh the mirror with:\n" +
			"\tcp docs/local-bridge.md internal/web/local-bridge.md")
	}
}

// The page has to survive rendering, not merely compile: a markdown fault or a
// broken template would otherwise ship as a 500 on a page nobody on the team
// loads.
func TestLocalBridgeRenders(t *testing.T) {
	rec := httptest.NewRecorder()
	LocalBridge("https://tg.test", false)(rec, httptest.NewRequest(http.MethodGet, "/docs/local-bridge", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<h1", "Local Bridge",
		// A heading from the middle of the guide: proves the whole document
		// was rendered, not just its opening lines.
		"Running it unattended",
		// Rendered as markup rather than dumped as literal markdown.
		"<code>", "<table>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page is missing %q", want)
		}
	}
	if strings.Contains(body, "## Install") {
		t.Error("page contains raw markdown headings — the body was not converted")
	}
}

// goldmark is configured without WithUnsafe, so raw HTML in the source never
// reaches the page as markup. Asserting that today's document happens to
// contain no markup would prove nothing about the renderer — it has to be fed
// the markup and watched.
//
// What it actually does is drop it: both a raw HTML block and inline HTML
// inside a paragraph are replaced by "<!-- raw HTML omitted -->", not escaped
// into visible text. That is worth pinning, because a change to escaping would
// be a visible change to the page, and a change to passing it through would be
// a security one.
func TestRenderMarkdown_NeutralisesRawHTML(t *testing.T) {
	out, err := renderMarkdown([]byte(
		"Intro paragraph.\n\n<script>alert(1)</script>\n\ntrailing <img src=x onerror=alert(1)> inline\n"))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	got := string(out)
	for _, raw := range []string{"<script", "<img src=x", "onerror"} {
		if strings.Contains(got, raw) {
			t.Errorf("renderer passed through raw HTML %q:\n%s", raw, got)
		}
	}
	if strings.Count(got, "raw HTML omitted") != 2 {
		t.Errorf("expected both the block and the inline HTML dropped, got:\n%s", got)
	}
}
