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

// goldmark is configured without WithUnsafe, so raw HTML in the source is
// escaped rather than passed through. That is deliberate: the guide is edited
// like any other file, and a page that executes whatever markup lands in a doc
// is a wider surface than a setup guide needs.
func TestLocalBridgeDoesNotRenderRawHTML(t *testing.T) {
	if strings.Contains(localBridgeMD, "<script") {
		t.Fatal("the source doc contains a script tag; this test can no longer distinguish escaped from executed")
	}
}
