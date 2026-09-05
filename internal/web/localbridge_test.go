package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The embedded copies exist only because go:embed cannot reach ../../docs.
// Nothing stops the two trees from drifting except this test, and a setup
// guide that disagrees with the repository is worse than no page at all —
// the reader has no way to tell which half is stale.
func TestLocalBridgeMarkdownMatchesDocs(t *testing.T) {
	pairs := []struct {
		canonical string
		embedded  string
	}{
		{"../../docs/local-bridge.md", localBridgeIndexMD},
		{"../../docs/local-bridge/quickstart.md", localBridgeQuickstartMD},
		{"../../docs/local-bridge/owner.md", localBridgeOwnerMD},
		{"../../docs/local-bridge/how-it-works.md", localBridgeHowItWorksMD},
		{"../../docs/local-bridge/support.md", localBridgeSupportMD},
		{"../../docs/local-bridge/legacy.md", localBridgeLegacyMD},
	}
	for _, p := range pairs {
		canonical, err := os.ReadFile(p.canonical)
		if err != nil {
			t.Fatalf("read %s: %v", p.canonical, err)
		}
		if string(canonical) != p.embedded {
			t.Errorf("%s has drifted from %s.\n"+
				"docs/local-bridge.md and docs/local-bridge/*.md are the source; refresh the mirrors with:\n"+
				"\tcp docs/local-bridge.md internal/web/local-bridge.md\n"+
				"\tcp docs/local-bridge/*.md internal/web/local-bridge/", p.canonical, filepath.Base(p.canonical))
		}
	}

	// Refuse a new docs/local-bridge/*.md that was never mirrored: the
	// explicit list above cannot see a file nobody added to the embed.
	err := filepath.WalkDir("../../docs/local-bridge", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		rel, _ := filepath.Rel("../../docs/local-bridge", path)
		mirror := filepath.Join("local-bridge", rel)
		data, rerr := os.ReadFile(mirror)
		if rerr != nil {
			t.Errorf("docs/local-bridge/%s has no internal/web/%s mirror", rel, mirror)
			return nil
		}
		canonical, _ := os.ReadFile(path)
		if string(canonical) != string(data) {
			t.Errorf("internal/web/%s drifted from docs/local-bridge/%s", mirror, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLocalBridgeRenders(t *testing.T) {
	for _, page := range localBridgePages() {
		path := localBridgeHref(page.Slug)
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			LocalBridge("https://tg.test", false)(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body: %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, want := range []string{
				"<h1", page.Marker, "<code>",
				`class="doc-nav"`, `href="/docs/local-bridge/quickstart"`,
				page.Source,
			} {
				if !strings.Contains(body, want) {
					t.Errorf("rendered page is missing %q", want)
				}
			}
			if strings.Contains(body, "## ") {
				t.Error("page contains raw markdown headings — the body was not converted")
			}
		})
	}
}

func TestLocalBridgeUnknownPageIs404(t *testing.T) {
	rec := httptest.NewRecorder()
	LocalBridge("https://tg.test", false)(rec, httptest.NewRequest(http.MethodGet, "/docs/local-bridge/not-a-page", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestLocalBridgeOverviewHasTOCNotOperatorWall(t *testing.T) {
	rec := httptest.NewRecorder()
	LocalBridge("https://tg.test", false)(rec, httptest.NewRequest(http.MethodGet, "/docs/local-bridge", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `class="doc-toc"`) {
		t.Error("overview is missing the page cards")
	}
	for _, buried := range []string{
		"Running it unattended",
		"launchd (macOS)",
		"mint_worker_token",
	} {
		if strings.Contains(body, buried) {
			t.Errorf("overview still contains %q — that belongs on a subpage, not the landing", buried)
		}
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

func TestRenderMarkdown_HeadingIDs(t *testing.T) {
	out, err := renderMarkdown([]byte("# Hello World\n"))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(string(out), `id="hello-world"`) {
		t.Errorf("expected auto heading id, got:\n%s", out)
	}
}

// TestPublicPages_NoStaleOperatorGateClaim is T14: with #484 shipped, no
// public page may still claim Local Bridge requires an operator to enable it
// per account, or that it is not self-serve -- those claims became false the
// moment `activate` started bootstrapping its own device credential with zero
// operator calls. This is a content assertion on purpose, the same class of
// staleness internal/web/localbridge.go's own comment records for /security's
// past false claim about session_encrypted. Validate by mutation: restoring
// either sentence on / or /docs fails this test.
func TestPublicPages_NoStaleOperatorGateClaim(t *testing.T) {
	forbidden := []string{
		"not self-serve",
		"operator enables it per account",
		"operator has to enable",
		"enabled per account on request",
		"contact the operator to enable real sends",
	}

	landingRec := httptest.NewRecorder()
	Landing("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true).
		ServeHTTP(landingRec, httptest.NewRequest(http.MethodGet, "/", nil))
	if landingRec.Code != http.StatusOK {
		t.Fatalf("GET /: status %d, body: %s", landingRec.Code, landingRec.Body.String())
	}

	docsRec := httptest.NewRecorder()
	Docs("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true).
		ServeHTTP(docsRec, httptest.NewRequest(http.MethodGet, "/docs", nil))
	if docsRec.Code != http.StatusOK {
		t.Fatalf("GET /docs: status %d, body: %s", docsRec.Code, docsRec.Body.String())
	}

	pages := map[string]string{
		"/":     landingRec.Body.String(),
		"/docs": docsRec.Body.String(),
	}
	for _, page := range localBridgePages() {
		path := localBridgeHref(page.Slug)
		rec := httptest.NewRecorder()
		LocalBridge("https://tg.mctl.ai", true)(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, rec.Code)
		}
		pages[path] = rec.Body.String()
	}
	for path, body := range pages {
		for _, bad := range forbidden {
			if strings.Contains(body, bad) {
				t.Errorf("%s still contains the stale claim %q -- Local Bridge is self-service since #484", path, bad)
			}
		}
	}
	if !strings.Contains(pages["/"], `href="/docs/local-bridge"`) {
		t.Error("landing no longer links to /docs/local-bridge")
	}
	if !strings.Contains(pages["/"], `id="local-bridge"`) {
		t.Error("landing is missing a dedicated Local Bridge section")
	}
}
