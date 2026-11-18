package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/mctlhq/mctl-telegram/internal/ui"
)

// chromeCSP has no 'unsafe-inline' on script-src, so any executable inline
// <script>, on* handler or javascript: URL on a chrome page is dead code that
// the browser blocks (and, before the policy tightened, a hole). These tests
// parse every rendered chrome page and fail on all three, and check that the
// external scripts the pages do reference are actually served.

// inertScriptTypes are the data-block types that are never executed. Anything
// else on an inline <script> (empty, module, any JavaScript MIME type, and any
// type we cannot classify) counts as executable: an unknown type is not safe.
var inertScriptTypes = map[string]bool{
	"application/ld+json": true,
	"application/json":    true,
}

type scriptFinding struct{ kind, detail string }

// scanScripts parses body and returns every executable inline script, inline
// event handler and javascript: URL, plus the src of each external script.
func scanScripts(t *testing.T, body string) (bad []scriptFinding, srcs []*html.Node) {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			attr := map[string]string{}
			for _, a := range n.Attr {
				k := strings.ToLower(a.Key)
				attr[k] = a.Val
				if strings.HasPrefix(k, "on") {
					bad = append(bad, scriptFinding{"inline handler", n.Data + " " + k})
				}
				if (k == "href" || k == "src" || k == "action" || k == "formaction") &&
					strings.HasPrefix(strings.ToLower(strings.TrimSpace(a.Val)), "javascript:") {
					bad = append(bad, scriptFinding{"javascript: URL", n.Data + " " + k})
				}
			}
			if n.Data == "script" {
				if _, ok := attr["src"]; ok {
					srcs = append(srcs, n)
				} else {
					typ := strings.ToLower(strings.TrimSpace(attr["type"]))
					if !inertScriptTypes[typ] {
						body := ""
						if n.FirstChild != nil {
							body = n.FirstChild.Data
						}
						if len(body) > 60 {
							body = body[:60]
						}
						bad = append(bad, scriptFinding{"inline <script>", "type=" + typ + " " + strings.TrimSpace(body)})
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return bad, srcs
}

func attrOf(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return a.Val, true
		}
	}
	return "", false
}

// chromePageBodies renders every page that is served under chromeCSP.
func chromePageBodies(t *testing.T) map[string]string {
	t.Helper()
	const base = "https://tg.mctl.ai"
	f := newManageAssistantFixture(t, nil)
	f.installDirect()
	hs := map[string]http.HandlerFunc{
		"/":                     Landing(base, "/mcp", base, true),
		"/docs":                 Docs(base, "/mcp", base, true, false),
		"/demo":                 Demo(base, "", true),
		"/demo (youtube)":       Demo(base, "https://www.youtube.com/watch?v=dQw4w9WgXcQ", true),
		"/security":             Security(base, true),
		"/privacy":              Privacy(base, true),
		"/terms":                Terms(base, true),
		"/platforms":            Platforms(base, "/mcp", base, true, testPlatformFacts()),
		"/docs/local-bridge":    LocalBridge(base, true),
		"/docs/product-updates": ProductUpdates(nil, nil, base, true),
		"/examples":             Examples(base, true),
		"/assistants":           Assistants(f.svc, base, true),
	}
	out := map[string]string{}
	for path, h := range hs {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(http.MethodGet, strings.Fields(path)[0], nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if got := rec.Header().Get("Content-Security-Policy"); got != chromeCSP {
			t.Fatalf("%s: not served under chromeCSP: %q", path, got)
		}
		out[path] = rec.Body.String()
	}
	return out
}

func TestChromeCSP_ScriptSrcHasNoUnsafeInline(t *testing.T) {
	for _, d := range strings.Split(chromeCSP, ";") {
		d = strings.TrimSpace(d)
		if strings.HasPrefix(d, "script-src ") {
			if strings.Contains(d, "'unsafe-inline'") || strings.Contains(d, "'unsafe-eval'") {
				t.Fatalf("script-src is not strict: %q", d)
			}
			return
		}
	}
	t.Fatal("chromeCSP has no script-src; default-src 'none' would block every script")
}

func TestChromePages_NoExecutableInlineScript(t *testing.T) {
	for path, body := range chromePageBodies(t) {
		t.Run(path, func(t *testing.T) {
			bad, _ := scanScripts(t, body)
			for _, b := range bad {
				t.Errorf("%s under script-src without 'unsafe-inline': %s: %s", path, b.kind, b.detail)
			}
		})
	}
}

// The scanner itself must see what it claims to: every flavour of inline
// script, handler and javascript: URL fails, data blocks and src scripts pass.
func TestScanScripts_Classification(t *testing.T) {
	for name, in := range map[string]string{
		"classic":    `<script>var a=1</script>`,
		"js mime":    `<script type="text/javascript">var a=1</script>`,
		"module":     `<script type="module">import "x"</script>`,
		"importmap":  `<script type="importmap">{}</script>`,
		"unknown":    `<script type="text/x-whatever">x</script>`,
		"upper":      `<SCRIPT TYPE=" Text/JavaScript ">x</SCRIPT>`,
		"handler":    `<button onclick="go()">x</button>`,
		"js url":     `<a href=" JavaScript:go()">x</a>`,
		"empty body": `<script></script>`,
	} {
		if bad, _ := scanScripts(t, `<!doctype html><html><head></head><body>`+in+`</body></html>`); len(bad) != 1 {
			t.Errorf("%s: want exactly 1 finding, got %v", name, bad)
		}
	}
	ok := `<!doctype html><html><head><script type="application/ld+json">{}</script>` +
		`<script src="/assets/a.js" defer></script></head><body></body></html>`
	bad, srcs := scanScripts(t, ok)
	if len(bad) != 0 || len(srcs) != 1 {
		t.Errorf("data block + src script: bad=%v srcs=%d", bad, len(srcs))
	}
}

// Every external script on a chrome page is either the pinned analytics tag or
// a same-origin /assets/ file the server really serves with the right headers.
// prepaint.js must stay synchronous in <head>: deferring it would paint the
// default theme before the stored choice is applied (a flash).
func TestChromePages_ExternalScriptsAreServed(t *testing.T) {
	asset := ui.AssetHandler()
	for path, body := range chromePageBodies(t) {
		t.Run(path, func(t *testing.T) {
			_, srcs := scanScripts(t, body)
			sawPrepaint, sawToggle := false, false
			for _, n := range srcs {
				src, _ := attrOf(n, "src")
				if src == "https://stats.mctl.ai/insights.js" {
					continue
				}
				if !strings.HasPrefix(src, ui.AssetPrefix) {
					t.Errorf("%s: script src %q is neither /assets/ nor the analytics tag", path, src)
					continue
				}
				rec := httptest.NewRecorder()
				asset.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, src, nil))
				if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
					t.Errorf("%s: GET %s = %d (%d bytes)", path, src, rec.Code, rec.Body.Len())
				}
				if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
					t.Errorf("%s: %s Cache-Control = %q, want immutable", path, src, cc)
				}
				_, deferred := attrOf(n, "defer")
				_, async := attrOf(n, "async")
				inHead := false
				for p := n.Parent; p != nil; p = p.Parent {
					if p.Type == html.ElementNode && p.Data == "head" {
						inHead = true
					}
				}
				switch {
				case strings.HasPrefix(src, "/assets/prepaint."):
					sawPrepaint = true
					if deferred || async || !inHead {
						t.Errorf("%s: prepaint must be a synchronous <head> script (defer=%v async=%v head=%v)", path, deferred, async, inHead)
					}
				case strings.HasPrefix(src, "/assets/toggle."):
					sawToggle = true
					fallthrough
				default:
					if !deferred {
						t.Errorf("%s: %s should be defer", path, src)
					}
				}
			}
			if !sawPrepaint || !sawToggle {
				t.Errorf("%s: missing prepaint (%v) or toggle (%v) script", path, sawPrepaint, sawToggle)
			}
		})
	}
}

// The landing and examples pages each load their own page script.
func TestChromePages_PageScriptsReferenced(t *testing.T) {
	bodies := chromePageBodies(t)
	for path, want := range map[string]string{"/": "/assets/landing.", "/examples": "/assets/examples."} {
		if !strings.Contains(bodies[path], `src="`+want) {
			t.Errorf("%s does not load %s*.js", path, want)
		}
	}
}
