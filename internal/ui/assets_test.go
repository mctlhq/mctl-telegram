package ui

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func get(t *testing.T, method, url string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	AssetHandler().ServeHTTP(rec, httptest.NewRequest(method, url, nil))
	return rec
}

var assetURLRe = regexp.MustCompile(`^/assets/[a-z]+\.[0-9a-f]{12}\.js$`)

func TestAssetURL_IsContentHashed(t *testing.T) {
	for name, a := range scripts {
		u := AssetURL(name)
		if !assetURLRe.MatchString(u) {
			t.Errorf("%s: URL %q is not /assets/<name>.<12 hex>.js", name, u)
		}
		if a.body == "" {
			t.Errorf("%s: embedded script is empty", name)
		}
	}
	// The hash must follow the content, or a changed script keeps its cached URL.
	a := scripts["toggle.js"]
	before := AssetURL("toggle.js")
	scripts["toggle.js"] = jsAsset{body: a.body + "\n//x", hash: hashOf(a.body + "\n//x")}
	after := AssetURL("toggle.js")
	scripts["toggle.js"] = a
	if before == after {
		t.Error("changing the script body did not change its URL")
	}
}

func TestAssetHandler_CurrentHashIsImmutable(t *testing.T) {
	for name, a := range scripts {
		rec := get(t, http.MethodGet, AssetURL(name))
		if rec.Code != http.StatusOK || rec.Body.String() != a.body {
			t.Fatalf("%s: code %d, body match %v", name, rec.Code, rec.Body.String() == a.body)
		}
		if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
			t.Errorf("%s: Cache-Control = %q", name, got)
		}
		if got := rec.Header().Get("Content-Type"); got != "text/javascript; charset=utf-8" {
			t.Errorf("%s: Content-Type = %q", name, got)
		}
	}
}

// A page rendered by the previous pod during a rolling deploy references the
// old hash: it still gets working code, but must not be cached under that URL.
func TestAssetHandler_StaleHashServedNoStore(t *testing.T) {
	rec := get(t, http.MethodGet, "/assets/prepaint.000000000000.js")
	if rec.Code != http.StatusOK || rec.Body.String() != scripts["prepaint.js"].body {
		t.Fatalf("stale hash: code %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("stale hash Cache-Control = %q, want no-store", got)
	}
}

func TestAssetHandler_RejectsEverythingElse(t *testing.T) {
	for _, u := range []string{
		"/assets/", "/assets/nope.0123456789ab.js", "/assets/prepaint.js", "/assets/prepaint.0123456789ab.css",
		"/assets/prepaint.0123456789ab.js.map", "/assets/../chrome.go", "/assets/a.b.c.js", "/assets/prepaint..js",
	} {
		if rec := get(t, http.MethodGet, u); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", u, rec.Code)
		}
	}
	if rec := get(t, http.MethodPost, AssetURL("toggle.js")); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", rec.Code)
	}
	if rec := get(t, http.MethodHead, AssetURL("toggle.js")); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD = %d with %d body bytes", rec.Code, rec.Body.Len())
	}
}

// The full chrome emits no inline executable script; the head loads prepaint
// synchronously and the toggle with defer.
func TestFullChrome_ScriptsAreExternal(t *testing.T) {
	page := `<!doctype html><html lang="en"><head>{{template "ui_head" .}}</head>` +
		`<body>{{template "ui_topbar" .}}{{template "ui_footer" .}}{{template "ui_script" .}}</body></html>`
	out := render(t, "full", page, Data{Title: "T", CanonicalPath: "/x", PublicBaseURL: "https://tg.test"})
	if strings.Contains(out, "<script>") {
		t.Error("full chrome still emits a bare inline <script>")
	}
	if !strings.Contains(out, `<script src="`+AssetURL("prepaint.js")+`"></script>`) {
		t.Error("head must load prepaint.js synchronously (no defer/async)")
	}
	if !strings.Contains(out, `<script defer src="`+AssetURL("toggle.js")+`"></script>`) {
		t.Error("toggle.js must be deferred")
	}
}
