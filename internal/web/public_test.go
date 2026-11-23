package web

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/productupdate"
	"github.com/mctlhq/mctl-telegram/internal/ui"
)

const publicTestBase = "https://tg.example.test"

// testProductUpdates is a rendered feed whose newest date (2026-11-03, a
// reviewed_at) differs from every created_at, so a lastmod taken from the
// wrong field, or from the first entry, is caught.
func testProductUpdates() []productupdate.ReleaseGroup {
	return []productupdate.ReleaseGroup{
		{Release: "0.139.0", Entries: []productupdate.Entry{
			{ID: "a", Kind: productupdate.KindNewTool, Title: "A", Summary: "a", CreatedAt: "2026-10-30", ReviewedAt: "2026-11-03"},
		}},
		{Release: "0.138.0", Entries: []productupdate.Entry{
			{ID: "b", Kind: productupdate.KindNewTool, Title: "B", Summary: "b", CreatedAt: "2026-11-01"},
		}},
	}
}

// newPublicMux mounts the public pages exactly as cmd/server does, through
// MountPublic, so the tests see the production route table and not a copy.
// withAssistants mounts /assistants the way main does when the agent API is
// on: the page, plus the nav flag.
func newPublicMux(t *testing.T, withAssistants bool) http.Handler {
	t.Helper()
	d := PublicDeps{
		PublicBaseURL:  publicTestBase,
		MCPPath:        "/mcp",
		AuthServer:     publicTestBase,
		ShowManage:     true,
		Platform:       testPlatformFacts(),
		ProductUpdates: testProductUpdates(),
	}
	if withAssistants {
		d.Assistants = newManageAssistantFixture(t, nil).svc
		ui.SetAssistantsMounted(true)
		t.Cleanup(func() { ui.SetAssistantsMounted(false) })
	}
	mux := chi.NewRouter()
	MountPublic(mux, d)
	return mux
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

type sitemapURL struct {
	Loc     string `xml:"loc"`
	LastMod string `xml:"lastmod"`
}

func readSitemap(t *testing.T, h http.Handler) []sitemapURL {
	t.Helper()
	rec := get(t, h, "/sitemap.xml")
	if rec.Code != http.StatusOK {
		t.Fatalf("sitemap.xml: status %d", rec.Code)
	}
	var set struct {
		URLs []sitemapURL `xml:"url"`
	}
	if err := xml.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("sitemap.xml does not parse: %v", err)
	}
	if len(set.URLs) == 0 {
		t.Fatal("sitemap.xml lists no URLs")
	}
	return set.URLs
}

func sitemapPaths(t *testing.T, urls []sitemapURL) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, u := range urls {
		p, ok := strings.CutPrefix(u.Loc, publicTestBase)
		if !ok || p == "" {
			t.Fatalf("sitemap loc %q is not on %s", u.Loc, publicTestBase)
		}
		out[p] = true
	}
	return out
}

var (
	canonicalRe = regexp.MustCompile(`<link rel="canonical" href="([^"]*)">`)
	ogURLRe     = regexp.MustCompile(`<meta property="og:url" content="([^"]*)">`)
	hrefRe      = regexp.MustCompile(`href="(/[^"]*)"`)
)

const noindexMeta = `<meta name="robots" content="noindex`

// Every sitemap URL is served, indexable and self-canonical, and its og:url
// is the same URL: the sitemap, the canonical and og:url name one page.
func TestPublicPages_SelfCanonical(t *testing.T) {
	mux := newPublicMux(t, true)
	for _, u := range readSitemap(t, mux) {
		path := strings.TrimPrefix(u.Loc, publicTestBase)
		t.Run(path, func(t *testing.T) {
			rec := get(t, mux, path)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			body := rec.Body.String()
			if strings.Contains(body, noindexMeta) {
				t.Error("sitemap URL is noindex")
			}
			can := canonicalRe.FindAllStringSubmatch(body, -1)
			if len(can) != 1 || can[0][1] != u.Loc {
				t.Errorf("canonical = %v, want exactly one equal to %s", can, u.Loc)
			}
			og := ogURLRe.FindAllStringSubmatch(body, -1)
			if len(og) != 1 || og[0][1] != u.Loc {
				t.Errorf("og:url = %v, want exactly one equal to %s", og, u.Loc)
			}
		})
	}
}

// The guide answers its trailing-slash variant too; that duplicate must
// name the slashless URL as canonical.
func TestLocalBridge_TrailingSlashCanonical(t *testing.T) {
	rec := get(t, newPublicMux(t, false), "/docs/local-bridge/quickstart/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	want := publicTestBase + "/docs/local-bridge/quickstart"
	if can := canonicalRe.FindAllStringSubmatch(rec.Body.String(), -1); len(can) != 1 || can[0][1] != want {
		t.Errorf("canonical = %v, want %s", can, want)
	}
}

// nonPagePrefixes are linked paths that are not public content pages: they
// are served by other mounts (OAuth, connect, MCP, assets), so the public
// mux answers 404 for them. Anything else that 404s here is a linked page
// the route table does not know, which is a failure, never a skip.
var nonPagePrefixes = []string{
	"/telegram/", "/oauth/", "/auth/", "/api/", "/mcp", "/.well-known/",
	"/favicon", "/apple-touch-icon.png", "/og.png", "/demo/walkthrough.mp4",
}

// Every internal page reachable by links from the sitemap pages that is
// served as indexable HTML is in the sitemap.
func TestPublicPages_LinkedIndexableInSitemap(t *testing.T) {
	mux := newPublicMux(t, true)
	inSitemap := sitemapPaths(t, readSitemap(t, mux))

	seen := map[string]bool{}
	queue := []string{}
	for p := range inSitemap {
		queue = append(queue, p)
	}
	sort.Strings(queue)
	var missing []string
	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]
		if seen[path] {
			continue
		}
		seen[path] = true
		rec := get(t, mux, path)
		if rec.Code == http.StatusNotFound {
			known := false
			for _, pre := range nonPagePrefixes {
				known = known || strings.HasPrefix(path, pre)
			}
			if !known {
				t.Errorf("%s is linked but not served by the public route table", path)
			}
			continue
		}
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			continue
		}
		body := rec.Body.String()
		if strings.Contains(body, noindexMeta) {
			continue
		}
		if !inSitemap[path] {
			missing = append(missing, path)
		}
		for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
			link := m[1]
			if strings.HasPrefix(link, "//") {
				continue
			}
			if i := strings.IndexAny(link, "?#"); i >= 0 {
				link = link[:i]
			}
			if link != "" && !seen[link] {
				queue = append(queue, link)
			}
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("linked, indexable pages missing from sitemap.xml: %v", missing)
	}
}

// /assistants is in the sitemap exactly when it is mounted.
func TestSitemap_AssistantsFollowsMount(t *testing.T) {
	want := publicTestBase + "/assistants"
	for _, mounted := range []bool{true, false} {
		mux := newPublicMux(t, mounted)
		found := false
		for _, u := range readSitemap(t, mux) {
			found = found || u.Loc == want
		}
		if found != mounted {
			t.Errorf("mounted=%v: /assistants in sitemap = %v", mounted, found)
		}
		if code := get(t, mux, "/assistants").Code; mounted != (code == http.StatusOK) {
			t.Errorf("mounted=%v: GET /assistants = %d", mounted, code)
		}
	}
}

// lastmod comes only from a date the page content carries: the newest
// created_at/reviewed_at in the rendered product-update feed. No other entry
// carries one, so a build or deploy time can never leak in.
func TestSitemap_LastmodFromFeed(t *testing.T) {
	mux := newPublicMux(t, false)
	for _, u := range readSitemap(t, mux) {
		switch u.Loc {
		case publicTestBase + "/docs/product-updates":
			if u.LastMod != "2026-11-03" {
				t.Errorf("product-updates lastmod = %q, want 2026-11-03", u.LastMod)
			}
		default:
			if u.LastMod != "" {
				t.Errorf("%s carries lastmod %q without a content date", u.Loc, u.LastMod)
			}
		}
	}

	// A feed that failed to load renders no entries: no lastmod either.
	d := PublicDeps{PublicBaseURL: publicTestBase, MCPPath: "/mcp", Platform: testPlatformFacts(),
		ProductUpdates: testProductUpdates(), ProductUpdatesErr: errFeedTest}
	failed := chi.NewRouter()
	MountPublic(failed, d)
	for _, u := range readSitemap(t, failed) {
		if u.LastMod != "" {
			t.Errorf("feed load failed, yet %s has lastmod %q", u.Loc, u.LastMod)
		}
	}
}

var errFeedTest = errors.New("read feed: failed (test)")
