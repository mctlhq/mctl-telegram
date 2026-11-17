package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/productupdate"
)

// Paths of the public content pages. Each page's handler uses its constant
// as its canonical path, and publicPages lists the same constants, so the
// mounted route, the sitemap <loc>, <link rel="canonical"> and og:url all
// name one URL.
const (
	PathLanding        = "/"
	PathDocs           = "/docs"
	PathPlatforms      = "/platforms"
	PathAssistants     = "/assistants"
	PathExamples       = "/examples"
	PathDemo           = "/demo"
	PathSecurity       = "/security"
	PathPrivacy        = "/privacy"
	PathTerms          = "/terms"
	PathLocalBridge    = "/docs/local-bridge"
	PathProductUpdates = "/docs/product-updates"
)

// PublicDeps is what the public content pages render from.
type PublicDeps struct {
	PublicBaseURL string
	MCPPath       string
	AuthServer    string
	ShowManage    bool
	Platform      PlatformFacts
	DemoVideoURL  string
	DocsBotAccess bool

	// ProductUpdates is the rendered feed and ProductUpdatesErr its load
	// error; a failed load renders no entries and gives no lastmod.
	ProductUpdates    []productupdate.ReleaseGroup
	ProductUpdatesErr error

	// Assistants mounts /assistants, and lists it in the sitemap, only when
	// non-nil.
	Assistants *assistantinstall.Service

	LandingOptions []LandingOption
	// Root wraps the landing page for "/" (cmd/server serves MCP there
	// too). Nil serves the landing page as is.
	Root func(landing http.Handler) http.Handler
}

// publicPage is one row of the public route table.
type publicPage struct {
	Path    string
	Handler http.Handler
	// Index lists the page in sitemap.xml. A noindex page (privacy, terms)
	// is mounted but never listed.
	Index      bool
	ChangeFreq string
	Priority   float32
	// LastMod is a date the page content itself carries; zero means none.
	// Never a build or deploy time: a lastmod that is not accurate is
	// ignored by search engines and teaches them to ignore the rest.
	LastMod time.Time
}

// publicPages is the single route table for the public content pages: what
// MountPublic mounts and what sitemap.xml lists come from this one list.
func publicPages(d PublicDeps) []publicPage {
	base, show := d.PublicBaseURL, d.ShowManage
	landing := http.Handler(Landing(base, d.MCPPath, d.AuthServer, show, d.LandingOptions...))
	if d.Root != nil {
		landing = d.Root(landing)
	}
	pages := []publicPage{
		{Path: PathLanding, Handler: landing, Index: true, ChangeFreq: "weekly", Priority: 1.0},
		{Path: PathDocs, Handler: Docs(base, d.MCPPath, d.AuthServer, show, d.DocsBotAccess), Index: true, ChangeFreq: "weekly", Priority: 0.8},
		{Path: PathPlatforms, Handler: Platforms(base, d.MCPPath, d.AuthServer, show, d.Platform), Index: true, ChangeFreq: "weekly", Priority: 0.8},
	}
	if d.Assistants != nil {
		pages = append(pages, publicPage{Path: PathAssistants, Handler: Assistants(d.Assistants, base, show), Index: true, ChangeFreq: "weekly", Priority: 0.7})
	}
	pages = append(pages,
		publicPage{Path: PathDemo, Handler: Demo(base, d.DemoVideoURL, show), Index: true, ChangeFreq: "monthly", Priority: 0.7},
		publicPage{Path: PathExamples, Handler: Examples(base, show), Index: true, ChangeFreq: "monthly", Priority: 0.7},
		publicPage{Path: PathSecurity, Handler: Security(base, show), Index: true, ChangeFreq: "monthly", Priority: 0.5},
		publicPage{Path: PathPrivacy, Handler: Privacy(base, show)},
		publicPage{Path: PathTerms, Handler: Terms(base, show)},
	)
	localBridge := LocalBridge(base, show)
	for _, p := range localBridgePages() {
		prio := float32(0.5)
		if p.Slug == localBridgeOverview {
			prio = 0.6
		}
		pages = append(pages, publicPage{Path: localBridgeHref(p.Slug), Handler: localBridge, Index: true, ChangeFreq: "monthly", Priority: prio})
	}
	pages = append(pages, publicPage{
		Path:       PathProductUpdates,
		Handler:    ProductUpdates(d.ProductUpdates, d.ProductUpdatesErr, base, show),
		Index:      true,
		ChangeFreq: "weekly",
		Priority:   0.7,
		LastMod:    productUpdatesLastMod(d.ProductUpdates, d.ProductUpdatesErr),
	})
	return pages
}

// MountPublic mounts every public content page and the sitemap built from
// the same table. It returns the handler mounted at GET "/", so the caller
// can serve the other methods there with the same handler.
func MountPublic(r chi.Router, d PublicDeps) http.Handler {
	pages := publicPages(d)
	var root http.Handler
	for _, p := range pages {
		r.Method(http.MethodGet, p.Path, p.Handler)
		if p.Path == PathLanding {
			root = p.Handler
		}
	}
	// Unknown slugs and trailing-slash variants of the guide pages; the
	// handler 404s the former and canonicalizes the latter.
	r.Method(http.MethodGet, PathLocalBridge+"/*", LocalBridge(d.PublicBaseURL, d.ShowManage))
	r.Method(http.MethodGet, "/sitemap.xml", sitemapHandler(d.PublicBaseURL, pages))
	return root
}

// productUpdatesLastMod is the newest created_at or reviewed_at among the
// rendered entries: the newest date the page shows. A failed load renders
// no entries, so it has none.
func productUpdatesLastMod(groups []productupdate.ReleaseGroup, loadErr error) time.Time {
	var newest time.Time
	if loadErr != nil {
		return newest
	}
	for _, g := range groups {
		for _, e := range g.Entries {
			for _, s := range []string{e.CreatedAt, e.ReviewedAt} {
				if t, err := time.Parse(time.DateOnly, strings.TrimSpace(s)); err == nil && t.After(newest) {
					newest = t
				}
			}
		}
	}
	return newest
}
