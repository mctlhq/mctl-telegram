package web

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"strings"
	"sync"

	"github.com/mctlhq/mctl-telegram/internal/ui"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
)

// local-bridge.md and local-bridge/*.md are generated mirrors of
// docs/local-bridge.md and docs/local-bridge/*.md, which are the source.
// They are copied here because go:embed cannot reach outside the package
// directory, and TestLocalBridgeMarkdownMatchesDocs fails the build when
// the two trees drift.
//
// The pages render that markdown rather than restating it in hand-written
// HTML, because the hand-synchronised alternative has already failed in this
// repository: /security asserted that session_encrypted is NULL for local-mode
// accounts long after that stopped being true, which is the worst possible
// place for a stale copy. A setup guide that quietly disagrees with the
// repository is the same failure with a longer fuse.
//
//go:embed local-bridge.md
var localBridgeIndexMD string

//go:embed local-bridge/quickstart.md
var localBridgeQuickstartMD string

//go:embed local-bridge/owner.md
var localBridgeOwnerMD string

//go:embed local-bridge/how-it-works.md
var localBridgeHowItWorksMD string

//go:embed local-bridge/support.md
var localBridgeSupportMD string

//go:embed local-bridge/legacy.md
var localBridgeLegacyMD string

//go:embed local-bridge.html
var localBridgeHTML string

var localBridgeTmpl = ui.New("local-bridge", localBridgeHTML)

// localBridgeSlug is the URL suffix after /docs/local-bridge. The empty
// slug is the overview at /docs/local-bridge itself.
type localBridgeSlug string

const (
	localBridgeOverview   localBridgeSlug = ""
	localBridgeQuickstart localBridgeSlug = "quickstart"
	localBridgeOwner      localBridgeSlug = "owner"
	localBridgeHowItWorks localBridgeSlug = "how-it-works"
	localBridgeSupport    localBridgeSlug = "support"
	localBridgeLegacy     localBridgeSlug = "legacy"
)

// localBridgePage is one entry in the split guide. The HTML chrome uses
// Label/Summary/Kind for the subnav and the overview card grid; Source is
// the repository path shown in the footer.
type localBridgePage struct {
	Slug        localBridgeSlug
	Label       string
	Summary     string
	Kind        string // "primary", "owner", or "support"
	Title       string
	Description string
	Source      string
	MD          string
	Marker      string // a heading that must appear in the rendered body
}

func localBridgePages() []localBridgePage {
	return []localBridgePage{
		{
			Slug:        localBridgeOverview,
			Label:       "Overview",
			Summary:     "When to use Local Bridge, what it changes, and the rest of this guide.",
			Kind:        "primary",
			Title:       "mctl-telegram — Local Bridge",
			Description: "Keep your Telegram session on your own machine. Local Bridge is self-service: init, login, activate, daemon. No operator step.",
			Source:      "docs/local-bridge.md",
			MD:          localBridgeIndexMD,
			Marker:      "When to use it",
		},
		{
			Slug:        localBridgeQuickstart,
			Label:       "Quick start",
			Summary:     "Install, init, login, activate, daemon. The zero-admin path.",
			Kind:        "primary",
			Title:       "mctl-telegram — Local Bridge quick start",
			Description: "Zero-admin Local Bridge setup: install the CLI, init, login, activate, and run the daemon.",
			Source:      "docs/local-bridge/quickstart.md",
			MD:          localBridgeQuickstartMD,
			Marker:      "Running it unattended",
		},
		{
			Slug:        localBridgeOwner,
			Label:       "Owner",
			Summary:     "Turn sending on, revoke a device, confirm the call path.",
			Kind:        "owner",
			Title:       "mctl-telegram — Local Bridge owner controls",
			Description: "Grant send consent with set_send_consent or the manage page, and revoke a Local Bridge device yourself.",
			Source:      "docs/local-bridge/owner.md",
			MD:          localBridgeOwnerMD,
			Marker:      "Turn sending on",
		},
		{
			Slug:        localBridgeHowItWorks,
			Label:       "How it works",
			Summary:     "Activation, proof of possession, read-only first token.",
			Kind:        "primary",
			Title:       "mctl-telegram — How Local Bridge works",
			Description: "How Local Bridge activation, device-signed credentials, and the read-only first token work.",
			Source:      "docs/local-bridge/how-it-works.md",
			MD:          localBridgeHowItWorksMD,
			Marker:      "Proof of possession",
		},
		{
			Slug:        localBridgeSupport,
			Label:       "Support",
			Summary:     "Migration, troubleshooting, emergency. Not onboarding.",
			Kind:        "support",
			Title:       "mctl-telegram — Local Bridge support and recovery",
			Description: "Operator migration, troubleshooting, and emergency steps for Local Bridge. Not part of normal onboarding.",
			Source:      "docs/local-bridge/support.md",
			MD:          localBridgeSupportMD,
			Marker:      "Operator: migrate a hosted account",
		},
		{
			Slug:        localBridgeLegacy,
			Label:       "Legacy",
			Summary:     "connect --token and operator-minted worker tokens.",
			Kind:        "support",
			Title:       "mctl-telegram — Local Bridge legacy connect",
			Description: "The pre-activate connect --token path, kept for compatibility and recovery.",
			Source:      "docs/local-bridge/legacy.md",
			MD:          localBridgeLegacyMD,
			Marker:      "connect --token",
		},
	}
}

func lookupLocalBridgePage(slug localBridgeSlug) (localBridgePage, bool) {
	for _, p := range localBridgePages() {
		if p.Slug == slug {
			return p, true
		}
	}
	return localBridgePage{}, false
}

func parseLocalBridgeSlug(path string) (localBridgeSlug, bool) {
	path = strings.TrimSuffix(path, "/")
	const prefix = "/docs/local-bridge"
	if path == prefix {
		return localBridgeOverview, true
	}
	if !strings.HasPrefix(path, prefix+"/") {
		return "", false
	}
	slug := localBridgeSlug(strings.TrimPrefix(path, prefix+"/"))
	if slug == "" || strings.Contains(string(slug), "/") {
		return "", false
	}
	_, ok := lookupLocalBridgePage(slug)
	return slug, ok
}

// localBridgeBodies renders each page once, on first request rather than in
// an init, so a rendering fault surfaces as a 500 on one page instead of
// taking the whole server down at boot over a documentation page.
var localBridgeBodies sync.Map // localBridgeSlug -> template.HTML

func localBridgeBody(page localBridgePage) (template.HTML, error) {
	if v, ok := localBridgeBodies.Load(page.Slug); ok {
		return v.(template.HTML), nil
	}
	body, err := renderMarkdown([]byte(page.MD))
	if err != nil {
		return "", err
	}
	actual, _ := localBridgeBodies.LoadOrStore(page.Slug, body)
	return actual.(template.HTML), nil
}

// renderMarkdown is the single markdown configuration this package uses, split
// out so a test can exercise the real renderer on its own input instead of
// asserting something about the document that happens to be embedded today.
//
// No WithHardWraps: the source is hard-wrapped at ~78 columns for reading in a
// repository, and honouring those newlines turns every paragraph into a ragged
// column in the browser.
//
// No WithUnsafe either, so raw HTML in the source is dropped rather than passed
// through — goldmark replaces it with an HTML comment. The guide is edited like
// any other file in the repository; a page that executes whatever markup lands
// in a doc is a wider surface than a setup guide needs.
//
// WithAutoHeadingID turns remaining H2/H3s into in-page anchors so a split
// page can still be linked to a section.
func renderMarkdown(src []byte) (template.HTML, error) {
	md := goldmark.New(
		goldmark.WithExtensions(extension.GFM),
		goldmark.WithParserOptions(parser.WithAutoHeadingID()),
	)
	var buf bytes.Buffer
	if err := md.Convert(src, &buf); err != nil {
		return "", err
	}
	return template.HTML(buf.String()), nil //nolint:gosec // renderer drops raw HTML; see above
}

type localBridgeNav struct {
	Href    string
	Label   string
	Summary string
	Kind    string
	Active  bool
}

type localBridgeData struct {
	ui.Data
	Body    template.HTML
	Pages   []localBridgeNav
	Source  string
	ShowTOC bool
}

func localBridgeHref(slug localBridgeSlug) string {
	if slug == localBridgeOverview {
		return "/docs/local-bridge"
	}
	return "/docs/local-bridge/" + string(slug)
}

func localBridgeNavItems(active localBridgeSlug) []localBridgeNav {
	pages := localBridgePages()
	out := make([]localBridgeNav, 0, len(pages))
	for _, p := range pages {
		out = append(out, localBridgeNav{
			Href:    localBridgeHref(p.Slug),
			Label:   p.Label,
			Summary: p.Summary,
			Kind:    p.Kind,
			Active:  p.Slug == active,
		})
	}
	return out
}

// LocalBridge serves the Local Bridge guide at /docs/local-bridge and the
// split pages under /docs/local-bridge/{quickstart,owner,how-it-works,support,legacy}.
// Anonymous-accessible: these are the pages a prospective user reads before
// deciding whether the mode is worth the machine it needs.
func LocalBridge(publicBaseURL string, showManage bool) http.HandlerFunc {
	base := strings.TrimRight(publicBaseURL, "/")
	return func(w http.ResponseWriter, r *http.Request) {
		slug, ok := parseLocalBridgeSlug(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		page, ok := lookupLocalBridgePage(slug)
		if !ok {
			http.NotFound(w, r)
			return
		}
		body, err := localBridgeBody(page)
		if err != nil {
			http.Error(w, "render markdown: "+err.Error(), http.StatusInternalServerError)
			return
		}
		data := localBridgeData{
			Data: ui.Data{
				Title:         page.Title,
				Description:   page.Description,
				NavActive:     "docs",
				PublicBaseURL: base,
				ShowManage:    showManage,
			},
			Body:    body,
			Pages:   localBridgeNavItems(slug),
			Source:  page.Source,
			ShowTOC: slug == localBridgeOverview,
		}
		chromePage(localBridgeTmpl, "local-bridge", data)(w, r)
	}
}
