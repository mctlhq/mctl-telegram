package ui

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

func render(t *testing.T, name, page string, data Data) string {
	t.Helper()
	var b bytes.Buffer
	if err := New(name, page).ExecuteTemplate(&b, name, data); err != nil {
		t.Fatalf("render %s: %v", name, err)
	}
	return b.String()
}

func TestFullChrome(t *testing.T) {
	page := `<!doctype html><html lang="en"><head>{{template "ui_head" .}}</head>` +
		`<body>{{template "ui_topbar" .}}<main class="mctl-site-container"></main>{{template "ui_footer" .}}{{template "ui_script" .}}</body></html>`
	out := render(t, "full", page, Data{Title: "T", NavActive: "docs", PublicBaseURL: "https://tg.mctl.ai"})

	for _, s := range []string{
		// Shared public-site shell (site.css): full-bleed header and footer,
		// their content in the one container the page content uses.
		`<header class="mctl-site-header">`,
		`<div class="mctl-site-container mctl-site-header__inner">`,
		`<a class="mctl-site-brand" href="/"`,
		`<footer class="mctl-site-footer">`,
		`<div class="mctl-site-container mctl-site-footer__inner">`,
		`<nav class="mctl-site-footer__links"`,
		"ui.mctl.ai/0.18.0/mctl.css",
		// global.css and site.css are pinned as a set with mctl.css.
		"ui.mctl.ai/0.18.0/global.css",
		"ui.mctl.ai/0.18.0/site.css",
		"family=Onest:wght@300;400;500;600;700;800",
		"Instrument+Serif",
		"JetBrains+Mono",
		"ui.mctl.ai/brand/favicon-telegram.svg",
		"https://tg.mctl.ai",
		`<a href="/docs" class="active">Docs</a>`,
		// CSS-only mobile menu: works without JS.
		`<input type="checkbox" id="site-nav-toggle" class="nav-toggle"`,
		`<label for="site-nav-toggle" class="nav-burger"`,
		"support@mctl.ai",
		// GitHub icon link — inline SVG with accessible label.
		`aria-label="GitHub"`,
		// Light/dark toggle — content pages can flip the theme.
		`class="theme-toggle"`,
		`aria-label="Toggle theme"`,
		"#e25a3c",
		// Self-hosted Umami page-view counter on public content pages.
		AnalyticsScript,
	} {
		if !strings.Contains(out, s) {
			t.Errorf("full page missing %q", s)
		}
	}
	for _, bad := range []string{
		"family=Geist", "'Geist'", "#00e5ff",
		"accent-swatch", "accent-picker", "data-pick",
	} {
		if strings.Contains(out, bad) {
			t.Errorf("full page still has stale chrome %q", bad)
		}
	}
}

func TestStylesheetIsVersionPinned(t *testing.T) {
	// The floating https://ui.mctl.ai/mctl.css has no version in it and a four
	// hour cache, so a token change upstream restyles this page with no commit
	// here and nothing to roll back to. The pinned path is served immutable and
	// mctl-design's CI refuses to edit a published version directory, so an
	// upgrade becomes an edit made here on purpose (mctl-design#78).
	//
	// Asserting the shape, not the exact version: a bump stays a one-line
	// change, while a revert to the floating URL fails here.
	page := `<!doctype html><html lang="en"><head>{{template "ui_head" .}}</head><body></body></html>`
	out := render(t, "pin", page, Data{Title: "T", PublicBaseURL: "https://tg.mctl.ai"})

	pinned := regexp.MustCompile(`https://ui\.mctl\.ai/\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?/mctl\.css`)
	if !pinned.MatchString(out) {
		t.Error("the design-system stylesheet must be version-pinned")
	}
	if strings.Contains(out, `"https://ui.mctl.ai/mctl.css"`) {
		t.Error("the floating (unversioned) stylesheet URL is back")
	}
}

func TestLiteChromeHasNoExternalDeps(t *testing.T) {
	page := `<!doctype html><html lang="en"><head>{{template "ui_head_lite" .}}</head>` +
		`<body>{{template "ui_topbar_lite" .}}<div class="mctl-site-container"></div>{{template "ui_footer_lite" .}}</body></html>`
	out := render(t, "lite", page, Data{Title: "L"})

	for _, bad := range []string{"mctl.css", "fonts.googleapis.com", "<script", "stats.mctl.ai", `href="/favicon.svg"`, "accent-swatch", "accent-picker"} {
		if strings.Contains(out, bad) {
			t.Errorf("lite (strict-CSP) page must not contain %q", bad)
		}
	}
	if !strings.Contains(out, "ui.mctl.ai/brand/favicon-telegram.svg") {
		t.Error("lite page missing CDN favicon")
	}
	for _, s := range []string{`<header class="mctl-site-header">`, `<footer class="mctl-site-footer">`} {
		if !strings.Contains(out, s) {
			t.Errorf("lite page missing %q", s)
		}
	}
	// No external CSS here, so the site.css layout classes must be inlined.
	for _, s := range []string{".mctl-site-container {", ".mctl-site-header {", ".mctl-site-footer {"} {
		if !strings.Contains(out, s) {
			t.Errorf("lite page must inline the site.css mirror; missing %q", s)
		}
	}
	if !strings.Contains(out, "'Onest'") {
		t.Error("lite fallback tokens must use Onest")
	}
	if !strings.Contains(out, "#e25a3c") {
		t.Error("lite fallback tokens must default to terracotta")
	}
	for _, bad := range []string{"'Geist'", "#00e5ff"} {
		if strings.Contains(out, bad) {
			t.Errorf("lite fallback still has stale design token %q", bad)
		}
	}
	// The lite pages have no external CSS, so the inlined tokens must carry the
	// 0.14 site-shell roles and the AA palette the shared components read.
	for _, s := range []string{
		"--surface-fg-subtle: #7d828b", "--surface-fg-subtle: #656a73",
		"--accent-fg:", "--accent-text:", "--status-bad-text:", "--status-warn-soft:",
		"--site-header-height:", "--site-wordmark-size:", "--site-grid-line:",
		"--text-hero-size:", "--text-section-size:",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("lite fallback tokens missing %q", s)
		}
	}
}

// Dark is the default on every tier, matching mctl.ai and docs.mctl.ai: the
// pre-paint script falls back to dark (not the OS preference) when nothing is
// stored, and the inline tokens no longer switch to light on their own.
func TestThemeDefaultsToDark(t *testing.T) {
	if strings.Contains(prepaintJS, "matchMedia") {
		t.Error("pre-paint script must not follow the OS preference; default is dark")
	}
	if !strings.Contains(prepaintJS, "t = 'dark'") {
		t.Error("pre-paint script must fall back to dark")
	}
	if strings.Contains(tokensCSS, "prefers-color-scheme") {
		t.Error("inline tokens must not switch theme on prefers-color-scheme")
	}
}

// Primary buttons must take their ink from --accent-fg, which flips with the
// theme; a fixed dark ink fails AA on the light theme's accent.
func TestButtonsUseAccentFg(t *testing.T) {
	for name, css := range map[string]string{"components": componentsCSS, "auth": AuthCSS} {
		if strings.Contains(css, "#0a0b0d") {
			t.Errorf("%s CSS hard-codes #0a0b0d; use var(--accent-fg)", name)
		}
	}
	if !strings.Contains(componentsCSS, ".btn, .cta-btn { background: var(--accent); color: var(--accent-fg); }") {
		t.Error("shared primary button must use --accent-fg")
	}
}

// The app name is MCTL: Telegram API ToS §2.3 bars "Telegram" from an app's
// name. Match delimited forms only, because the topbar and footer link to the
// github.com/mctlhq/mctl-telegram repository on purpose.
func TestChromeBrandIsMCTL(t *testing.T) {
	pages := map[string]string{
		"full": `<!doctype html><html lang="en"><head>{{template "ui_head" .}}</head>` +
			`<body>{{template "ui_topbar" .}}{{template "ui_footer" .}}</body></html>`,
		"lite": `<!doctype html><html lang="en"><head>{{template "ui_head_lite" .}}</head>` +
			`<body>{{template "ui_topbar_lite" .}}{{template "ui_footer_lite" .}}</body></html>`,
	}
	for name, page := range pages {
		out := render(t, name, page, Data{Title: "T", PublicBaseURL: "https://tg.mctl.ai"})
		// Accent "M" + "CTL" wordmark, in both the topbar and the footer.
		const mark = `<span class="wordmark"><span class="wordmark-m">M</span><span class="wordmark-ctl">CTL</span></span>`
		if n := strings.Count(out, mark); n != 2 {
			t.Errorf("%s page: topbar and footer must both carry the MCTL wordmark, found %d", name, n)
		}
		if !strings.Contains(out, "© 2026 MCTL") {
			t.Errorf("%s page: footer must carry the MCTL copyright line", name)
		}
		if name == "full" && !strings.Contains(out, `<meta property="og:site_name" content="MCTL Assistant">`) {
			t.Errorf("%s page: og:site_name must be MCTL Assistant", name)
		}
		for _, bad := range []string{`content="mctl-telegram"`, ">mctl-telegram<", "MCTL Telegram", `<span class="mark">`} {
			if strings.Contains(out, bad) {
				t.Errorf("%s page still has old brand %q", name, bad)
			}
		}
	}
}

// TestCtrlListColumnCanShrink guards the phone layout: a bare 1fr grid column
// has an auto minimum, so a <pre> snippet inside a ul.ctrl item widened the
// whole list to ~550px at a 375px viewport and clipped every item's text.
func TestCtrlListColumnCanShrink(t *testing.T) {
	i := strings.Index(componentsCSS, "ul.ctrl {")
	if i < 0 {
		t.Fatal("ul.ctrl rule not found")
	}
	rule := componentsCSS[i : i+strings.Index(componentsCSS[i:], "}")]
	if !strings.Contains(rule, "grid-template-columns: minmax(0, 1fr);") {
		t.Fatalf("ul.ctrl column must be minmax(0, 1fr); rule:\n%s", rule)
	}
}

// The mobile-menu checkbox must not be focusable on desktop, where nothing
// gives it meaning: display:none outside the mobile query.
func TestNavToggleHiddenOnDesktop(t *testing.T) {
	if !strings.Contains(componentsCSS, "  .nav-toggle { display: none; }") {
		t.Fatal(".nav-toggle must be display:none outside the mobile query")
	}
	m := strings.Index(componentsCSS, "@media (max-width: 1023px)")
	if m < 0 || !strings.Contains(componentsCSS[m:], ".nav-toggle {\n      display: block;") {
		t.Fatal(".nav-toggle must be re-enabled (visually hidden) inside the mobile query")
	}
}

// The inlined site.css mirror must be the same version the content pages link
// from the CDN; otherwise strict-CSP pages and a CDN outage would lay out
// differently from the pinned sheet. The published file's first line names
// its version.
func TestSiteCSSMirrorMatchesPinnedVersion(t *testing.T) {
	first, _, found := strings.Cut(siteCSS, "\n")
	if !found {
		t.Fatalf("assets/site.css header line is missing its newline")
	}
	if want := "/* @mctlhq/css " + DesignVersion + " — site.css. */"; first != want {
		t.Fatalf("assets/site.css header = %q, want %q (refresh the mirror with the pin)", first, want)
	}
	if !strings.Contains(ComponentsCSS, siteCSS) {
		t.Fatal("ComponentsCSS (strict-CSP pages) must carry the site.css mirror")
	}
}

// Strict-CSP pages load no CDN sheet, so every token the site.css mirror reads
// without a fallback must be in the inline subset. 0.18.0 put the header on
// --mctl-z-index-nav; missing here, the open mobile menu drew under the page.
func TestSiteCSSTokensInInlineSubset(t *testing.T) {
	re := regexp.MustCompile(`var\((--[a-z0-9-]+)\)`)
	for _, m := range re.FindAllStringSubmatch(siteCSS, -1) {
		if !strings.Contains(tokensCSS, m[1]+":") {
			t.Errorf("site.css reads %s with no fallback, but tokens.css does not define it", m[1])
		}
	}
}

// The content box is 1400px plus a 20px gutter on each side, the same edge as
// mctl.ai and docs.mctl.ai. The old 920px .wrap (an 872px column) and the
// 100vw header/footer breakout it needed must not come back.
func TestNoLocalPageWrap(t *testing.T) {
	for _, bad := range []string{".wrap {", "100vw", ".topbar {", "max-width: 920px"} {
		if strings.Contains(componentsCSS, bad) {
			t.Errorf("components.css still has the pre-0.15 page box %q", bad)
		}
	}
	if !strings.Contains(tokensCSS, "--site-content-width: 1400px;") || !strings.Contains(tokensCSS, "--site-gutter: 20px;") {
		t.Error("fallback tokens must carry the 1400px content width and 20px gutter")
	}
	if !strings.Contains(tokensCSS, "--mctl-layout-prose-width: 720px;") {
		t.Error("fallback tokens must carry the 720px prose width site.css reads")
	}
}
