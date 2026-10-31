// Package ui holds the shared visual chrome (design tokens, topbar, footer,
// theme script) for every human-facing mctl-telegram page, so the look is
// defined once instead of copy-pasted per page. It lives in its own package
// because both internal/web and internal/oauth render pages and web
// deliberately avoids importing oauth.
//
// The look follows the shared public site shell of mctl.ai and docs.mctl.ai
// (mctl-design): full-width header with the accent-"M" wordmark, Title Case
// nav in the display face, the BaseButton/BaseCard recipes, the docs table
// style and the centred wordmark footer. The layout boxes (header, container,
// hero, section, card grid, reading column, footer) are the shared
// .mctl-site-* classes from @mctlhq/css site.css, so the brand, hero, section
// titles and cards start on the same edge as on mctl.ai and docs.mctl.ai.
//
// Page markup: the header and footer sit directly in <body>, full-bleed, and
// the page content sits in <main class="mctl-site-container ...">. Long-form
// pages put their content in .mctl-site-prose (the 720px reading width).
//
// Two tiers are provided:
//   - "full"  — content pages (landing, docs, security, privacy). Loads
//     ui.mctl.ai/<version>/{mctl,global,site}.css + Google Fonts as progressive
//     enhancement and runs the light/dark toggle JS (the choice persists in
//     localStorage; with nothing stored the page is dark, like the sibling
//     sites), plus the self-hosted Umami page-view counter (AnalyticsScript).
//     The mobile nav menu is CSS-only and works without JS.
//   - "lite"  — OAuth-flow pages served under a strict CSP
//     (default-src 'none'; style-src 'unsafe-inline'; img-src https://ui.mctl.ai).
//     No external CSS/JS: same palette and layout via inlined tokens and the
//     site.css mirror (dark, since there is no script to read a stored
//     choice). The tab icon is the only CDN fetch (favicon-telegram.svg).
package ui

import (
	_ "embed"
	"html/template"
	"sync/atomic"
)

//go:embed assets/tokens.css
var tokensCSS string

//go:embed assets/components.css
var componentsCSS string

// siteCSS mirrors ui.mctl.ai/<DesignVersion>/site.css verbatim (its first line
// names the version). It is the only layout source on the strict-CSP pages and
// the fallback on content pages when the CDN is unreachable; there the CDN
// copy is linked after it and wins.
//
//go:embed assets/site.css
var siteCSS string

//go:embed assets/prepaint.js
var prepaintJS string

//go:embed assets/toggle.js
var toggleJS string

// Data is the common template data every page provides for the shared chrome.
// Pages embed it anonymously in their own data struct so page-specific fields
// (e.g. MCPURL) sit alongside these.
type Data struct {
	Title         string // <title> text
	Description   string // social-share / meta description; falls back to a default when empty
	NavActive     string // "docs" | "platforms" | "assistants" | "demo" | "manage" highlight a header link; "home" | "security" | "privacy" | "terms" | "" highlight none (those pages are linked from the footer and the landing hero)
	PublicBaseURL string // shown in the footer, and used as the og:url / og:image origin
	ShowManage    bool   // set true only when /telegram/connect/manage is mounted (local-jwt auth mode)
	CanonicalPath string // when set, emits <link rel="canonical"> at PublicBaseURL+CanonicalPath
	NoIndex       bool   // when set, emits <meta name="robots" content="noindex, follow">
}

// FaviconLink is the shared tab icon pointing at the design-CDN terracotta T
// badge. Content pages and strict-CSP OAuth heads both concatenate this so the
// URL lives in one place. Those CSP pages must allow https://ui.mctl.ai on img-src.
const FaviconLink = `<link rel="icon" type="image/svg+xml" href="https://ui.mctl.ai/brand/favicon-telegram.svg?v=9dc770313d10">`

// AnalyticsScript is the self-hosted Umami tracker (stats.mctl.ai). It belongs
// to the full chrome only, i.e. public content pages, which send no CSP. The
// lite chrome used by OAuth, connect and manage pages must never carry it:
// those pages show codes, tokens and account data, and their strict CSP
// (default-src 'none') would block it anyway. data-domains keeps preview and
// local runs out of the numbers; the website ID is public by design.
const AnalyticsScript = `<script defer src="https://stats.mctl.ai/insights.js" data-website-id="d4fa9d69-8b07-4d27-98e6-0b611eeaa707" data-domains="tg.mctl.ai"></script>`

// DesignVersion is the published @mctlhq/css version every full-chrome page
// loads. mctl.css, global.css and site.css are pinned together as a set;
// tokens.css mirrors the same version's values and site.css is mirrored
// verbatim, for the strict-CSP pages and as a fallback when the CDN is
// unreachable.
const DesignVersion = "0.19.0"

// wordmark is the MCTL brand mark: accent "M" + "CTL", as LogoDefault.vue
// (mctl.ai) and BrandMark.vue (docs.mctl.ai) draw it.
const wordmark = `<span class="wordmark"><span class="wordmark-m">M</span><span class="wordmark-ctl">CTL</span></span>`

// Shared template defines. CSS/JS are concatenated in as literal template text
// (they contain no {{ }} actions), so there is no escaping concern.
var defs = `
{{define "ui_head"}}<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{{if .NoIndex}}<meta name="robots" content="noindex, follow">
{{end}}<title>{{.Title}}</title>
<meta name="description" content="{{if .Description}}{{.Description}}{{else}}Connect Telegram to Claude, ChatGPT, or any AI assistant. Summarize unread chats, draft replies, and search your history — no extra apps.{{end}}">
{{if .CanonicalPath}}<link rel="canonical" href="{{.PublicBaseURL}}{{.CanonicalPath}}">
{{end}}` + FaviconLink + `
<link rel="shortcut icon" href="/favicon.ico">
<meta property="og:type" content="website">
<meta property="og:site_name" content="MCTL Assistant">
<meta property="og:title" content="{{.Title}}">
<meta property="og:description" content="{{if .Description}}{{.Description}}{{else}}Connect Telegram to Claude, ChatGPT, or any AI assistant. Summarize unread chats, draft replies, and search your history — no extra apps.{{end}}">
<meta property="og:url" content="{{.PublicBaseURL}}">
<meta property="og:image" content="{{.PublicBaseURL}}/og.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{{.Title}}">
<meta name="twitter:description" content="{{if .Description}}{{.Description}}{{else}}Connect Telegram to Claude, ChatGPT, or any AI assistant. Summarize unread chats, draft replies, and search your history — no extra apps.{{end}}">
<meta name="twitter:image" content="{{.PublicBaseURL}}/og.png">
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "MCTL Assistant",
  "applicationCategory": "DeveloperApplication",
  "operatingSystem": "Cloud",
  "url": "{{.PublicBaseURL}}",
  "description": "Connect Telegram to Claude, ChatGPT, or any AI assistant via MCP",
  "provider": {
    "@type": "Organization",
    "@id": "https://mctl.ai/#organization",
    "name": "MCTL",
    "url": "https://mctl.ai"
  }
}
</script>
<style>` + tokensCSS + siteCSS + `</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Onest:wght@300;400;500;600;700;800&family=Instrument+Serif:ital@0;1&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://ui.mctl.ai/` + DesignVersion + `/mctl.css">
<link rel="stylesheet" href="https://ui.mctl.ai/` + DesignVersion + `/global.css">
<link rel="stylesheet" href="https://ui.mctl.ai/` + DesignVersion + `/site.css">
<script>` + prepaintJS + `</script>
` + AnalyticsScript + `
<style>` + componentsCSS + `</style>{{end}}

{{define "ui_topbar"}}<header class="mctl-site-header">
    <div class="mctl-site-container mctl-site-header__inner">
    <a class="mctl-site-brand" href="/" aria-label="MCTL home">` + wordmark + `</a>
    <input type="checkbox" id="site-nav-toggle" class="nav-toggle" aria-label="Open menu" aria-controls="site-nav">
    <label for="site-nav-toggle" class="nav-burger" title="Menu"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg></label>
    <nav class="site-nav" id="site-nav" aria-label="Main">
      <a href="/docs"{{if eq .NavActive "docs"}} class="active"{{end}}>Docs</a>
      <a href="/platforms"{{if eq .NavActive "platforms"}} class="active"{{end}}>Platforms</a>
      {{if assistantsMounted}}<a href="/assistants"{{if eq .NavActive "assistants"}} class="active"{{end}}>Assistants</a>{{end}}
      <a href="/demo"{{if eq .NavActive "demo"}} class="active"{{end}}>Demo</a>
      {{if .ShowManage}}<a href="/telegram/connect/manage" class="nav-manage{{if eq .NavActive "manage"}} active{{end}}">Manage</a>{{end}}
      <a href="https://github.com/mctlhq/mctl-telegram" target="_blank" rel="noopener" aria-label="GitHub" title="GitHub" class="gh-link"><svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.65 7.65 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg></a>
    </nav>
    <button class="theme-toggle" type="button" aria-label="Toggle theme" title="Toggle theme">
      <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
      <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"></path></svg>
    </button>
    </div>
  </header>{{end}}

{{define "ui_footer"}}<footer class="mctl-site-footer">
    <div class="mctl-site-container mctl-site-footer__inner">
    <a class="brand" href="/" aria-label="MCTL home">` + wordmark + `</a>
    <nav class="mctl-site-footer__links" aria-label="Footer">
      <a href="https://mctl.ai" target="_blank" rel="noopener">Platform</a>
      <a href="https://alice.mctl.ai" target="_blank" rel="noopener">Alice MCP</a>
      <a href="/">Home</a>
      <a href="/docs">Docs</a>
      <a href="/platforms">Platforms</a>
      {{if assistantsMounted}}<a href="/assistants">Assistants</a>
      {{end}}<a href="/demo">Demo</a>
      <a href="/security">Security</a>
      <a href="/privacy">Privacy</a>
      <a href="/terms">Terms</a>
      <a href="mailto:support@mctl.ai">Support</a>
      {{if .ShowManage}}<a href="/telegram/connect/manage">Manage</a>
      {{end}}<a href="https://github.com/mctlhq/mctl-telegram" target="_blank" rel="noopener">GitHub</a>
    </nav>
    <p class="mctl-site-footer__copy">© 2026 MCTL</p>
    <p class="service">Service: <code>{{.PublicBaseURL}}</code></p>
    </div>
  </footer>{{end}}

{{define "ui_script"}}<script>` + toggleJS + `</script>{{end}}

{{define "ui_head_lite"}}<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
` + FaviconLink + `
<style>` + tokensCSS + siteCSS + componentsCSS + `</style>{{end}}

{{define "ui_topbar_lite"}}` + topbarLiteHTML + `{{end}}

{{define "ui_footer_lite"}}` + footerLiteHTML + `{{end}}
`

// topbarLiteHTML / footerLiteHTML are the static (no-JS) chrome markup for
// strict-CSP pages. Exported via TopbarLite/FooterLite for callers that build
// their HTML by string concatenation instead of the template defines.
const topbarLiteHTML = `<header class="mctl-site-header">
    <div class="mctl-site-container mctl-site-header__inner">
    <a class="mctl-site-brand" href="/" aria-label="MCTL home">` + wordmark + `</a>
    </div>
  </header>`

const footerLiteHTML = `<footer class="mctl-site-footer">
    <div class="mctl-site-container mctl-site-footer__inner">
    <a class="brand" href="/" aria-label="MCTL home">` + wordmark + `</a>
    <nav class="mctl-site-footer__links" aria-label="Footer">
      <a href="/">Home</a>
      <a href="/security">Security</a>
      <a href="/privacy">Privacy</a>
    </nav>
    <p class="mctl-site-footer__copy">© 2026 MCTL</p>
    </div>
  </footer>`

// Exported building blocks for strict-CSP pages (OAuth flow) that compose their
// HTML as plain strings under a CSP that forbids external CSS/JS. TokensCSS +
// ComponentsCSS go inside one <style>; ComponentsCSS carries the site.css
// mirror first, so the .mctl-site-* layout classes work there too.
// TopbarLite/FooterLite are the markup; the page puts them directly in <body>
// around <div class="mctl-site-container"><main class="auth-main">...</main></div>.
// The theme is the design system's dark default (no script, no stored choice).
var (
	TokensCSS     = tokensCSS
	ComponentsCSS = siteCSS + componentsCSS
	TopbarLite    = topbarLiteHTML
	FooterLite    = footerLiteHTML
)

// AuthCSS styles the OAuth-flow card / step indicator / form fields using the
// shared design tokens. Append it inside the same <style> as TokensCSS +
// ComponentsCSS. Buttons are the shared .btn / .btn-secondary from
// components.css; only their in-card layout is set here. The step indicator is
// .flow-steps (not the shared numbered ol.steps) to avoid clashing with the
// component CSS inlined alongside it.
const AuthCSS = `
  .auth-main { max-width: 520px; margin: 56px auto; }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--mctl-radius-lg); padding: 32px 28px;
    box-shadow: var(--shadow-sm);
  }
  .card h1 { font-family: var(--font-display), system-ui, sans-serif; font-size: 24px; font-weight: 700; line-height: 1.3; letter-spacing: -.01em; margin: 0 0 12px; color: var(--text); }
  .card h2 { border-bottom: 0; padding-bottom: 0; }
  .card h2:not([class]) { font-size: 17px; font-weight: 600; margin: 24px 0 8px; }
  .card p { margin: 8px 0; }
  .card .btn { display: flex; width: 100%; margin-top: 20px; padding: 11px 16px; text-align: center; }
  input[type="text"], input[type="tel"], input[type="password"] {
    width: 100%; box-sizing: border-box; margin-top: 6px; padding: 10px 12px;
    font-family: var(--font-mono); font-size: 14px;
    background: var(--surface-elevated); color: var(--text);
    border: 1px solid var(--border-strong); border-radius: var(--mctl-radius-md);
  }
  label { display: block; margin-top: 14px; font-size: 13px; color: var(--text-dim); }
  .flow-steps { display: flex; list-style: none; padding: 0; margin: 0 0 26px; gap: 0; }
  .flow-steps li { flex: 1; text-align: center; font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; padding: 10px 4px; border-bottom: 2px solid var(--border); color: var(--muted); transition: color .15s, border-color .15s; }
  .flow-steps li.active { border-bottom-color: var(--accent); color: var(--accent-text); font-weight: 600; }
  .error { background: var(--status-bad-soft); border: 1px solid color-mix(in srgb, var(--danger) 45%, transparent); border-radius: var(--mctl-radius-md); padding: 10px 12px; font-size: 13px; color: var(--status-bad-text); margin: 12px 0; }
  .meta { font-size: 13px; color: var(--muted); margin-top: 18px; }
  .url { font-family: var(--font-mono); font-size: 13px; word-break: break-all; color: var(--accent-highlight); }
`

// assistantsMounted records whether the server mounted /assistants (it only
// does with AGENT_ENABLED), so the header and footer link to it only where it
// exists. It is set once at startup, before any page renders, and read at
// render time, so every page picks it up without each handler carrying it.
var assistantsMounted atomic.Bool

// SetAssistantsMounted tells the shared chrome whether /assistants is served.
func SetAssistantsMounted(on bool) { assistantsMounted.Store(on) }

// base carries the shared defines; pages clone it and add their own body.
var base = template.Must(template.New("ui").Funcs(template.FuncMap{
	"assistantsMounted": assistantsMounted.Load,
}).Parse(defs))

// New returns a template named name whose body is page and which can reference
// the shared {{template "ui_*"}} defines. Execute it with ExecuteTemplate(w, name, data).
func New(name, page string) *template.Template {
	return template.Must(template.Must(base.Clone()).New(name).Parse(page))
}
