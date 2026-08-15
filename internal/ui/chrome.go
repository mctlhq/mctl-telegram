// Package ui holds the shared visual chrome (design tokens, topbar, footer,
// theme script) for every human-facing mctl-telegram page, so the look is
// defined once instead of copy-pasted per page. It lives in its own package
// because both internal/web and internal/oauth render pages and web
// deliberately avoids importing oauth.
//
// Two tiers are provided:
//   - "full"  — content pages (landing, docs, security, privacy). Loads
//     ui.mctl.ai/mctl.css + Google Fonts as progressive enhancement and runs
//     the light/dark toggle JS (the choice persists in localStorage;
//     it defaults to the OS preference until the user flips it).
//   - "lite"  — OAuth-flow pages served under a strict CSP
//     (default-src 'none'; style-src 'unsafe-inline'; img-src https://ui.mctl.ai).
//     No external CSS/JS: same palette via inlined tokens, theme follows the OS
//     via a prefers-color-scheme fallback baked into tokens.css. The tab icon
//     is the only CDN fetch (favicon-telegram.svg).
package ui

import (
	_ "embed"
	"html/template"
)

//go:embed assets/tokens.css
var tokensCSS string

//go:embed assets/components.css
var componentsCSS string

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
	NavActive     string // "home" | "docs" | "security" | "privacy" | "terms" | "demo" | "manage" | ""
	PublicBaseURL string // shown in the footer, and used as the og:url / og:image origin
	ShowManage    bool   // set true only when /telegram/connect/manage is mounted (local-jwt auth mode)
}

// FaviconLink is the shared tab icon pointing at the design-CDN terracotta T
// badge. Content pages and strict-CSP OAuth heads both concatenate this so the
// URL lives in one place. Those CSP pages must allow https://ui.mctl.ai on img-src.
const FaviconLink = `<link rel="icon" type="image/svg+xml" href="https://ui.mctl.ai/brand/favicon-telegram.svg?v=9dc770313d10">`

// Shared template defines. CSS/JS are concatenated in as literal template text
// (they contain no {{ }} actions), so there is no escaping concern.
var defs = `
{{define "ui_head"}}<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<meta name="description" content="{{if .Description}}{{.Description}}{{else}}Connect Telegram to Claude, ChatGPT, or any AI assistant. Summarise unread chats, draft replies, and search your history — no extra apps.{{end}}">
` + FaviconLink + `
<link rel="shortcut icon" href="/favicon.ico">
<meta property="og:type" content="website">
<meta property="og:site_name" content="mctl-telegram">
<meta property="og:title" content="{{.Title}}">
<meta property="og:description" content="{{if .Description}}{{.Description}}{{else}}Connect Telegram to Claude, ChatGPT, or any AI assistant. Summarise unread chats, draft replies, and search your history — no extra apps.{{end}}">
<meta property="og:url" content="{{.PublicBaseURL}}">
<meta property="og:image" content="{{.PublicBaseURL}}/og.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{{.Title}}">
<meta name="twitter:description" content="{{if .Description}}{{.Description}}{{else}}Connect Telegram to Claude, ChatGPT, or any AI assistant. Summarise unread chats, draft replies, and search your history — no extra apps.{{end}}">
<meta name="twitter:image" content="{{.PublicBaseURL}}/og.png">
<style>` + tokensCSS + `</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Onest:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://ui.mctl.ai/mctl.css">
<script>` + prepaintJS + `</script>
<style>` + componentsCSS + `</style>{{end}}

{{define "ui_topbar"}}<header class="topbar">
    <a class="brand" href="/">
      <span class="mark">M</span>
      <span>mctl-telegram</span>
    </a>
    <nav class="meta">
      <a href="/"{{if eq .NavActive "home"}} class="active"{{end}}>home</a>
      <a href="/docs"{{if eq .NavActive "docs"}} class="active"{{end}}>docs</a>
      <a href="/demo"{{if eq .NavActive "demo"}} class="active"{{end}}>demo</a>
      <a href="/security"{{if eq .NavActive "security"}} class="active"{{end}}>security</a>
      <a href="/privacy"{{if eq .NavActive "privacy"}} class="active"{{end}}>privacy</a>
      <a href="/terms"{{if eq .NavActive "terms"}} class="active"{{end}}>terms</a>
      {{if .ShowManage}}<a href="/telegram/connect/manage"{{if eq .NavActive "manage"}} class="active"{{end}}>manage</a>{{end}}
      <a href="https://github.com/mctlhq/mctl-telegram" target="_blank" rel="noopener" aria-label="GitHub" title="GitHub" class="gh-link"><svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.65 7.65 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg></a>
      <button class="theme-toggle" type="button" aria-label="Toggle theme" title="Toggle theme">
        <svg class="icon-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
        <svg class="icon-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"></path></svg>
      </button>
    </nav>
  </header>{{end}}

{{define "ui_footer"}}<footer>
    <div class="links">
      <span class="brand-mark">mctl-telegram</span>
      <span class="sep">·</span>
      <a href="/">home</a>
      <span class="sep">·</span>
      <a href="/docs">docs</a>
      <span class="sep">·</span>
      <a href="/security">security</a>
      <span class="sep">·</span>
      <a href="/privacy">privacy</a>
      <span class="sep">·</span>
      <a href="/terms">terms</a>
      <span class="sep">·</span>
      <a href="/demo">demo</a>
      <span class="sep">·</span>
      <a href="mailto:support@mctl.ai">support</a>
      {{if .ShowManage}}<span class="sep">·</span>
      <a href="/telegram/connect/manage">manage</a>{{end}}
      <span class="sep">·</span>
      <a href="https://github.com/mctlhq/mctl-telegram" target="_blank" rel="noopener">source</a>
    </div>
    <span>service: <code>{{.PublicBaseURL}}</code></span>
  </footer>{{end}}

{{define "ui_script"}}<script>` + toggleJS + `</script>{{end}}

{{define "ui_head_lite"}}<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
` + FaviconLink + `
<style>` + tokensCSS + componentsCSS + `</style>{{end}}

{{define "ui_topbar_lite"}}` + topbarLiteHTML + `{{end}}

{{define "ui_footer_lite"}}` + footerLiteHTML + `{{end}}
`

// topbarLiteHTML / footerLiteHTML are the static (no-JS) chrome markup for
// strict-CSP pages. Exported via TopbarLite/FooterLite for callers that build
// their HTML by string concatenation instead of the template defines.
const topbarLiteHTML = `<header class="topbar">
    <a class="brand" href="/">
      <span class="mark">M</span>
      <span>mctl-telegram</span>
    </a>
  </header>`

const footerLiteHTML = `<footer>
    <div class="links">
      <span class="brand-mark">mctl-telegram</span>
      <span class="sep">·</span>
      <a href="/">home</a>
      <span class="sep">·</span>
      <a href="/security">security</a>
      <span class="sep">·</span>
      <a href="/privacy">privacy</a>
    </div>
  </footer>`

// Exported building blocks for strict-CSP pages (OAuth flow) that compose their
// HTML as plain strings under a CSP that forbids external CSS/JS. TokensCSS +
// ComponentsCSS go inside one <style>; TopbarLite/FooterLite are the markup.
// Theme follows the OS via the prefers-color-scheme fallback in tokens.css.
var (
	TokensCSS     = tokensCSS
	ComponentsCSS = componentsCSS
	TopbarLite    = topbarLiteHTML
	FooterLite    = footerLiteHTML
)

// AuthCSS styles the OAuth-flow card / primary button / step indicator using
// the shared design tokens. Append it inside the same <style> as TokensCSS +
// ComponentsCSS. The step indicator is .flow-steps (not the shared numbered
// ol.steps) to avoid clashing with the component CSS inlined alongside it.
const AuthCSS = `
  .auth-main { max-width: 520px; margin: 56px auto; }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-top: 2px solid var(--accent);
    border-radius: var(--mctl-radius-lg); padding: 32px 28px;
    box-shadow: 0 4px 28px color-mix(in srgb, var(--accent) 5%, transparent);
  }
  .card h1 { font-family: var(--font-display), system-ui, sans-serif; font-size: 22px; font-weight: 600; margin: 0 0 12px; color: var(--text); }
  .card p { margin: 8px 0; }
  .btn {
    display: inline-block; width: 100%; box-sizing: border-box; text-align: center;
    margin-top: 20px; font-family: var(--font-display), system-ui, sans-serif;
    font-size: 15px; font-weight: 600; padding: 11px 16px; border: 0; cursor: pointer;
    border-radius: var(--mctl-radius-md); background: var(--accent); color: #0a0b0d; text-decoration: none;
  }
  .btn:hover { filter: brightness(.92); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 22%, transparent); }
  .btn-secondary {
    display: inline-block; box-sizing: border-box; text-align: center; cursor: pointer;
    font-family: var(--font-display), system-ui, sans-serif; font-size: 14px; font-weight: 600;
    padding: 9px 16px; border-radius: var(--mctl-radius-md);
    background: var(--surface); color: var(--text); border: 1px solid var(--border-strong);
  }
  .btn-secondary:hover { background: var(--surface-elevated); border-color: var(--accent); }
  input[type="text"], input[type="tel"], input[type="password"] {
    width: 100%; box-sizing: border-box; margin-top: 6px; padding: 10px 12px;
    font-family: var(--font-mono); font-size: 14px;
    background: var(--surface-elevated); color: var(--text);
    border: 1px solid var(--border-strong); border-radius: var(--mctl-radius-md);
  }
  label { display: block; margin-top: 14px; font-size: 13px; color: var(--text-dim); }
  .flow-steps { display: flex; list-style: none; padding: 0; margin: 0 0 26px; gap: 0; }
  .flow-steps li { flex: 1; text-align: center; font-family: var(--font-mono); font-size: 11px; text-transform: uppercase; letter-spacing: .06em; padding: 10px 4px; border-bottom: 2px solid var(--border); color: var(--muted); transition: color .15s, border-color .15s; }
  .flow-steps li.active { border-bottom-color: var(--accent); color: var(--accent); font-weight: 600; }
  .error { background: var(--warn-soft); border: 1px solid color-mix(in srgb, var(--danger) 45%, transparent); border-radius: var(--mctl-radius-md); padding: 10px 12px; font-size: 13px; color: var(--danger); margin: 12px 0; }
  .meta { font-size: 13px; color: var(--muted); margin-top: 18px; }
  .url { font-family: var(--font-mono); font-size: 13px; word-break: break-all; color: var(--accent-highlight); }
`

// base carries the shared defines; pages clone it and add their own body.
var base = template.Must(template.New("ui").Parse(defs))

// New returns a template named name whose body is page and which can reference
// the shared {{template "ui_*"}} defines. Execute it with ExecuteTemplate(w, name, data).
func New(name, page string) *template.Template {
	return template.Must(template.Must(base.Clone()).New(name).Parse(page))
}
