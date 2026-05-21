// Package ui holds the shared visual chrome (design tokens, topbar, footer,
// theme script) for every human-facing mctl-telegram page, so the look is
// defined once instead of copy-pasted per page. It lives in its own package
// because both internal/web and internal/oauth render pages and web
// deliberately avoids importing oauth.
//
// Two tiers are provided:
//   - "full"  — content pages (landing, docs, security, privacy). Loads
//     ui.mctl.ai/mctl.css + Google Fonts as progressive enhancement and runs
//     the theme/accent toggle JS.
//   - "lite"  — OAuth-flow pages served under a strict CSP
//     (default-src 'none'; style-src 'unsafe-inline'). No external resources
//     and no JS: same palette via inlined tokens, theme follows the OS via a
//     prefers-color-scheme fallback baked into tokens.css.
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
	NavActive     string // "home" | "docs" | "security" | "privacy" | ""
	PublicBaseURL string // shown in the footer
}

// Shared template defines. CSS/JS are concatenated in as literal template text
// (they contain no {{ }} actions), so there is no escaping concern.
var defs = `
{{define "ui_head"}}<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="shortcut icon" href="/favicon.ico">
<style>` + tokensCSS + `</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
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
      <a href="/security"{{if eq .NavActive "security"}} class="active"{{end}}>security</a>
      <a href="/privacy"{{if eq .NavActive "privacy"}} class="active"{{end}}>privacy</a>
      <a href="https://github.com/mctlhq/mctl-telegram" target="_blank" rel="noopener">github ↗</a>
      <span class="accent-picker hide-sm" role="group" aria-label="Accent color">
        <button class="accent-swatch" type="button" data-pick="cyan"      aria-label="Cyan accent"      title="Cyan"></button>
        <button class="accent-swatch" type="button" data-pick="lime"      aria-label="Lime accent"      title="Lime"></button>
        <button class="accent-swatch" type="button" data-pick="vermilion" aria-label="Vermilion accent" title="Vermilion"></button>
        <button class="accent-swatch" type="button" data-pick="lilac"     aria-label="Lilac accent"     title="Lilac"></button>
      </span>
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
      <a href="https://github.com/mctlhq/mctl-telegram" target="_blank" rel="noopener">source</a>
    </div>
    <span>resource: <code>{{.PublicBaseURL}}</code></span>
  </footer>{{end}}

{{define "ui_script"}}<script>` + toggleJS + `</script>{{end}}

{{define "ui_head_lite"}}<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
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
  .auth-main { max-width: 520px; margin: 48px auto; }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--mctl-radius-lg); padding: 28px 26px;
  }
  .card h1 { font-family: var(--font-display), system-ui, sans-serif; font-size: 22px; font-weight: 600; margin: 0 0 12px; color: var(--text); }
  .card p { margin: 8px 0; }
  .btn {
    display: inline-block; width: 100%; box-sizing: border-box; text-align: center;
    margin-top: 20px; font-family: var(--font-display), system-ui, sans-serif;
    font-size: 15px; font-weight: 600; padding: 11px 16px; border: 0; cursor: pointer;
    border-radius: var(--mctl-radius-md); background: var(--accent); color: #0a0b0d; text-decoration: none;
  }
  .btn:hover { filter: brightness(.92); }
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
  .flow-steps { display: flex; list-style: none; padding: 0; margin: 0 0 22px; gap: 0; }
  .flow-steps li { flex: 1; text-align: center; font-size: 12px; padding: 8px 4px; border-bottom: 2px solid var(--border); color: var(--muted); }
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
