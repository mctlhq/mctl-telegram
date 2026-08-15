package ui

import (
	"bytes"
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
		`<body><div class="wrap">{{template "ui_topbar" .}}<main></main>{{template "ui_footer" .}}</div>{{template "ui_script" .}}</body></html>`
	out := render(t, "full", page, Data{Title: "T", NavActive: "docs", PublicBaseURL: "https://tg.mctl.ai"})

	for _, s := range []string{
		`class="topbar"`,
		"accent-swatch",
		"ui.mctl.ai/mctl.css",
		"ui.mctl.ai/brand/favicon-telegram.svg",
		"<footer>",
		"https://tg.mctl.ai",
		`<a href="/docs" class="active">docs</a>`,
		"support@mctl.ai",
		// GitHub icon link — inline SVG with accessible label.
		`aria-label="GitHub"`,
		// Light/dark toggle — content pages can flip the theme.
		`class="theme-toggle"`,
		`aria-label="Toggle theme"`,
	} {
		if !strings.Contains(out, s) {
			t.Errorf("full page missing %q", s)
		}
	}
}

func TestLiteChromeHasNoExternalDeps(t *testing.T) {
	page := `<!doctype html><html lang="en"><head>{{template "ui_head_lite" .}}</head>` +
		`<body><div class="wrap">{{template "ui_topbar_lite" .}}{{template "ui_footer_lite" .}}</div></body></html>`
	out := render(t, "lite", page, Data{Title: "L"})

	for _, bad := range []string{"ui.mctl.ai/mctl.css", "fonts.googleapis.com", "<script", `href="/favicon.svg"`} {
		if strings.Contains(out, bad) {
			t.Errorf("lite (strict-CSP) page must not contain %q", bad)
		}
	}
	if !strings.Contains(out, "ui.mctl.ai/brand/favicon-telegram.svg") {
		t.Error("lite page missing CDN favicon")
	}
	if !strings.Contains(out, `class="topbar"`) {
		t.Error("lite page missing topbar")
	}
}
