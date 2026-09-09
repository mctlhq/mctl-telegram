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
		`<body><div class="wrap">{{template "ui_topbar" .}}<main></main>{{template "ui_footer" .}}</div>{{template "ui_script" .}}</body></html>`
	out := render(t, "full", page, Data{Title: "T", NavActive: "docs", PublicBaseURL: "https://tg.mctl.ai"})

	for _, s := range []string{
		`class="topbar"`,
		"ui.mctl.ai/0.5.0/mctl.css",
		"family=Onest",
		"JetBrains+Mono",
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
		"#e25a3c",
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
		`<body><div class="wrap">{{template "ui_topbar_lite" .}}{{template "ui_footer_lite" .}}</div></body></html>`
	out := render(t, "lite", page, Data{Title: "L"})

	for _, bad := range []string{"mctl.css", "fonts.googleapis.com", "<script", `href="/favicon.svg"`, "accent-swatch", "accent-picker"} {
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
}
