package web

import (
	"net/http"
	"strings"
)

// NoIndexValue is the X-Robots-Tag value; it matches the NoIndex meta tag
// emitted by internal/ui ("noindex, follow").
const NoIndexValue = "noindex, follow"

// noIndexPrefixes are the auth, session, callback and JSON-API route trees
// that must never appear in a search index. They mirror the Disallow lines in
// robots.txt (see RobotsTxt). A Disallow alone does not remove an indexed URL
// and stops Google from seeing a noindex, so the header is the removal signal.
var noIndexPrefixes = []string{"/oauth/", "/telegram/connect", "/auth/", "/api/"}

func noIndexPath(p string) bool {
	for _, pre := range noIndexPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// SecurityHeaders sets the transport-level hardening headers every response
// from this server should carry, independent of which handler produced it.
// They are deliberately content-neutral: nothing here constrains what a page
// may load, so the MCP endpoint, OAuth metadata and HTML pages all get the
// same set. Content-Security-Policy stays per-page (see chromeCSP and the
// OAuth/connect handlers), because its allowlist depends on the page.
//
// HSTS is only meaningful on an https:// origin; a plain-http local dev
// server would pin browsers to TLS it does not offer, so it is emitted only
// when publicBaseURL is https. The other headers are harmless anywhere.
func SecurityHeaders(publicBaseURL string) func(http.Handler) http.Handler {
	hsts := strings.HasPrefix(strings.ToLower(publicBaseURL), "https://")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			if hsts {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			// Set before the handler runs so it covers every status code,
			// including 4xx/5xx and non-HTML bodies a meta tag cannot reach.
			if noIndexPath(r.URL.Path) {
				h.Set("X-Robots-Tag", NoIndexValue)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// chromeCSP is the Content-Security-Policy for the shared-chrome content pages
// (landing, docs, security, privacy, terms, demo, Local Bridge docs, product
// updates). Every script is a same-origin file under /assets/ (see
// ui.AssetHandler) or the Umami tracker, so script-src carries NO
// 'unsafe-inline': an injected inline <script> or on* handler does not run.
// JSON-LD blocks stay inline; they are data, not executed. Every page still
// inlines its own <style> and uses style attributes, hence 'unsafe-inline' on
// style-src until those are moved out in a separate change. The rest is the exact set of origins the chrome
// loads from: ui.mctl.ai (design CSS, favicon), Google Fonts, and the Umami
// analytics script at stats.mctl.ai. Two directives are deliberately wider
// than that exact set, both for /demo: media-src admits any https origin
// because the file-video branch plays whatever DEMO_VIDEO_URL the operator
// configured, and frame-src admits the two embed hosts classifyDemoVideo can
// produce (YouTube, Loom). frame-ancestors 'none' replaces X-Frame-Options;
// these pages are never meant to be embedded.
const chromeCSP = "default-src 'none'; " +
	"script-src 'self' https://stats.mctl.ai; " +
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://ui.mctl.ai; " +
	"font-src https://fonts.gstatic.com; " +
	"img-src 'self' data: https://ui.mctl.ai; " +
	"media-src 'self' https:; " +
	"frame-src https://www.youtube.com https://www.loom.com; " +
	"connect-src 'self' https://stats.mctl.ai; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
