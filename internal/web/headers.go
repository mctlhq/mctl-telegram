package web

import (
	"net/http"
	"strings"
)

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
			next.ServeHTTP(w, r)
		})
	}
}

// chromeCSP is the Content-Security-Policy for the shared-chrome content pages
// (landing, docs, security, privacy, terms, demo, Local Bridge docs, product
// updates). The chrome inlines its pre-paint theme script and toggle script
// and every page inlines its own <style>, hence 'unsafe-inline' on both
// script-src and style-src; the rest is the exact set of origins the chrome
// loads from: ui.mctl.ai (design CSS, favicon), Google Fonts, and the Umami
// analytics script at stats.mctl.ai. frame-ancestors 'none' replaces
// X-Frame-Options; these pages are never meant to be embedded.
const chromeCSP = "default-src 'none'; " +
	"script-src 'self' 'unsafe-inline' https://stats.mctl.ai; " +
	"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://ui.mctl.ai; " +
	"font-src https://fonts.gstatic.com; " +
	"img-src 'self' data: https://ui.mctl.ai; " +
	"media-src 'self' https:; " +
	"connect-src 'self' https://stats.mctl.ai; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
