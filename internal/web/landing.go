// Package web serves the human-facing landing page that explains how
// to wire mctl-telegram into Claude.ai as a custom MCP connector.
package web

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/ui"
)

//go:embed landing.html
var landingHTML string

//go:embed favicon.svg
var faviconSVG []byte

// Favicon returns the SVG favicon at /favicon.svg and /favicon.ico.
func Favicon() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(faviconSVG)
	}
}

var landingTmpl = ui.New("landing", landingHTML)

// landingData is shared by the landing and docs pages: it embeds the shared
// chrome data (Title, NavActive, PublicBaseURL) and adds the deployment URLs
// both templates render.
type landingData struct {
	ui.Data
	MCPURL       string
	WellKnownURL string
	AuthServer   string
}

// Landing renders the connection-instructions HTML at PublicBaseURL/.
// MCPPath is rendered into the page so the operator sees the exact URL
// to paste into Claude.ai's "Add custom connector" dialog.
//
// authServer is the issuer URL used by the OAuth flow. For the Telegram-native
// auth model this is the same as publicBaseURL — mctl-telegram is its own
// authorization server. The legacy "shared-hmac" mode points it at
// https://api.mctl.ai; main.go decides which one to pass in.
func Landing(publicBaseURL, mcpPath, authServer string) http.HandlerFunc {
	base := strings.TrimRight(publicBaseURL, "/")
	mcpPath = "/" + strings.TrimLeft(mcpPath, "/")
	if authServer == "" {
		authServer = base
	}
	data := landingData{
		Data:         ui.Data{Title: "mctl-telegram — Your Telegram, inside your AI assistant", NavActive: "home", PublicBaseURL: base},
		MCPURL:       base + mcpPath,
		WellKnownURL: base + "/.well-known/oauth-protected-resource",
		AuthServer:   authServer,
	}
	return chromePage(landingTmpl, "landing", data)
}

// BrowserRedirect wraps an MCP Streamable-HTTP handler so that a plain
// browser navigation to /mcp (Accept: text/html, no JSON-RPC body) is
// bounced to the landing page instead of returning an empty SSE stream.
// MCP clients send Accept: application/json, text/event-stream — those
// fall through to the real handler unchanged.
func BrowserRedirect(next http.Handler, landingPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && isBrowserGet(r.Header.Get("Accept")) {
			http.Redirect(w, r, landingPath, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isBrowserGet(accept string) bool {
	if accept == "" {
		return false
	}
	a := strings.ToLower(accept)
	if !strings.Contains(a, "text/html") {
		return false
	}
	// MCP clients announce JSON and SSE explicitly — if either is present,
	// it's a real client and we must not redirect.
	if strings.Contains(a, "application/json") || strings.Contains(a, "text/event-stream") {
		return false
	}
	return true
}
