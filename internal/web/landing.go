// Package web serves the human-facing landing page that explains how
// to wire mctl-telegram into Claude.ai as a custom MCP connector.
package web

import (
	_ "embed"
	"html/template"
	"net/http"
	"strings"
)

//go:embed landing.html
var landingHTML string

var landingTmpl = template.Must(template.New("landing").Parse(landingHTML))

type landingData struct {
	PublicBaseURL string
	MCPURL        string
	WellKnownURL  string
	AuthServer    string
}

// Landing renders the connection-instructions HTML at PublicBaseURL/.
// MCPPath is rendered into the page so the operator sees the exact URL
// to paste into Claude.ai's "Add custom connector" dialog.
func Landing(publicBaseURL, mcpPath string) http.HandlerFunc {
	base := strings.TrimRight(publicBaseURL, "/")
	mcpPath = "/" + strings.TrimLeft(mcpPath, "/")
	data := landingData{
		PublicBaseURL: base,
		MCPURL:        base + mcpPath,
		WellKnownURL:  base + "/.well-known/oauth-protected-resource",
		AuthServer:    "https://api.mctl.ai",
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = landingTmpl.Execute(w, data)
	}
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
