package web

import (
	_ "embed"
	"html/template"
	"net/http"
	"strings"
)

//go:embed docs.html
var docsHTML string

var docsTmpl = template.Must(template.New("docs").Parse(docsHTML))

// Docs renders the developer reference page at /docs. It receives the same
// four deployment-specific values as Landing() and injects them into the
// template so the displayed endpoint URLs are correct for the deployment.
func Docs(publicBaseURL, mcpPath, authServer string) http.HandlerFunc {
	base := strings.TrimRight(publicBaseURL, "/")
	mcpPath = "/" + strings.TrimLeft(mcpPath, "/")
	if authServer == "" {
		authServer = base
	}
	data := landingData{
		PublicBaseURL: base,
		MCPURL:        base + mcpPath,
		WellKnownURL:  base + "/.well-known/oauth-protected-resource",
		AuthServer:    authServer,
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = docsTmpl.Execute(w, data)
	}
}
