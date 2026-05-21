package web

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/ui"
)

//go:embed docs.html
var docsHTML string

var docsTmpl = ui.New("docs", docsHTML)

// Docs renders the developer reference page at /docs. It receives the same
// three deployment-specific values as Landing() and injects them into the
// template so the displayed endpoint URLs are correct for the deployment.
func Docs(publicBaseURL, mcpPath, authServer string) http.HandlerFunc {
	base := strings.TrimRight(publicBaseURL, "/")
	mcpPath = "/" + strings.TrimLeft(mcpPath, "/")
	if authServer == "" {
		authServer = base
	}
	data := landingData{
		Data:         ui.Data{Title: "mctl-telegram — Developer reference", NavActive: "docs", PublicBaseURL: base},
		MCPURL:       base + mcpPath,
		WellKnownURL: base + "/.well-known/oauth-protected-resource",
		AuthServer:   authServer,
	}
	return chromePage(docsTmpl, "docs", data)
}
