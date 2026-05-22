package web

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/ui"
)

// chromePage renders a shared-chrome template into a buffer before writing, so
// a template error cannot leave a half-written body under an already-sent 200.
func chromePage(t *template.Template, name string, data any) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		var buf bytes.Buffer
		if err := t.ExecuteTemplate(&buf, name, data); err != nil {
			http.Error(w, "template execute: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(buf.Bytes())
	}
}

//go:embed security.html
var securityHTML string

//go:embed privacy.html
var privacyHTML string

var (
	securityTmpl = ui.New("security", securityHTML)
	privacyTmpl  = ui.New("privacy", privacyHTML)
)

// Security serves the human-readable threat model at /security. The HTML is
// authored alongside SECURITY.md in the repo and synchronised by hand;
// rendering markdown at request time would pull in goldmark for ~one page,
// which isn't worth the binary-size cost. Anonymous-accessible — there is
// nothing user-specific here, only the deployment-wide security policy.
func Security(publicBaseURL string) http.HandlerFunc {
	return chromePage(securityTmpl, "security", ui.Data{
		Title:         "mctl-telegram — security model",
		NavActive:     "security",
		PublicBaseURL: strings.TrimRight(publicBaseURL, "/"),
	})
}

// Privacy serves the data-inventory and retention policy at /privacy. Same
// rationale as Security() above.
func Privacy(publicBaseURL string) http.HandlerFunc {
	return chromePage(privacyTmpl, "privacy", ui.Data{
		Title:         "mctl-telegram — privacy",
		NavActive:     "privacy",
		PublicBaseURL: strings.TrimRight(publicBaseURL, "/"),
	})
}
