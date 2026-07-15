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

//go:embed terms.html
var termsHTML string

var (
	securityTmpl = ui.New("security", securityHTML)
	privacyTmpl  = ui.New("privacy", privacyHTML)
	termsTmpl    = ui.New("terms", termsHTML)
)

// Security serves the human-readable threat model at /security. The HTML is
// authored alongside SECURITY.md in the repo and synchronised by hand;
// rendering markdown at request time would pull in goldmark for ~one page,
// which isn't worth the binary-size cost. Anonymous-accessible — there is
// nothing user-specific here, only the deployment-wide security policy.
func Security(publicBaseURL string, showManage bool) http.HandlerFunc {
	return chromePage(securityTmpl, "security", ui.Data{
		Title:         "mctl-telegram — security model",
		Description:   "How mctl-telegram protects your Telegram session: AES-256-GCM encryption at rest, per-user keys, no message logging, and a draft-by-default send gate.",
		NavActive:     "security",
		PublicBaseURL: strings.TrimRight(publicBaseURL, "/"),
		ShowManage:    showManage,
	})
}

// Privacy serves the data-inventory and retention policy at /privacy. Same
// rationale as Security() above.
func Privacy(publicBaseURL string, showManage bool) http.HandlerFunc {
	return chromePage(privacyTmpl, "privacy", ui.Data{
		Title:         "mctl-telegram — privacy",
		Description:   "What mctl-telegram stores and for how long: only an encrypted session blob per account, no message text, and one-click disconnect or full deletion any time.",
		NavActive:     "privacy",
		PublicBaseURL: strings.TrimRight(publicBaseURL, "/"),
		ShowManage:    showManage,
	})
}

// Terms serves the terms of service at /terms. Same rationale as Security()
// above — a hand-authored static page, anonymous-accessible.
func Terms(publicBaseURL string, showManage bool) http.HandlerFunc {
	return chromePage(termsTmpl, "terms", ui.Data{
		Title:         "mctl-telegram — terms of service",
		NavActive:     "terms",
		PublicBaseURL: strings.TrimRight(publicBaseURL, "/"),
		ShowManage:    showManage,
	})
}
