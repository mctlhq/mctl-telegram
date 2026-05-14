package web

import (
	_ "embed"
	"net/http"
)

//go:embed security.html
var securityHTML []byte

//go:embed privacy.html
var privacyHTML []byte

// Security serves the human-readable threat model at /security. The HTML is
// authored alongside SECURITY.md in the repo and synchronised by hand;
// rendering markdown at request time would pull in goldmark for ~one page,
// which isn't worth the binary-size cost. Anonymous-accessible — there is
// nothing user-specific here, only the deployment-wide security policy.
func Security() http.HandlerFunc {
	return staticPage(securityHTML)
}

// Privacy serves the data-inventory and retention policy at /privacy. Same
// rationale as Security() above.
func Privacy() http.HandlerFunc {
	return staticPage(privacyHTML)
}

func staticPage(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	}
}
