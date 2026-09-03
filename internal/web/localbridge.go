package web

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"strings"
	"sync"

	"github.com/mctlhq/mctl-telegram/internal/ui"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
)

// local-bridge.md is a generated mirror of docs/local-bridge.md, which is the
// single source. It is copied here because go:embed cannot reach outside the
// package directory, and TestLocalBridgeMarkdownMatchesDocs fails the build
// when the two drift.
//
// The page renders that markdown rather than restating it in hand-written
// HTML, because the hand-synchronised alternative has already failed in this
// repository: /security asserted that session_encrypted is NULL for local-mode
// accounts long after that stopped being true, which is the worst possible
// place for a stale copy. A setup guide that quietly disagrees with the
// repository is the same failure with a longer fuse.
//
//go:embed local-bridge.md
var localBridgeMD string

//go:embed local-bridge.html
var localBridgeHTML string

var localBridgeTmpl = ui.New("local-bridge", localBridgeHTML)

// localBridgeBody renders the markdown once, on first request rather than in
// an init, so a rendering fault surfaces as a 500 on one page instead of
// taking the whole server down at boot over a documentation page.
var localBridgeBody = sync.OnceValues(func() (template.HTML, error) {
	// No WithHardWraps: the source is hard-wrapped at ~78 columns for reading
	// in a repository, and honouring those newlines turns every paragraph into
	// a ragged column in the browser.
	md := goldmark.New(goldmark.WithExtensions(extension.GFM))
	var buf bytes.Buffer
	if err := md.Convert([]byte(localBridgeMD), &buf); err != nil {
		return "", err
	}
	// The rendered HTML comes from a file in this repository, not from user
	// input, so it is trusted markup by construction. goldmark is configured
	// without WithUnsafe, so raw HTML in the source is escaped rather than
	// passed through.
	return template.HTML(buf.String()), nil //nolint:gosec // trusted repo content
})

type localBridgeData struct {
	ui.Data
	Body template.HTML
}

// LocalBridge serves the Local Bridge setup guide at /docs/local-bridge.
// Anonymous-accessible: it is the page a prospective user reads before
// deciding whether the mode is worth the machine it needs.
func LocalBridge(publicBaseURL string, showManage bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := localBridgeBody()
		if err != nil {
			http.Error(w, "render markdown: "+err.Error(), http.StatusInternalServerError)
			return
		}
		chromePage(localBridgeTmpl, "local-bridge", localBridgeData{
			Data: ui.Data{
				Title:         "mctl-telegram — Local Bridge setup guide",
				Description:   "How to run Local Bridge: keep your Telegram session on your own machine and let tg.mctl.ai act only as a relay. Install, set up, limitations, and how to roll back.",
				NavActive:     "docs",
				PublicBaseURL: strings.TrimRight(publicBaseURL, "/"),
				ShowManage:    showManage,
			},
			Body: body,
		})(w, r)
	}
}
