package web

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/productupdate"
	"github.com/mctlhq/mctl-telegram/internal/ui"
)

//go:embed productupdates.html
var productUpdatesHTML string

var productUpdatesTmpl = ui.New("productupdates", productUpdatesHTML)

// productUpdatesEntryView is the view model for one feed entry. It
// deliberately has no Provenance field (author, reviewer, assisting model):
// the template cannot render what this struct does not carry, which is what
// makes "never show provenance" hold even if the template changes later.
type productUpdatesEntryView struct {
	ID       string
	Kind     string
	Title    string
	Summary  string
	Tools    []string
	Links    []string
	DocsOnly bool
}

type productUpdatesGroupView struct {
	Release string // "" for entries citing no release (a links-only notice)
	Entries []productUpdatesEntryView
}

type productUpdatesData struct {
	ui.Data
	Groups  []productUpdatesGroupView
	LoadErr bool
}

// ProductUpdates renders the reviewed product-update feed at
// /docs/product-updates (issue-683 task 10). groups is the same
// []productupdate.ReleaseGroup RenderDocs computed from the one feed loaded
// once at server start, so docs, web and Telegram all read the same
// reviewed bytes. When loadErr is non-nil the page shows a notice and no
// entries -- never a 500, and never stale or partial content.
func ProductUpdates(groups []productupdate.ReleaseGroup, loadErr error, publicBaseURL string, showManage bool) http.HandlerFunc {
	data := productUpdatesData{
		Data: ui.Data{
			Title:         "mctl-telegram — product updates",
			Description:   "Reviewed product updates for mctl-telegram, grouped by release: new tools, changed behavior and deprecations.",
			NavActive:     "docs",
			PublicBaseURL: strings.TrimRight(publicBaseURL, "/"),
			ShowManage:    showManage,
		},
		LoadErr: loadErr != nil,
	}
	if loadErr == nil {
		for _, g := range groups {
			view := productUpdatesGroupView{Release: g.Release}
			for _, e := range g.Entries {
				view.Entries = append(view.Entries, productUpdatesEntryView{
					ID:       e.ID,
					Kind:     string(e.Kind),
					Title:    e.Title,
					Summary:  e.Summary,
					Tools:    e.Tools,
					Links:    e.Evidence.Links,
					DocsOnly: e.Delivery == productupdate.DeliveryDocsOnly,
				})
			}
			data.Groups = append(data.Groups, view)
		}
	}
	return chromePage(productUpdatesTmpl, "productupdates", data)
}
