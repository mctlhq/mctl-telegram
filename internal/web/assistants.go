package web

// assistants.go serves /assistants, the public, read-only assistant catalog
// (#1022). It lists exactly what the list_assistants MCP tool lists, from
// the same assistantinstall.Service call, so the page and the tool cannot
// disagree about what is installable. Installing happens on the manage page
// (manage_assistant.go) or through the MCP tools.

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/ui"
)

//go:embed assistants.html
var assistantsHTML string

var assistantsTmpl = ui.New("assistants", assistantsHTML)

// assistantView is one catalog entry as the page shows it. It is built
// from assistantinstall.CatalogEntry, which carries no instructions, tools,
// owner, profile paths or install values, so the template cannot render
// what this struct does not hold.
type assistantView struct {
	Name, Version, Title, Description, Lifecycle string
	Tags, Examples                               []string
	Variables                                    []assistantVariableView
	Intents                                      []assistantinstall.CatalogIntent
	Mode, DisclosurePolicy                       string
	// Limits is "" when the entry states none.
	Limits string
	// Tiers is the one-line digest of Intents by tier (tierSummary); nil
	// when the entry has no intents.
	Tiers []tierLine
}

// tierLine is one tier of the digest: the tier and its intents, joined.
type tierLine struct {
	Tier, Names string
}

// assistantGroup is one catalog name as the page shows it: a card for the
// newest version and, folded inside it, every older version the catalog
// still lists. Nothing installable leaves the page; older versions only
// stop being cards of their own (#1022, owner feedback 2026-11-01).
type assistantGroup struct {
	Latest assistantView
	Older  []assistantView
}

type assistantVariableView struct {
	Name, Type, Description string
	Required                bool
	Choices                 []string
	// Default is the registry's non-secret default, rendered; "" when none.
	// The registry leaves a secret variable's default out, and the embedded
	// catalog carries none, so nothing here can be a secret.
	Default string
}

type assistantsData struct {
	ui.Data
	// Entries is every installable version, as list_assistants lists it;
	// Groups is the same set folded by name for the cards.
	Entries []assistantView
	Groups  []assistantGroup
	// Unavailable is set when the catalog could not be read: the page then
	// says so with an error status instead of showing an empty catalog.
	Unavailable bool
	Source      string
}

func buildAssistantViews(entries []assistantinstall.CatalogEntry) []assistantView {
	out := make([]assistantView, 0, len(entries))
	for _, e := range entries {
		v := assistantView{
			Name: e.Name, Version: e.Version, Title: e.Title, Description: e.Description,
			Lifecycle: e.Lifecycle, Tags: e.Tags, Examples: e.Examples, Intents: e.Intents,
			Mode: e.Defaults.Mode, DisclosurePolicy: e.Defaults.DisclosurePolicy,
		}
		if l := e.Defaults.Limits; l != nil {
			v.Limits = strconv.Itoa(l.MaxAutonomousTurns) + " autonomous turns, " +
				groupThousands(l.MaxMsgsPerMinute) + " messages per minute, " +
				groupThousands(l.MaxReplyChars) + " characters per reply"
		}
		v.Tiers = tierSummary(e.Intents)
		for _, cv := range e.Variables {
			vv := assistantVariableView{
				Name: cv.Name, Type: cv.Type, Description: cv.Description,
				Required: cv.Required, Choices: cv.Choices,
			}
			if cv.Default != nil {
				if s, ok := cv.Default.(string); ok {
					vv.Default = s
				} else if b, err := json.Marshal(cv.Default); err == nil {
					vv.Default = string(b)
				}
			}
			v.Variables = append(v.Variables, vv)
		}
		out = append(out, v)
	}
	return out
}

// groupAssistants folds views by name, in the order the catalog lists them:
// the first view of a name is the group's newest version (sortCatalog puts
// versions in descending order), every later one is an older version. The
// output order is the input order of first appearance, so the page keeps the
// catalog's by-name ordering, and no view is dropped or reordered within a
// name.
func groupAssistants(views []assistantView) []assistantGroup {
	var out []assistantGroup
	index := map[string]int{}
	for _, v := range views {
		if i, ok := index[v.Name]; ok {
			out[i].Older = append(out[i].Older, v)
			continue
		}
		index[v.Name] = len(out)
		out = append(out, assistantGroup{Latest: v})
	}
	return out
}

// tierOrder is how tierSummary orders the known tiers: from what the
// assistant does on its own to what it is never allowed to do. A tier the
// catalog names that is not listed here follows, in order of appearance.
var tierOrder = []string{"auto", "approve", "never"}

// tierSummary digests intents into one line per tier ("auto: discovery,
// schedule", "approve: decline, share_details"); tiers with no intent are
// left out, and intents keep their catalog order within a tier. nil for no
// intents.
func tierSummary(intents []assistantinstall.CatalogIntent) []tierLine {
	byTier := map[string][]string{}
	order := append([]string(nil), tierOrder...)
	for _, in := range intents {
		if _, known := byTier[in.Tier]; !known {
			byTier[in.Tier] = nil
			if !slices.Contains(order, in.Tier) {
				order = append(order, in.Tier)
			}
		}
		byTier[in.Tier] = append(byTier[in.Tier], in.Name)
	}
	var out []tierLine
	for _, tier := range order {
		if names := byTier[tier]; len(names) > 0 {
			out = append(out, tierLine{Tier: tier, Names: strings.Join(names, ", ")})
		}
	}
	return out
}

// groupThousands renders n with a comma between thousands (1200 -> "1,200"),
// the US style the page copy uses.
func groupThousands(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// Assistants renders /assistants. The catalog is read on every request,
// like list_assistants; a registry that cannot be read answers 503 with
// an explicit "catalog unavailable" notice, never an empty catalog.
func Assistants(svc *assistantinstall.Service, publicBaseURL string, showManage bool) http.HandlerFunc {
	base := ui.Data{
		Title:         "MCTL — assistants",
		NavActive:     "assistants",
		Description:   "Assistants you can install on your Telegram account: what each one does, the values it asks for and its defaults.",
		PublicBaseURL: strings.TrimRight(publicBaseURL, "/"),
		ShowManage:    showManage,
		CanonicalPath: "/assistants",
	}
	return func(w http.ResponseWriter, r *http.Request) {
		data := assistantsData{Data: base}
		status := http.StatusOK
		source, entries, err := svc.ListCatalog(r.Context())
		if err != nil {
			var ie *assistantinstall.Error
			if errors.As(err, &ie) && ie.Err != nil {
				slog.Warn("assistants page: catalog", "kind", assistantinstall.AuditText(err), "err", ie.Err)
			} else {
				slog.Warn("assistants page: catalog", "err", err)
			}
			data.Unavailable = true
			status = http.StatusServiceUnavailable
		} else {
			data.Source = source
			data.Entries = buildAssistantViews(entries)
			data.Groups = groupAssistants(data.Entries)
		}
		var buf bytes.Buffer
		if err := assistantsTmpl.ExecuteTemplate(&buf, "assistants", data); err != nil {
			http.Error(w, "template execute: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", chromeCSP)
		if data.Unavailable {
			w.Header().Set("Retry-After", "60")
		}
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
}
