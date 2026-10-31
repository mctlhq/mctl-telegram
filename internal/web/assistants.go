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
	Entries []assistantView
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
				strconv.Itoa(l.MaxMsgsPerMinute) + " messages a minute, " +
				strconv.Itoa(l.MaxReplyChars) + " characters a reply"
		}
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

// Assistants renders /assistants. The catalog is read on every request,
// like list_assistants; a registry that cannot be read answers 503 with
// an explicit "catalog unavailable" notice, never an empty catalog.
func Assistants(svc *assistantinstall.Service, publicBaseURL string, showManage bool) http.HandlerFunc {
	base := ui.Data{
		Title:         "MCTL — assistants",
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
