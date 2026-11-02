package web

// manage_assistant.go adds the assistant section to the management
// dashboard (/telegram/connect/manage, #1022): the caller's install and
// server-rendered forms to install a catalog version and to make the
// common changes (pause, listening, mode).
//
// Every write goes through assistantinstall.Service, the same service as
// the install_assistant and update_install MCP tools, so the page has no
// semantics of its own: an install is Apply with SelfService, a change is
// Patch, a JSON merge patch over the stored install's spec, and both are a
// compare-and-set against the install revision the page was rendered with.
//
// Authorization and CSRF are the other manage forms' (see
// manage_notifications.go): the identity must hold account:manage, exactly
// like the MCP write tools, with no browser sign-in exception, and
// cross-site submission is refused by the SameSite=Lax connect-session
// cookie.
//
// The page never shows install values, owner notes or instructions: the
// section is built from assistantinstall.Installed and Settings, which do
// not carry them, and the install form is never prefilled.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// WithAssistants wires the install service behind the assistant section.
// nil (the default, and any deployment without AGENT_ENABLED) hides the
// section and makes its routes answer 404.
func (s *ManageServer) WithAssistants(svc *assistantinstall.Service) *ManageServer {
	s.assistants = svc
	return s
}

// Audit names of the assistant forms.
const (
	manageAssistantInstallRoute = "POST /telegram/connect/manage/assistant/install"
	manageAssistantUpdateRoute  = "POST /telegram/connect/manage/assistant/update"
)

// manageAssistantFormLimit caps a parsed assistant form body.
const manageAssistantFormLimit = 32 << 10 // 32 KiB

// msgManageCannotChangeAssistant refuses a credential without
// account:manage, on the 403 page and in place of the forms.
const msgManageCannotChangeAssistant = "This connection cannot change your assistant: it needs the account:manage scope."

// assistantValueField prefixes a variable's input name in the install form.
const assistantValueField = "value."

// assistantModes are the modes the mode form offers; the install schema
// decides what is valid.
var assistantModes = []string{"observe", "guarded", "off"}

// assistantRuntimes are the runtimes the runtime form offers.
var assistantRuntimes = []string{db.RuntimeOwn, db.RuntimeManaged}

// assistantSectionView is the manage page's assistant section.
type assistantSectionView struct {
	// LoadErr: the install could not be read. The section then shows
	// neither an install nor "none installed".
	LoadErr   bool
	Installed bool
	Assistant string
	Version   string
	Revision  int64
	Settings  *assistantinstall.Settings
	CanManage bool
	// Catalog is what the install form offers; CatalogUnavailable is set
	// when it could not be read, which is not an empty catalog.
	Catalog            []assistantInstallOption
	CatalogUnavailable bool
	Modes              []string
	Runtimes           []string
	// ConsentText is the verbatim managed data flow consent text, and
	// ConsentValue the value the checkbox sends.
	ConsentText  string
	ConsentValue string
	// Notice is the outcome of the last submission. NoticeOK marks a
	// success; anything else renders as an error.
	Notice   string
	NoticeOK bool
}

type assistantInstallOption struct {
	Name, Version, Title string
	Variables            []assistantInputView
}

type assistantInputView struct {
	Field, Name, Type, Description string
	Required                       bool
	Choices                        []string
}

// assistantNotice is a submission outcome to show in the section.
type assistantNotice struct {
	msg string
	ok  bool
}

// buildAssistantSection reads the caller's install and, for a caller who
// may change it, the catalog the install form offers.
func (s *ManageServer) buildAssistantSection(r *http.Request, id *auth.Identity, notice *assistantNotice) *assistantSectionView {
	if s.assistants == nil {
		return nil
	}
	v := &assistantSectionView{CanManage: canManageAccount(id), Modes: assistantModes,
		Runtimes: assistantRuntimes, ConsentText: db.ManagedConsentText, ConsentValue: db.ManagedConsentCurrent}
	if notice != nil {
		v.Notice, v.NoticeOK = notice.msg, notice.ok
	}
	cur, err := s.assistants.Current(r.Context(), id.UserID)
	if err == nil {
		v.Settings, err = s.assistants.CurrentSettings(r.Context(), id.UserID)
	}
	if err != nil {
		slog.Warn("manage: read assistant install", "kind", assistantinstall.AuditText(err), "err", errors.Unwrap(err))
		v.LoadErr = true
		return v
	}
	v.Installed, v.Assistant, v.Version, v.Revision = cur.Installed, cur.Assistant, cur.Version, cur.InstallRevision
	if !v.CanManage {
		return v
	}
	_, entries, err := s.assistants.ListCatalog(r.Context())
	if err != nil {
		slog.Warn("manage: assistant catalog", "kind", assistantinstall.AuditText(err), "err", errors.Unwrap(err))
		v.CatalogUnavailable = true
		return v
	}
	for _, e := range entries {
		opt := assistantInstallOption{Name: e.Name, Version: e.Version, Title: e.Title}
		for _, cv := range e.Variables {
			opt.Variables = append(opt.Variables, assistantInputView{
				Field: assistantValueField + cv.Name, Name: cv.Name, Type: cv.Type,
				Description: cv.Description, Required: cv.Required, Choices: cv.Choices,
			})
		}
		v.Catalog = append(v.Catalog, opt)
	}
	return v
}

// assistantFormGate runs the checks every assistant form shares and parses
// the form. It answers the request itself and returns nil when the request
// does not get through.
func (s *ManageServer) assistantFormGate(w http.ResponseWriter, r *http.Request, route string) *auth.Identity {
	id := auth.From(r.Context())
	if id == nil {
		s.WriteUnauthorized(w, r, http.StatusUnauthorized, auth.MsgAuthRequired)
		return nil
	}
	if s.assistants == nil {
		http.NotFound(w, r)
		return nil
	}
	if !canManageAccount(id) {
		auditScopeDenied(r, s.store, id, route)
		renderManage(w, http.StatusForbidden, manageErrorTemplate, manageErrorData{Message: msgManageCannotChangeAssistant})
		return nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, manageAssistantFormLimit)
	if err := r.ParseForm(); err != nil {
		slog.Warn("manage: parse assistant form", "err", err)
		s.serveManage(w, r, id, http.StatusBadRequest, &assistantNotice{msg: "Could not read the form. Please try again."})
		return nil
	}
	return id
}

// expectedRevisionForm reads the expected_revision field: a positive
// integer, required.
func expectedRevisionForm(r *http.Request) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(r.PostForm.Get("expected_revision")), 10, 64)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

const msgAssistantFormStale = "The form did not say which install revision it was made from. Nothing was changed; the current state is shown below."

// HandleAssistantInstall installs a catalog version on the caller's
// account through assistantinstall.Service.Apply. The install starts
// paused and not listening; the form offers no way to change that.
func (s *ManageServer) HandleAssistantInstall(w http.ResponseWriter, r *http.Request) {
	id := s.assistantFormGate(w, r, manageAssistantInstallRoute)
	if id == nil {
		return
	}
	expected, ok := expectedRevisionForm(r)
	if !ok {
		s.serveManage(w, r, id, http.StatusBadRequest, &assistantNotice{msg: msgAssistantFormStale})
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	version := strings.TrimSpace(r.PostForm.Get("version"))
	if name == "" || version == "" {
		s.serveManage(w, r, id, http.StatusBadRequest, &assistantNotice{msg: "Choose an assistant version to install."})
		return
	}
	// The variable types come from the same catalog the form was built
	// from; a version it does not list is refused here as Commit would.
	_, entries, err := s.assistants.ListCatalog(r.Context())
	if err != nil {
		s.assistantFailure(w, r, id, manageAssistantInstallRoute, err)
		return
	}
	var entry *assistantinstall.CatalogEntry
	for i := range entries {
		if entries[i].Name == name && entries[i].Version == version {
			entry = &entries[i]
			break
		}
	}
	if entry == nil {
		s.assistantFailure(w, r, id, manageAssistantInstallRoute,
			&assistantinstall.Error{Kind: assistantinstall.KindNotFound, Msg: "unknown assistant " + name + "@" + version})
		return
	}
	values, msg := assistantValuesFromForm(r, entry.Variables)
	if msg != "" {
		s.serveManage(w, r, id, http.StatusUnprocessableEntity, &assistantNotice{msg: msg})
		return
	}
	// paused and listening are left out, as install_assistant leaves them
	// out when not given: the install's own defaults, paused and not
	// listening, then apply.
	spec := map[string]any{"assistant": map[string]any{"name": name, "version": version}}
	if len(values) > 0 {
		spec["values"] = values
	}
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "assistants.mctl.ai/v1alpha1",
		"kind":       "AssistantInstall",
		"spec":       spec,
	})
	if err != nil {
		s.assistantFailure(w, r, id, manageAssistantInstallRoute, err)
		return
	}
	res, err := s.assistants.Apply(r.Context(), id.UserID, raw,
		assistantinstall.CommitOptions{ExpectedRevision: &expected, SelfService: true})
	if err != nil {
		s.assistantFailure(w, r, id, manageAssistantInstallRoute, err)
		return
	}
	if res.CleanupErr != nil {
		slog.Warn("manage: deny earlier-install actions failed", "user_id", id.UserID, "err", res.CleanupErr)
	}
	s.auditManage(r, id, manageAssistantInstallRoute, nil)
	http.Redirect(w, r, s.issuer+"/telegram/connect/manage?assistant=saved#assistant", http.StatusFound)
}

// assistantValuesFromForm converts the install form's value fields by each
// variable's catalog type. An empty field is left out, so the definition's
// rules decide whether it was required. The message names the variable,
// never the value.
func assistantValuesFromForm(r *http.Request, vars []assistantinstall.CatalogVariable) (map[string]any, string) {
	values := map[string]any{}
	for _, v := range vars {
		raw := strings.TrimSpace(r.PostForm.Get(assistantValueField + v.Name))
		if raw == "" {
			continue
		}
		switch v.Type {
		case "string_list":
			var items []any
			for _, it := range strings.FieldsFunc(raw, func(c rune) bool { return c == ',' || c == '\n' || c == '\r' }) {
				if it = strings.TrimSpace(it); it != "" {
					items = append(items, it)
				}
			}
			if len(items) > 0 {
				values[v.Name] = items
			}
		case "number":
			// ParseFloat accepts NaN and Inf, which no install can carry
			// (json.Marshal refuses them).
			n, err := strconv.ParseFloat(raw, 64)
			if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
				return nil, "The value for " + v.Name + " must be a number. Nothing was changed."
			}
			values[v.Name] = n
		case "boolean":
			switch raw {
			case "true":
				values[v.Name] = true
			case "false":
				values[v.Name] = false
			default:
				return nil, "The value for " + v.Name + " must be yes or no. Nothing was changed."
			}
		default:
			values[v.Name] = raw
		}
	}
	return values, ""
}

// HandleAssistantUpdate applies one common change to the caller's install
// as a merge patch through assistantinstall.Service.Patch, at the revision
// the page showed.
func (s *ManageServer) HandleAssistantUpdate(w http.ResponseWriter, r *http.Request) {
	id := s.assistantFormGate(w, r, manageAssistantUpdateRoute)
	if id == nil {
		return
	}
	expected, ok := expectedRevisionForm(r)
	if !ok {
		s.serveManage(w, r, id, http.StatusBadRequest, &assistantNotice{msg: msgAssistantFormStale})
		return
	}
	patch, ok := assistantPatchFromForm(r.PostForm.Get("setting"), r.PostForm.Get("value"))
	if !ok {
		s.serveManage(w, r, id, http.StatusBadRequest, &assistantNotice{msg: "That change is not one this page makes. Nothing was changed."})
		return
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		s.assistantFailure(w, r, id, manageAssistantUpdateRoute, err)
		return
	}
	// The consent checkbox is a per-call assertion: it matters only when
	// the change is to managed, and is never stored.
	consent := ""
	if r.PostForm.Get("setting") == "runtime" {
		consent = strings.TrimSpace(r.PostForm.Get("consent"))
	}
	res, err := s.assistants.PatchWithConsent(r.Context(), id.UserID, raw, expected, consent)
	if err != nil {
		s.assistantFailure(w, r, id, manageAssistantUpdateRoute, err)
		return
	}
	if res.CleanupErr != nil {
		slog.Warn("manage: deny earlier-install actions failed", "user_id", id.UserID, "err", res.CleanupErr)
	}
	s.auditManage(r, id, manageAssistantUpdateRoute, nil)
	http.Redirect(w, r, s.issuer+"/telegram/connect/manage?assistant=saved#assistant", http.StatusFound)
}

// assistantPatchFromForm builds the merge patch for one of the page's
// changes: paused or listening to true or false, or mode to one of
// assistantModes. Anything else is refused.
func assistantPatchFromForm(setting, value string) (map[string]any, bool) {
	switch setting {
	case "paused", "listening":
		switch value {
		case "true":
			return map[string]any{setting: true}, true
		case "false":
			return map[string]any{setting: false}, true
		}
	case "runtime":
		for _, m := range assistantRuntimes {
			if value == m {
				return map[string]any{"runtime": value}, true
			}
		}
	case "mode":
		for _, m := range assistantModes {
			if value == m {
				return map[string]any{"mode": value}, true
			}
		}
	}
	return nil, false
}

// assistantFailure audits a failed submission by its error kind and
// re-renders the page with the current install and what went wrong.
func (s *ManageServer) assistantFailure(w http.ResponseWriter, r *http.Request, id *auth.Identity, route string, err error) {
	s.auditManage(r, id, route, errors.New(assistantinstall.AuditText(err)))
	status, msg := http.StatusInternalServerError, "Could not save your assistant. Nothing was changed; please try again."
	var ie *assistantinstall.Error
	if errors.As(err, &ie) {
		if ie.Err != nil {
			slog.Warn("manage: assistant change", "kind", assistantinstall.AuditText(err), "err", ie.Err)
		}
		switch ie.Kind {
		case assistantinstall.KindRevisionConflict:
			status = http.StatusConflict
			msg = "Your assistant install changed since this page was loaded (it is now at revision " +
				strconv.FormatInt(ie.CurrentRevision, 10) + "). Nothing was changed. The current state is shown below; review it and try again."
		case assistantinstall.KindInvalid:
			// Msg names where and which rule, never a submitted value
			// (assistantinstall.Error); Detail could, so it is not shown.
			status, msg = http.StatusUnprocessableEntity, ie.Msg+". Nothing was changed."
		case assistantinstall.KindNotFound:
			status, msg = http.StatusNotFound, ie.Msg+". Nothing was changed."
		case assistantinstall.KindLifecycle, assistantinstall.KindNoInstall:
			status, msg = http.StatusConflict, ie.Msg+". Nothing was changed."
		case assistantinstall.KindManagedConsentRequired:
			status, msg = http.StatusUnprocessableEntity, "Tick the box to agree to the managed data flow before switching. Nothing was changed."
		case assistantinstall.KindManagedDisabled:
			status, msg = http.StatusForbidden, "The managed runtime is not available. Nothing was changed."
		case assistantinstall.KindManagedQuota:
			status, msg = http.StatusConflict, "No managed capacity is available right now. Nothing was changed."
		case assistantinstall.KindUnavailable:
			status, msg = http.StatusServiceUnavailable, "The assistant catalog is unavailable right now. Nothing was changed; try again in a minute."
		case assistantinstall.KindUpstream:
			status, msg = http.StatusBadGateway, "The assistant catalog returned something this server could not use. Nothing was changed."
		}
	} else {
		slog.Warn("manage: assistant change", "err", err)
	}
	s.serveManage(w, r, id, status, &assistantNotice{msg: msg})
}

// manageAssistantSection is the assistant section of manageTemplate,
// rendered with an *assistantSectionView as dot. Every form carries the
// revision it was rendered at as expected_revision. Choices become a
// select only for a string variable: they are what assistant.checkType
// enforces, and it enforces them on strings alone, so any other type keeps
// its own input.
const manageAssistantSection = `
    <h2 class="notif-heading" id="assistant">Assistant</h2>
    {{if .Notice}}<div class="{{if .NoticeOK}}meta{{else}}error{{end}}" id="assistant-notice">{{.Notice}}</div>{{end}}
    {{if .LoadErr}}
    <p class="meta" id="assistant-unknown">We could not load your assistant install right now, so nothing is shown here. Reload the page to try again.</p>
    {{else}}
    {{if .Installed}}
    <div class="field-row"><span class="field-label">Assistant</span><span class="field-value" id="assistant-ref">{{.Assistant}}@{{.Version}}</span></div>
    <div class="field-row"><span class="field-label">Install revision</span><span class="field-value" id="assistant-revision">{{.Revision}}</span></div>
    {{with .Settings}}
    <div class="field-row"><span class="field-label">Mode</span><span class="field-value" id="assistant-mode">{{.Mode}}</span></div>
    <div class="field-row"><span class="field-label">Runtime</span><span class="field-value" id="assistant-runtime">{{if eq .Runtime "managed"}}managed (platform worker){{else}}own (your worker){{end}}</span></div>
    {{if .ManagedReconsentRequired}}<p class="error" id="assistant-reconsent">Your consent to the managed data flow is out of date. Agree again below to keep using the managed runtime.</p>{{end}}
    <div class="field-row"><span class="field-label">Paused</span><span class="field-value" id="assistant-paused">{{if .Paused}}yes{{else}}no{{end}}</span></div>
    <div class="field-row"><span class="field-label">Listening</span><span class="field-value" id="assistant-listening">{{if .Listening}}yes{{else}}no{{end}}</span></div>
    <div class="field-row"><span class="field-label">Disclosure line</span><span class="field-value">{{if .DisclosureEnabled}}on{{if .DisclosureText}}: {{.DisclosureText}}{{end}}{{else}}off{{end}}</span></div>
    <div class="field-row"><span class="field-label">Limits</span><span class="field-value">{{.MaxAutonomousTurns}} turns, {{.MaxMsgsPerMinute}}/min, {{.MaxReplyChars}} chars</span></div>
    <div class="field-row"><span class="field-label">Replies on its own</span><span class="field-value">{{if .AutoIntents}}{{range $i, $x := .AutoIntents}}{{if $i}}, {{end}}{{$x}}{{end}}{{else}}none{{end}}</span></div>
    <div class="field-row"><span class="field-label">Never</span><span class="field-value">{{if .NeverIntents}}{{range $i, $x := .NeverIntents}}{{if $i}}, {{end}}{{$x}}{{end}}{{else}}none{{end}}</span></div>
    <div class="field-row"><span class="field-label">Working hours</span><span class="field-value">{{if .WorkingHours}}{{.WorkingHours}}{{else}}always{{end}}</span></div>
    <div class="field-row"><span class="field-label">Audience excludes</span><span class="field-value">{{if .AudienceExcludes}}{{range $i, $x := .AudienceExcludes}}{{if $i}}, {{end}}{{$x}}{{end}}{{else}}none{{end}}</span></div>
    <div class="field-row"><span class="field-label">Sender lists</span><span class="field-value">{{.OnlySendersCount}} only, {{.BlockedSendersCount}} blocked</span></div>
    {{end}}
    <p class="meta">Your stored values and notes are never shown here. Change them from your MCP client with <code>update_install</code>.</p>
    {{else}}
    <p id="assistant-none">No assistant is installed on this account.</p>
    {{end}}
    {{if .CanManage}}
    {{if .Installed}}{{with .Settings}}
    <form method="POST" action="/telegram/connect/manage/assistant/update" style="display:inline">
      <input type="hidden" name="expected_revision" value="{{$.Assistant.Revision}}">
      <input type="hidden" name="setting" value="paused">
      <input type="hidden" name="value" value="{{if .Paused}}false{{else}}true{{end}}">
      <button type="submit" class="btn-secondary">{{if .Paused}}Unpause{{else}}Pause{{end}}</button>
    </form>
    <form method="POST" action="/telegram/connect/manage/assistant/update" style="display:inline">
      <input type="hidden" name="expected_revision" value="{{$.Assistant.Revision}}">
      <input type="hidden" name="setting" value="listening">
      <input type="hidden" name="value" value="{{if .Listening}}false{{else}}true{{end}}">
      <button type="submit" class="btn-secondary">{{if .Listening}}Stop listening{{else}}Start listening{{end}}</button>
    </form>
    <form method="POST" action="/telegram/connect/manage/assistant/update" class="assistant-form">
      <input type="hidden" name="expected_revision" value="{{$.Assistant.Revision}}">
      <input type="hidden" name="setting" value="mode">
      <label>Mode
        <select name="value">{{$mode := .Mode}}{{range $.Assistant.Modes}}<option value="{{.}}"{{if eq . $mode}} selected{{end}}>{{.}}</option>{{end}}</select>
      </label>
      <button type="submit" class="btn-secondary">Change mode</button>
    </form>
    <form method="POST" action="/telegram/connect/manage/assistant/update" class="assistant-form" id="assistant-runtime-form">
      <input type="hidden" name="expected_revision" value="{{$.Assistant.Revision}}">
      <input type="hidden" name="setting" value="runtime">
      <label>Runtime
        <select name="value">{{$rt := .Runtime}}{{range $.Assistant.Runtimes}}<option value="{{.}}"{{if eq . $rt}} selected{{end}}>{{.}}</option>{{end}}</select>
      </label>
      <label><input type="checkbox" name="consent" value="{{$.Assistant.ConsentValue}}"> {{$.Assistant.ConsentText}}</label>
      <button type="submit" class="btn-secondary">Change runtime</button>
    </form>
    {{end}}{{end}}
    <h3 class="notif-heading">Install an assistant</h3>
    <p class="meta">An install replaces the current one as a whole, its stored values and notes included, and starts paused and not listening.</p>
    {{if .CatalogUnavailable}}
    <p class="meta" id="assistant-catalog-unavailable">The assistant catalog could not be read right now, so no version can be installed from this page. Try again in a minute.</p>
    {{else if not .Catalog}}
    <p class="meta">No assistants are available to install.</p>
    {{else}}
    {{range .Catalog}}
    <details class="assistant-install">
      <summary>{{if .Title}}{{.Title}} {{end}}<code>{{.Name}}@{{.Version}}</code></summary>
      <form method="POST" action="/telegram/connect/manage/assistant/install" class="assistant-form" autocomplete="off">
        <input type="hidden" name="expected_revision" value="{{$.Assistant.Revision}}">
        <input type="hidden" name="name" value="{{.Name}}">
        <input type="hidden" name="version" value="{{.Version}}">
        {{range .Variables}}
        <label>{{.Name}}{{if .Required}} (required){{end}}{{if .Description}} <span class="meta">{{.Description}}</span>{{end}}
          {{if and .Choices (eq .Type "string")}}<select name="{{.Field}}"><option value=""></option>{{range .Choices}}<option value="{{.}}">{{.}}</option>{{end}}</select>
          {{else if eq .Type "boolean"}}<select name="{{.Field}}"><option value=""></option><option value="true">yes</option><option value="false">no</option></select>
          {{else if eq .Type "string_list"}}<textarea name="{{.Field}}" rows="2" placeholder="One per line or comma-separated"></textarea>
          {{else if eq .Type "number"}}<input type="number" step="any" name="{{.Field}}">
          {{else}}<input type="text" name="{{.Field}}">{{end}}
        </label>
        {{end}}
        <button type="submit" class="btn-secondary">Install {{.Name}}@{{.Version}}</button>
      </form>
    </details>
    {{end}}
    {{end}}
    {{else}}
    <p class="meta" id="assistant-unavailable">` + msgManageCannotChangeAssistant + `</p>
    {{end}}
    {{end}}
    <p class="meta"><a href="/assistants">Browse the assistant catalog</a></p>
`
