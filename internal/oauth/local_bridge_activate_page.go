package oauth

// local_bridge_activate_page.go holds the HTML for the self-service Local
// Bridge activation browser flow: the user_code entry form, the consent
// page, and the denied/done/error result screens. Reuses enableHead/
// enableFoot (enable_access_page.go) so the page chrome matches the rest of
// the in-browser flows without duplicating the CSS block.

import (
	"bytes"
	"html/template"
	"net/http"
)

// activationFormPage backs the user_code entry form (GET/POST
// /local-bridge/activate). It never carries device_code or user_code as a
// URL parameter — the only way a browser binds to an activation is the user
// typing the code their own CLI printed.
type activationFormPage struct {
	CSRFToken string
	Error     string
}

// activationConsentPage backs the consent screen shown once Telegram OIDC
// has proven identity. It names the device and the signed-in Telegram
// account so the person approving can recognize both, and carries the
// user_code (so the user can cross-check it against their own terminal) and
// the consentToken (the CSRF token for Approve/Deny) as hidden fields.
type activationConsentPage struct {
	UserCode     string
	ConsentToken string
	DeviceLabel  string
	Username     string
	DisplayName  string
	Error        string
}

// activationMessagePage backs the plain denied/done/error result screens.
type activationMessagePage struct {
	Title   string
	Message string
}

var activationFormTemplate = template.Must(template.New("activationForm").Parse(enableHead + `    <h1>Activate a Local Bridge device</h1>
    <p>Enter the code your Local Bridge CLI printed to your terminal.</p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form method="POST" action="/local-bridge/activate" autocomplete="off">
      <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
      <label class="field">
        <span>Verification code</span>
        <input name="user_code" type="text" inputmode="text" autocapitalize="characters"
               placeholder="K7QP-3ZM4" required autofocus>
      </label>
      <button type="submit">Continue</button>
    </form>
    <p class="meta">This code came from a command you ran yourself. Never enter a code from a
       link someone else sent you.</p>
` + enableFoot))

var activationConsentTemplate = template.Must(template.New("activationConsent").Parse(enableHead + `    <h1>Approve this device?</h1>
    <p>You are signed in as <span class="url">{{if .Username}}@{{.Username}}{{else}}{{.DisplayName}}{{end}}</span>.
       Approving will connect the Local Bridge device below to this Telegram account.</p>
    <p class="meta">Device: <strong>{{if .DeviceLabel}}{{.DeviceLabel}}{{else}}(unnamed device){{end}}</strong> &#8212;
       verification code <span class="url">{{.UserCode}}</span> (check this matches your terminal).</p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form method="POST" action="/local-bridge/activate/consent" autocomplete="off">
      <input type="hidden" name="user_code" value="{{.UserCode}}">
      <input type="hidden" name="consent_token" value="{{.ConsentToken}}">
      <input type="hidden" name="action" value="approve">
      <button type="submit">Approve device</button>
    </form>
    <form method="POST" action="/local-bridge/activate/consent" autocomplete="off">
      <input type="hidden" name="user_code" value="{{.UserCode}}">
      <input type="hidden" name="consent_token" value="{{.ConsentToken}}">
      <input type="hidden" name="action" value="deny">
      <button type="submit">Deny</button>
    </form>
    <p class="meta">Only approve this if you just ran the activation command on the device named
       above yourself. Signing in to Telegram does not by itself register anything.</p>
` + enableFoot))

var activationMessageTemplate = template.Must(template.New("activationMessage").Parse(enableHead + `    <h1>{{.Title}}</h1>
    <div class="error">{{.Message}}</div>
    <p class="meta">You can close this tab.</p>
` + enableFoot))

var activationDoneTemplate = template.Must(template.New("activationDone").Parse(enableHead + `    <h1>&#10003; Device activated</h1>
    <p>Your Local Bridge device is now registered. You can close this tab and return to your
       terminal.</p>
` + enableFoot))

func renderActivationForm(w http.ResponseWriter, p activationFormPage) {
	renderActivationPage(w, http.StatusOK, activationFormTemplate, p)
}

func renderActivationConsent(w http.ResponseWriter, p activationConsentPage) {
	renderActivationPage(w, http.StatusOK, activationConsentTemplate, p)
}

func renderActivationDenied(w http.ResponseWriter, msg string) {
	renderActivationPage(w, http.StatusOK, activationMessageTemplate, activationMessagePage{
		Title:   "Not activated",
		Message: msg,
	})
}

func renderActivationError(w http.ResponseWriter, msg string) {
	renderActivationPage(w, http.StatusBadRequest, activationMessageTemplate, activationMessagePage{
		Title:   "Sign-in interrupted",
		Message: msg,
	})
}

func renderActivationDone(w http.ResponseWriter) {
	renderActivationPage(w, http.StatusOK, activationDoneTemplate, nil)
}

// renderActivationPage executes t into a buffer first so a template failure
// cannot leave a half-written body under an already-sent status, then writes
// the page. No inline scripts on any activation page, so the CSP forbids
// scripts outright.
func renderActivationPage(w http.ResponseWriter, status int, t *template.Template, data any) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		http.Error(w, "template execute: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src https://ui.mctl.ai; form-action 'self'; base-uri 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
