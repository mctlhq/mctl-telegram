package oauth

// enable_access_page.go holds the HTML for the in-browser enable_access flow:
// the phone, SMS-code, 2FA-password, and error screens. They need no
// JavaScript and no external resources, so the CSP forbids scripts entirely.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"html/template"
	"net/http"
)

type enablePhonePage struct {
	Issuer      string
	EnableToken string
	Phone       string
	SendOptIn   bool
	Error       string
	WizardMode  bool
	WizardStep  int
}

type enableCodePage struct {
	Issuer      string
	EnableToken string
	Phone       string
	Error       string
	WizardMode  bool
	WizardStep  int
}

type enablePasswordPage struct {
	Issuer      string
	EnableToken string
	Error       string
	// Nonce authorizes the single inline <script> on the password screen
	// (the show/hide-password toggle). It is generated per request by
	// renderEnablePassword and echoed in the CSP script-src.
	Nonce      string
	WizardMode bool
	WizardStep int
}

type enablePermissionsPage struct {
	Issuer      string
	EnableToken string
	Error       string
}

type enableErrorPage struct {
	Message string
}

// enableHead / enableFoot wrap every screen. The CSS is the GitHub light/dark
// palette also used by the authorize page, kept inline so the page renders
// with no CDN and the CSP can forbid every external source.
const enableHead = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Enable message access</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: light dark; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
           background: #f6f8fa; color: #1f2328; margin: 0; padding: 40px 20px; }
    .card { max-width: 460px; margin: 0 auto; background: #ffffff; border: 1px solid #d0d7de;
            border-radius: 12px; padding: 32px 28px; box-shadow: 0 1px 3px rgba(27,31,36,0.04); }
    h1 { font-size: 22px; margin: 0 0 12px; font-weight: 600; }
    p { line-height: 1.5; margin: 8px 0; }
    .meta { font-size: 13px; color: #57606a; margin-top: 20px; }
    .url { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 13px; }
    .field { display: block; margin: 20px 0 8px; }
    .field span { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; }
    .field input { width: 100%; box-sizing: border-box; font-size: 15px; padding: 9px 10px;
                   border: 1px solid #d0d7de; border-radius: 6px; background: #ffffff; color: #1f2328; }
    .check { display: flex; gap: 8px; align-items: flex-start; font-size: 13px; color: #57606a; margin: 14px 0; }
    .check input { margin-top: 2px; }
    button { margin-top: 16px; width: 100%; font-size: 15px; font-weight: 600; padding: 10px 14px;
             border: 1px solid rgba(27,31,36,0.15); border-radius: 6px; background: #1f883d;
             color: #ffffff; cursor: pointer; }
    button:hover { background: #1a7f37; }
    .error { background: #ffebe9; border: 1px solid #ff818266; border-radius: 6px;
             padding: 10px 12px; font-size: 13px; color: #cf222e; margin: 12px 0; }
    .pwwrap { position: relative; }
    .pwwrap input { padding-right: 46px; }
    .pwtoggle { position: absolute; top: 1px; right: 1px; bottom: 1px; width: 42px;
                margin: 0; padding: 0; border: none; border-radius: 0 6px 6px 0;
                background: none; color: #57606a; cursor: pointer;
                display: flex; align-items: center; justify-content: center; }
    .pwtoggle:hover { background: none; color: #1f2328; }
    .steps { display: flex; list-style: none; padding: 0; margin: 0 0 20px; gap: 0; }
    .steps li { flex: 1; text-align: center; font-size: 12px; padding: 6px 4px;
                border-bottom: 2px solid #d0d7de; color: #57606a; }
    .steps li.active { border-bottom-color: #1f883d; color: #1f883d; font-weight: 600; }
    .notice { background: #ddf4ff; border: 1px solid #54aeff; border-radius: 6px;
              padding: 10px 12px; font-size: 13px; color: #0969da; margin: 12px 0; }
    .radio-group { display: flex; flex-direction: column; gap: 8px; margin: 12px 0; }
    .radio-group label { display: flex; gap: 8px; align-items: flex-start; font-size: 14px; cursor: pointer; }
    .radio-group input { margin-top: 3px; }
    @media (prefers-color-scheme: dark) {
      body { background: #0d1117; color: #e6edf3; }
      .card { background: #161b22; border-color: #30363d; box-shadow: 0 1px 3px rgba(0,0,0,0.4); }
      h1 { color: #e6edf3; }
      .meta { color: #8b949e; }
      .url { color: #58a6ff; }
      .field span { color: #e6edf3; }
      .field input { background: #0d1117; border-color: #30363d; color: #e6edf3; }
      .check { color: #8b949e; }
      .error { background: #2d1314; border-color: #6b3030; color: #f85149; }
      .pwtoggle { color: #8b949e; }
      .pwtoggle:hover { color: #e6edf3; }
      .steps li { border-bottom-color: #30363d; color: #8b949e; }
      .steps li.active { border-bottom-color: #3fb950; color: #3fb950; }
      .notice { background: #051d4d; border-color: #1f6feb; color: #79c0ff; }
    }
  </style>
</head>
<body>
  <div class="card">
`

const enableFoot = `  </div>
</body>
</html>`

var enablePhoneTemplate = template.Must(template.New("enablePhone").Parse(enableHead + `    {{if .WizardMode}}<ol class="steps">
      <li>Sign in with Telegram</li>
      <li>Permissions</li>
      <li{{if eq .WizardStep 3}} class="active"{{end}}>Phone number</li>
      <li>Done</li>
    </ol>{{end}}
    {{if .WizardMode}}<h1>Step {{.WizardStep}} of 4 &#8212; Phone number</h1>{{else}}<h1>Enable message access</h1>{{end}}
    {{if .WizardMode}}<div class="notice">A new Telegram session will appear in your account&#8217;s Active Sessions. This is normal &#8212; it is this connector.</div>{{end}}
    <p>You are connecting <span class="url">{{.Issuer}}</span> to your Telegram account. To
       read your messages, this server needs a Telegram session. Enter your phone number and
       Telegram will send you a login code.</p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form method="POST" action="/oauth/telegram/enable_access/start" autocomplete="off">
      <input type="hidden" name="es" value="{{.EnableToken}}">
      <label class="field">
        <span>Phone number (international format)</span>
        <input name="phone" type="tel" inputmode="tel" placeholder="+14155551234"
               value="{{.Phone}}" required autofocus>
      </label>
      {{if .WizardMode}}{{else}}<label class="check">
        <input type="checkbox" name="send_optin" value="on"{{if .SendOptIn}} checked{{end}}>
        <span>Also allow this connector to send messages on my behalf (you can turn this off later)</span>
      </label>{{end}}
      <button type="submit">Send code</button>
    </form>
    <p class="meta">The login code is delivered inside your Telegram app. The server stores an
       encrypted session blob — never your password.</p>
` + enableFoot))

var enableCodeTemplate = template.Must(template.New("enableCode").Parse(enableHead + `    {{if .WizardMode}}<ol class="steps">
      <li>Sign in with Telegram</li>
      <li>Permissions</li>
      <li>Phone number</li>
      <li{{if eq .WizardStep 4}} class="active"{{end}}>Done</li>
    </ol>{{end}}
    {{if .WizardMode}}<h1>Step {{.WizardStep}} of 4 &#8212; Login code</h1>{{else}}<h1>Enter your login code</h1>{{end}}
    <p>Telegram sent a login code to <span class="url">{{.Phone}}</span>. Open the Telegram app
       on another device to find it.</p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form method="POST" action="/oauth/telegram/enable_access/code" autocomplete="off">
      <input type="hidden" name="es" value="{{.EnableToken}}">
      <label class="field">
        <span>Login code</span>
        <input name="code" type="text" inputmode="numeric" autocomplete="one-time-code"
               placeholder="12345" required autofocus>
      </label>
      <button type="submit">Verify code</button>
    </form>
    <p class="meta">Wrong code? Telegram only accepts it once — start again from the phone
       screen to receive a fresh one.</p>
` + enableFoot))

var enablePasswordTemplate = template.Must(template.New("enablePassword").Parse(enableHead + `    <h1>Two-step verification</h1>
    <p>Your Telegram account is protected by a two-step verification password. Enter it to
       finish connecting. This is your <strong>Telegram cloud password</strong> — <strong>not</strong>
       the 5-digit login code you entered on the previous screen.</p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form method="POST" action="/oauth/telegram/enable_access/password" autocomplete="off">
      <input type="hidden" name="es" value="{{.EnableToken}}">
      <label class="field">
        <span>Two-step verification password</span>
        <div class="pwwrap">
          <input id="pw" name="password" type="password" required autofocus>
          <button type="button" id="pwtoggle" class="pwtoggle" aria-label="Show password">
            <svg class="eye-show" viewBox="0 0 24 24" width="20" height="20" fill="none"
                 stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/>
            </svg>
            <svg class="eye-hide" viewBox="0 0 24 24" width="20" height="20" fill="none"
                 stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" hidden>
              <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/>
              <line x1="1" y1="1" x2="23" y2="23"/>
            </svg>
          </button>
        </div>
      </label>
      <button type="submit">Finish</button>
    </form>
    <script nonce="{{.Nonce}}">
(function () {
  var input = document.getElementById('pw'),
      toggle = document.getElementById('pwtoggle'),
      show = toggle.querySelector('.eye-show'),
      hide = toggle.querySelector('.eye-hide');
  toggle.addEventListener('click', function () {
    var reveal = input.type === 'password';
    input.type = reveal ? 'text' : 'password';
    show.hidden = reveal;
    hide.hidden = !reveal;
    toggle.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
  });
})();
</script>
` + enableFoot))

var enableErrorTemplate = template.Must(template.New("enableError").Parse(enableHead + `    <h1>Sign-in interrupted</h1>
    <div class="error">{{.Message}}</div>
    <p class="meta">Return to your MCP client and start the connection again.</p>
` + enableFoot))

var enablePermissionsTemplate = template.Must(template.New("enablePermissions").Parse(enableHead + `    <ol class="steps">
      <li>Sign in with Telegram</li>
      <li class="active">Permissions</li>
      <li>Phone number</li>
      <li>Done</li>
    </ol>
    <h1>Step 2 of 4 &#8212; Permissions</h1>
    <p>Choose what this connector is allowed to do with your Telegram account.</p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form method="POST" action="/oauth/telegram/enable_access/permissions" autocomplete="off">
      <input type="hidden" name="es" value="{{.EnableToken}}">
      <div class="radio-group">
        <label>
          <input type="radio" name="send_optin" value="readonly" checked>
          Read only (recommended) &#8212; the connector can read messages but cannot send.
        </label>
        <label>
          <input type="radio" name="send_optin" value="send">
          Read + send &#8212; the connector can also send messages on your behalf.
        </label>
      </div>
      <button type="submit">Continue</button>
    </form>
    <p class="meta">You can change this permission later from the session management page.</p>
` + enableFoot))

func renderEnablePhone(w http.ResponseWriter, p enablePhonePage) {
	renderEnable(w, http.StatusOK, enablePhoneTemplate, p, "")
}

func renderEnableCode(w http.ResponseWriter, p enableCodePage) {
	renderEnable(w, http.StatusOK, enableCodeTemplate, p, "")
}

// renderEnablePassword is the only screen with an inline <script> (the
// show/hide-password toggle). It mints a fresh per-request CSP nonce, hands
// it to the template, and echoes it in the script-src so that — and only
// that — script may run.
func renderEnablePassword(w http.ResponseWriter, p enablePasswordPage) {
	nonce, err := newCSPNonce()
	if err != nil {
		http.Error(w, "csp nonce: "+err.Error(), http.StatusInternalServerError)
		return
	}
	p.Nonce = nonce
	renderEnable(w, http.StatusOK, enablePasswordTemplate, p, nonce)
}

func renderEnableError(w http.ResponseWriter, msg string) {
	renderEnable(w, http.StatusBadRequest, enableErrorTemplate, enableErrorPage{Message: msg}, "")
}

func renderEnablePermissions(w http.ResponseWriter, p enablePermissionsPage) {
	renderEnable(w, http.StatusOK, enablePermissionsTemplate, p, "")
}

// newCSPNonce returns a fresh nonce for a CSP script-src. 16 random bytes is
// well above the 128-bit unguessability the CSP spec calls for. URL-safe
// base64 (no '+' '/' '=') is used so the value survives HTML-attribute
// escaping byte-for-byte and still matches the nonce in the CSP header.
func newCSPNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// renderEnable executes t into a buffer first so a template failure cannot
// leave a half-written body under an already-sent 200, then writes the page.
// The CSP forbids scripts entirely unless nonce is non-empty, in which case
// exactly that one inline script is allowed — still no external or injected
// scripts.
func renderEnable(w http.ResponseWriter, status int, t *template.Template, data any, nonce string) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		http.Error(w, "template execute: "+err.Error(), http.StatusInternalServerError)
		return
	}
	csp := "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'"
	if nonce != "" {
		csp = "default-src 'none'; script-src 'nonce-" + nonce +
			"'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
