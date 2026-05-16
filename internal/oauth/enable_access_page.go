package oauth

// enable_access_page.go holds the HTML for the in-browser enable_access flow:
// the phone, SMS-code, 2FA-password, and error screens. They mirror the visual
// style of authorize_page.go but need no JavaScript and no external resources,
// so the CSP is tighter than the widget page's.

import (
	"bytes"
	"html/template"
	"net/http"
)

type enablePhonePage struct {
	Issuer      string
	EnableToken string
	Phone       string
	SendOptIn   bool
	Error       string
}

type enableCodePage struct {
	Issuer      string
	EnableToken string
	Phone       string
	Error       string
}

type enablePasswordPage struct {
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
    }
  </style>
</head>
<body>
  <div class="card">
`

const enableFoot = `  </div>
</body>
</html>`

var enablePhoneTemplate = template.Must(template.New("enablePhone").Parse(enableHead + `    <h1>Enable message access</h1>
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
      <label class="check">
        <input type="checkbox" name="send_optin" value="on"{{if .SendOptIn}} checked{{end}}>
        <span>Also allow this connector to send messages on my behalf (you can turn this off later)</span>
      </label>
      <button type="submit">Send code</button>
    </form>
    <p class="meta">The login code is delivered inside your Telegram app. The server stores an
       encrypted session blob — never your password.</p>
` + enableFoot))

var enableCodeTemplate = template.Must(template.New("enableCode").Parse(enableHead + `    <h1>Enter your login code</h1>
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
       finish connecting. This is your Telegram <em>cloud password</em> — not the login code.</p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form method="POST" action="/oauth/telegram/enable_access/password" autocomplete="off">
      <input type="hidden" name="es" value="{{.EnableToken}}">
      <label class="field">
        <span>Two-step verification password</span>
        <input name="password" type="password" required autofocus>
      </label>
      <button type="submit">Finish</button>
    </form>
` + enableFoot))

var enableErrorTemplate = template.Must(template.New("enableError").Parse(enableHead + `    <h1>Sign-in interrupted</h1>
    <div class="error">{{.Message}}</div>
    <p class="meta">Return to your MCP client and start the connection again.</p>
` + enableFoot))

func renderEnablePhone(w http.ResponseWriter, p enablePhonePage) {
	renderEnable(w, http.StatusOK, enablePhoneTemplate, p)
}

func renderEnableCode(w http.ResponseWriter, p enableCodePage) {
	renderEnable(w, http.StatusOK, enableCodeTemplate, p)
}

func renderEnablePassword(w http.ResponseWriter, p enablePasswordPage) {
	renderEnable(w, http.StatusOK, enablePasswordTemplate, p)
}

func renderEnableError(w http.ResponseWriter, msg string) {
	renderEnable(w, http.StatusBadRequest, enableErrorTemplate, enableErrorPage{Message: msg})
}

// renderEnable executes t into a buffer first so a template failure cannot
// leave a half-written body under an already-sent 200, then writes the page
// with a no-JavaScript CSP.
func renderEnable(w http.ResponseWriter, status int, t *template.Template, data any) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		http.Error(w, "template execute: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
