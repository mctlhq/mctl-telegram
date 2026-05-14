package oauth

import (
	"html/template"
	"net/http"
)

// authorizePage is the data model for the /oauth/authorize HTML response.
// Kept tiny: every field is plainly addressable from the template.
type authorizePage struct {
	Issuer      string // canonical service URL, displayed in the breadcrumb
	BotUsername string // @username for data-telegram-login
	ServerState string // the server-issued state token (hidden form field)
	ClientName  string // human label for the requesting client; defaults to "Claude"
}

// authorizeTemplate is the single-page Login Widget host. The Telegram-widget
// JS injects an iframe that, on confirm, calls window.onTelegramAuth(user)
// with the signed payload. We collect those fields into a hidden form and
// submit them as application/x-www-form-urlencoded to /oauth/telegram/callback.
//
// We intentionally avoid any external CSS/JS dependency beyond Telegram's own
// widget script so the page works without a CDN and CSP can stay narrow.
var authorizeTemplate = template.Must(template.New("authorize").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Connect Telegram to {{.ClientName}}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: light dark; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
           background: #f7f8fa; color: #1a1a1a; margin: 0; padding: 40px 20px; }
    @media (prefers-color-scheme: dark) {
      body { background: #11151a; color: #e6e6e6; }
      .card { background: #1a1f26; box-shadow: 0 1px 4px rgba(0,0,0,0.6); }
      .meta { color: #9aa5b1; }
      .url { color: #8bb6e8; }
    }
    .card { max-width: 460px; margin: 0 auto; background: #ffffff;
            border-radius: 12px; padding: 32px 28px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }
    h1 { font-size: 22px; margin: 0 0 12px; font-weight: 600; }
    p { line-height: 1.5; margin: 8px 0; }
    .meta { font-size: 13px; color: #5a6573; }
    .url { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 13px; }
    .widget { margin: 28px 0 8px; min-height: 50px; display: flex; justify-content: center; }
    .error { color: #c33; font-size: 13px; margin-top: 12px; min-height: 18px; }
    .footer { font-size: 12px; color: #8a95a5; margin-top: 24px; }
    .footer a { color: inherit; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Connect Telegram to {{.ClientName}}</h1>
    <p>To finish setup, log in with your Telegram account. {{.ClientName}} will be able
       to call the MCP tools on this server on your behalf.</p>
    <p class="meta">You are signing in to <span class="url">{{.Issuer}}</span>. Message access is granted by the
       Telegram session stored on this server. If your account hasn't been provisioned yet, you'll see
       a follow-up screen explaining the next step.</p>

    <div class="widget">
      <script async src="https://telegram.org/js/telegram-widget.js?22"
              data-telegram-login="{{.BotUsername}}"
              data-size="large"
              data-radius="8"
              data-onauth="onTelegramAuth(user)"
              data-request-access="write"></script>
    </div>
    <div id="err" class="error"></div>

    <form id="cb" method="POST" action="/oauth/telegram/callback" style="display:none">
      <input type="hidden" name="st" value="{{.ServerState}}">
      <input type="hidden" name="id">
      <input type="hidden" name="first_name">
      <input type="hidden" name="last_name">
      <input type="hidden" name="username">
      <input type="hidden" name="photo_url">
      <input type="hidden" name="auth_date">
      <input type="hidden" name="hash">
    </form>

    <p class="footer">
      <a href="/privacy">Privacy</a> · <a href="/security">Security</a> · <a href="/">About</a>
    </p>
  </div>

  <script>
    function onTelegramAuth(user) {
      try {
        var f = document.getElementById('cb');
        ["id","first_name","last_name","username","photo_url","auth_date","hash"].forEach(function(k){
          if (user[k] !== undefined && user[k] !== null) f.elements[k].value = user[k];
        });
        f.submit();
      } catch (e) {
        document.getElementById('err').textContent = "Telegram callback failed: " + e.message;
      }
    }
  </script>
</body>
</html>`))

// renderAuthorizeHTML writes the rendered template to w. Errors are surfaced
// as 500s only when the template engine itself fails, which would indicate a
// programming bug (every field is plain text).
func renderAuthorizeHTML(w http.ResponseWriter, page authorizePage) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Tight CSP — the only external script we load is the Telegram widget.
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self' https://telegram.org 'unsafe-inline'; "+
			"frame-src https://oauth.telegram.org; "+
			"img-src 'self' https://*.telegram.org https://*.t.me data:; "+
			"style-src 'self' 'unsafe-inline'")
	if err := authorizeTemplate.Execute(w, page); err != nil {
		http.Error(w, "template execute: "+err.Error(), http.StatusInternalServerError)
	}
}
