package web

// manage.go implements the session management dashboard for the browser-based
// self-connect flow (/telegram/connect/manage). It lets connected users
// disconnect their session or toggle the send_enabled permission without having
// to use the MCP tools or the API directly.

import (
	"bytes"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/ui"
)

// ManagePool is the minimal interface ManageServer needs from telegram.ClientPool.
type ManagePool interface {
	RemoveAtomic(userID int64, fn func() error) error
}

// ManageServer handles the /telegram/connect/manage routes.
type ManageServer struct {
	store  *db.Store
	pool   ManagePool
	issuer string
}

// NewManageServer constructs a ManageServer.
func NewManageServer(store *db.Store, pool ManagePool, issuer string) *ManageServer {
	return &ManageServer{store: store, pool: pool, issuer: issuer}
}

// WriteUnauthorized is the browser-facing 401 for /telegram/connect/manage.
// Auth is still rejected (same status and JSON error for API clients);
// only the HTML presentation and next-step links change.
func (s *ManageServer) WriteUnauthorized(w http.ResponseWriter, r *http.Request, status int, msg string) {
	auth.AddNegotiationVary(w)
	if auth.WantsJSON(r) {
		// renderManageNeedAuth sets this on the HTML arm; the JSON arm is
		// reached directly from the handlers below, which never pass
		// through auth.writeUnauthorized.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
		return
	}
	renderManageNeedAuth(w, status, manageNeedAuthData{
		ConnectURL:             s.issuer + "/telegram/connect",
		LocalBridgeDocsURL:     s.issuer + "/docs/local-bridge",
		LocalBridgeActivateURL: s.issuer + "/local-bridge/activate",
		InvalidSession:         msg == auth.MsgInvalidCredentials,
	})
}

// HandleManage renders the session management dashboard.
func (s *ManageServer) HandleManage(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		s.WriteUnauthorized(w, r, http.StatusUnauthorized, auth.MsgAuthRequired)
		return
	}
	info, err := s.store.GetActiveAccount(r.Context(), id.UserID)
	if err != nil {
		slog.Warn("manage: get account", "err", err)
		renderManageError(w, "Could not load your session. Please try again.")
		return
	}
	renderManagePage(w, managePageData{
		Connected:   info.Connected,
		DisplayName: info.DisplayName,
		Username:    info.Username,
		ConnectedAt: info.ConnectedAt.Format("2006-01-02 15:04 UTC"),
		SendEnabled: info.SendEnabled,
		Issuer:      s.issuer,
	})
}

// HandleDisconnect revokes the user's active session and redirects back.
func (s *ManageServer) HandleDisconnect(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		s.WriteUnauthorized(w, r, http.StatusUnauthorized, auth.MsgAuthRequired)
		return
	}
	var err error
	if s.pool != nil {
		err = s.pool.RemoveAtomic(id.UserID, func() error {
			_, e := s.store.RevokeActiveSession(r.Context(), id.UserID, "disconnect")
			return e
		})
	} else {
		_, err = s.store.RevokeActiveSession(r.Context(), id.UserID, "disconnect")
	}
	if err != nil {
		slog.Warn("manage: disconnect", "err", err)
		renderManageError(w, "Disconnect failed. Please try again.")
		return
	}
	// Clear the connect-session cookie so the now-revoked DB session does not
	// remain reachable via a still-valid JWT cookie until its 1-hour expiry.
	// Path / Secure must match the Set-Cookie shape in HandleConnectDone.
	http.SetCookie(w, &http.Cookie{
		Name:     "mctl_connect_token",
		Path:     "/telegram/connect",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   strings.HasPrefix(s.issuer, "https://"),
		MaxAge:   -1,
	})
	http.Redirect(w, r, s.issuer+"/telegram/connect", http.StatusFound)
}

// HandleToggleSend flips the send_enabled flag and redirects back.
func (s *ManageServer) HandleToggleSend(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		s.WriteUnauthorized(w, r, http.StatusUnauthorized, auth.MsgAuthRequired)
		return
	}
	if _, err := s.store.ToggleSendEnabled(r.Context(), id.UserID); err != nil {
		slog.Warn("manage: toggle_send_enabled", "err", err)
		renderManageError(w, "Could not update permission. Please try again.")
		return
	}
	http.Redirect(w, r, s.issuer+"/telegram/connect/manage", http.StatusFound)
}

// ----- HTML templates -----

type managePageData struct {
	Connected   bool
	DisplayName string
	Username    string
	ConnectedAt string
	SendEnabled bool
	Issuer      string
}

const manageExtraCSS = `
  .field-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid var(--border); font-size: 14px; }
  .field-row:last-of-type { border-bottom: none; }
  .field-label { color: var(--text-dim); }
  .field-value { font-weight: 500; color: var(--text); }
  .btn-danger {
    display: inline-block; margin-top: 16px; font-family: var(--font-display), system-ui, sans-serif;
    font-size: 14px; font-weight: 600; padding: 9px 16px; border: 0; cursor: pointer;
    border-radius: var(--mctl-radius-md); background: var(--danger); color: #fff;
  }
  .btn-danger:hover { filter: brightness(.92); }
  .card .btn-secondary { margin-top: 16px; margin-left: 8px; }
`

var manageHead = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Manage Telegram session</title>
  ` + ui.FaviconLink + `
  <style>` + ui.TokensCSS + ui.ComponentsCSS + ui.AuthCSS + manageExtraCSS + `</style>
</head>
<body>
  <div class="wrap">
` + ui.TopbarLite + `
  <main class="auth-main">
    <div class="card">
`

var manageFoot = `    </div>
  </main>
` + ui.FooterLite + `
  </div>
</body>
</html>`

var manageTemplate = template.Must(template.New("manage").Parse(manageHead + `    <h1>Manage your Telegram session</h1>
    {{if .Connected}}
    <div class="field-row"><span class="field-label">Account</span><span class="field-value">{{if .DisplayName}}{{.DisplayName}}{{else}}(unknown){{end}}{{if .Username}} (@{{.Username}}){{end}}</span></div>
    <div class="field-row"><span class="field-label">Connected at</span><span class="field-value">{{.ConnectedAt}}</span></div>
    <div class="field-row"><span class="field-label">Send messages</span><span class="field-value">{{if .SendEnabled}}Enabled{{else}}Disabled{{end}}</span></div>
    <form method="POST" action="/telegram/connect/manage/toggle-send" style="display:inline">
      <button type="submit" class="btn-secondary">{{if .SendEnabled}}Disable send{{else}}Enable send{{end}}</button>
    </form>
    <form method="POST" action="/telegram/connect/manage/disconnect" style="display:inline">
      <button type="submit" class="btn-danger">Disconnect</button>
    </form>
    {{else}}
    <p>No active Telegram session found.</p>
    {{end}}
    <p class="meta"><a href="{{.Issuer}}/telegram/connect">Reconnect</a></p>
` + manageFoot))

var manageErrorTemplate = template.Must(template.New("manageError").Parse(manageHead + `    <h1>Error</h1>
    <div class="error">{{.Message}}</div>
    <p class="meta"><a href="/telegram/connect/manage">Back</a></p>
` + manageFoot))

type manageErrorData struct {
	Message string
}

type manageNeedAuthData struct {
	ConnectURL             string
	LocalBridgeDocsURL     string
	LocalBridgeActivateURL string
	InvalidSession         bool
}

var manageNeedAuthTemplate = template.Must(template.New("manageNeedAuth").Parse(manageHead + `    <h1>Sign in to manage your session</h1>
    {{if .InvalidSession}}
    <p>Your connect session is missing, expired, or invalid, so it was rejected. Sign in again to manage send permissions and disconnect.</p>
    {{else}}
    <p>You need to connect a Telegram account before you can manage this session.</p>
    {{end}}
    <a class="btn" href="{{.ConnectURL}}">Connect with Telegram</a>
    <p class="meta">Using Local Bridge? <a href="{{.LocalBridgeDocsURL}}">Setup guide</a>
       &#183; <a href="{{.LocalBridgeActivateURL}}">Activate a device</a></p>
` + manageFoot))

func renderManageNeedAuth(w http.ResponseWriter, status int, data manageNeedAuthData) {
	renderManage(w, status, manageNeedAuthTemplate, data)
}

func renderManagePage(w http.ResponseWriter, data managePageData) {
	renderManage(w, http.StatusOK, manageTemplate, data)
}

func renderManageError(w http.ResponseWriter, msg string) {
	renderManage(w, http.StatusInternalServerError, manageErrorTemplate, manageErrorData{Message: msg})
}

func renderManage(w http.ResponseWriter, status int, t *template.Template, data any) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		http.Error(w, "template execute: "+err.Error(), http.StatusInternalServerError)
		return
	}
	const csp = "default-src 'none'; style-src 'unsafe-inline'; img-src https://ui.mctl.ai; form-action 'self'; base-uri 'none'"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
