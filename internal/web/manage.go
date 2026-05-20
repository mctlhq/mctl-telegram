package web

// manage.go implements the session management dashboard for the browser-based
// self-connect flow (/telegram/connect/manage). It lets connected users
// disconnect their session or toggle the send_enabled permission without having
// to use the MCP tools or the API directly.

import (
	"bytes"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
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

// HandleManage renders the session management dashboard.
func (s *ManageServer) HandleManage(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		http.Redirect(w, r, s.issuer+"/telegram/connect", http.StatusFound)
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
		http.Redirect(w, r, s.issuer+"/telegram/connect", http.StatusFound)
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
	http.Redirect(w, r, s.issuer+"/telegram/connect/manage", http.StatusFound)
}

// HandleToggleSend flips the send_enabled flag and redirects back.
func (s *ManageServer) HandleToggleSend(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		http.Redirect(w, r, s.issuer+"/telegram/connect", http.StatusFound)
		return
	}
	current, err := s.store.IsSendEnabled(r.Context(), id.UserID)
	if err != nil {
		slog.Warn("manage: is_send_enabled", "err", err)
		renderManageError(w, "Could not read session state. Please try again.")
		return
	}
	if err := s.store.SetSendEnabled(r.Context(), id.UserID, !current); err != nil {
		slog.Warn("manage: set_send_enabled", "err", err)
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

const manageHead = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Manage Telegram session</title>
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
    .field-row { display: flex; justify-content: space-between; padding: 8px 0;
                 border-bottom: 1px solid #d0d7de; font-size: 14px; }
    .field-row:last-of-type { border-bottom: none; }
    .field-label { color: #57606a; }
    .field-value { font-weight: 500; }
    button { margin-top: 16px; font-size: 14px; font-weight: 600; padding: 8px 14px;
             border: 1px solid rgba(27,31,36,0.15); border-radius: 6px; cursor: pointer; }
    .btn-danger { background: #cf222e; color: #ffffff; border-color: transparent; }
    .btn-danger:hover { background: #a40e26; }
    .btn-secondary { background: #f6f8fa; color: #1f2328; margin-left: 8px; }
    .btn-secondary:hover { background: #e9ebef; }
    .error { background: #ffebe9; border: 1px solid #ff818266; border-radius: 6px;
             padding: 10px 12px; font-size: 13px; color: #cf222e; margin: 12px 0; }
    @media (prefers-color-scheme: dark) {
      body { background: #0d1117; color: #e6edf3; }
      .card { background: #161b22; border-color: #30363d; box-shadow: 0 1px 3px rgba(0,0,0,0.4); }
      h1 { color: #e6edf3; }
      .meta { color: #8b949e; }
      .field-row { border-bottom-color: #30363d; }
      .field-label { color: #8b949e; }
      .btn-secondary { background: #21262d; color: #e6edf3; border-color: #30363d; }
      .btn-secondary:hover { background: #30363d; }
      .error { background: #2d1314; border-color: #6b3030; color: #f85149; }
    }
  </style>
</head>
<body>
  <div class="card">
`

const manageFoot = `  </div>
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
	const csp = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
