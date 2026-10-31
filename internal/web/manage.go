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
	"sync/atomic"

	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/canaryguard"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
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
	// loginBotUsername is the validated login bot @username, or "".
	loginBotUsername string
	// connectClient is oauth.ConnectClientID; see canDisconnectFromManagePage.
	connectClient string
	// canary is CANARY_TELEGRAM_IDS; see WithCanaryGuard.
	canary canaryguard.Set
	// assistants is the install service behind the assistant section; see
	// WithAssistants in manage_assistant.go.
	assistants *assistantinstall.Service
}

// WithCanaryGuard sets the monitoring canary's accounts. Disconnecting one of
// them from this page takes a second confirmation that names it as the
// canary (issue #961).
func (s *ManageServer) WithCanaryGuard(ids canaryguard.Set) *ManageServer {
	s.canary = ids
	return s
}

// NewManageServer constructs a ManageServer. loginBotUsername is the validated
// TELEGRAM_LOGIN_BOT_USERNAME, or "" when unset. connectClient is the browser
// sign-in client_id (oauth.ConnectClientID) that may disconnect here without
// account:manage; it is a parameter rather than a builder step so that a
// call site cannot silently drop the owner's way out.
func NewManageServer(store *db.Store, pool ManagePool, issuer, loginBotUsername, connectClient string) *ManageServer {
	return &ManageServer{store: store, pool: pool, issuer: issuer, loginBotUsername: loginBotUsername, connectClient: connectClient}
}

// loginBotStartURL is the one place the login bot start link is built, shared
// by the connect success page and the manage page. It returns "" when the
// username is unset so callers fall back to plain-text instructions.
func loginBotStartURL(username string) string {
	if username == "" {
		return ""
	}
	return "https://t.me/" + username + "?start=onboarding"
}

// botReachabilityView is the manage page's login-bot block. The template
// branches on the typed flags, never on Label, so rewording the copy cannot
// silently drop an explanation.
type botReachabilityView struct {
	Label        string
	StartURL     string
	Username     string
	NotReachable bool
	// Unobserved is true when no reachability has ever been recorded: the
	// state is unknown, not a claim that the client never started the bot.
	Unobserved bool
}

func buildBotReachabilityView(r *db.BotReachability, username string) *botReachabilityView {
	v := &botReachabilityView{StartURL: loginBotStartURL(username), Username: username, NotReachable: true}
	state := ""
	if r != nil {
		state = r.State
	}
	switch state {
	case notify.StateReachable:
		v.Label = "Reachable"
		v.NotReachable = false
	case notify.StateBlocked:
		v.Label = "Blocked"
	case notify.StateCannotInitiate:
		v.Label = "Not started"
	default:
		v.Label = "Not yet observed"
		v.Unobserved = true
	}
	return v
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
		Assistants:             s.assistants != nil,
	})
}

// HandleManage renders the session management dashboard.
func (s *ManageServer) HandleManage(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		s.WriteUnauthorized(w, r, http.StatusUnauthorized, auth.MsgAuthRequired)
		return
	}
	var notice *assistantNotice
	if r.URL.Query().Get("assistant") == "saved" {
		notice = &assistantNotice{msg: "Your assistant install was saved.", ok: true}
	}
	s.serveManage(w, r, id, http.StatusOK, notice)
}

// serveManage renders the dashboard for id with status. notice, when set,
// is the outcome of an assistant form shown in that section; a refused
// assistant change re-renders the page through here so the owner sees the
// current install beside the reason.
func (s *ManageServer) serveManage(w http.ResponseWriter, r *http.Request, id *auth.Identity, status int, notice *assistantNotice) {
	info, err := s.store.GetActiveAccount(r.Context(), id.UserID)
	if err != nil {
		slog.Warn("manage: get account", "err", err)
		renderManageError(w, "Could not load your session. Please try again.")
		return
	}
	// Notification preferences render even when no Telegram session is
	// connected: consent is a property of the account, and a client who
	// disconnected should still be able to stop product updates without
	// reconnecting first. A read failure degrades to no section rather than
	// to an error page, because it must not block disconnect.
	//
	// The choice state is three-valued: a failed read is unknown, never
	// "chosen" and never "not chosen" -- could not observe is not observed.
	var rows []notificationRow
	choice := choiceUnknown
	if prefs, err := s.store.ResolveNotificationPrefs(r.Context(), id.UserID); err != nil {
		slog.Warn("manage: resolve notification prefs", "err", err)
	} else {
		rows = buildNotificationRows(prefs)
		choice = choiceChosen
		for _, p := range prefs {
			if p.Category == string(db.CategoryProductUpdates) && !p.Explicit {
				choice = choiceNotChosen
			}
		}
	}
	// A reachability read failure hides the block; it must not break the page
	// or the disconnect controls. Read-only: nothing is written on GET.
	var botView *botReachabilityView
	if reach, err := s.store.GetBotReachability(r.Context(), id.UserID); err != nil {
		slog.Warn("manage: get bot reachability", "err", err)
	} else {
		botView = buildBotReachabilityView(reach, s.loginBotUsername)
	}
	renderManage(w, status, manageTemplate, managePageData{
		Connected:     info.Connected,
		DisplayName:   info.DisplayName,
		Username:      info.Username,
		ConnectedAt:   info.ConnectedAt.Format("2006-01-02 15:04 UTC"),
		SendEnabled:   info.SendEnabled,
		CanDisconnect: canDisconnectFromManagePage(id, s.connectClient),
		CanManage:     canManageAccount(id),
		IsCanary:      s.canary.Contains(id.TelegramID),
		// The browser sign-in token without account:manage may only turn
		// notifications off; see HandleSetNotifications.
		NotificationsReduceOnly: !canManageAccount(id) && isBrowserSignIn(id, s.connectClient),
		Issuer:                  s.issuer,
		Notifications:           rows,
		Bot:                     botView,
		NotChosen:               choice == choiceNotChosen,
		Chosen:                  choice == choiceChosen,
		ChoiceUnknown:           choice == choiceUnknown,
		// ?onboarding=1 is where the connect success page sends a newly
		// connected client: the explicit category choice is put first. It
		// only changes presentation; consent is still written by the form.
		Onboarding: r.URL.Query().Get("onboarding") == "1",
		Assistant:  s.buildAssistantSection(r, id, notice),
	})
}

// msgManageCannotDisconnect explains a refused manage-page disconnect, both on
// the 403 page and in place of the button.
const msgManageCannotDisconnect = "This connection cannot disconnect the account. Sign in to this page with Telegram in a browser to disconnect."

// msgManageCannotChangeSend explains a refused send-consent change, both on
// the 403 page and in place of the toggle. Send consent takes no browser
// sign-in exception, and a fresh sign-in carries account:manage only for the
// admin and client tiers, so the message names the scope and nothing else.
const msgManageCannotChangeSend = "This connection cannot change send consent: it needs the account:manage scope."

// msgManageCannotChangeNotifications refuses a credential that is neither
// granted account:manage nor the browser sign-in token. The browser sign-in
// can always turn notifications off, so naming it is a remedy that works.
const msgManageCannotChangeNotifications = "This connection cannot change notification preferences. Sign in to this page with Telegram in a browser to turn notifications off."

// msgManageNotificationsReduceOnly is shown to the browser sign-in token
// without account:manage, beside the form and on the 403 page when a
// submission would turn a notification on.
const msgManageNotificationsReduceOnly = "This sign-in can turn notifications off but not on: turning one on needs the account:manage scope."

// HandleDisconnect revokes the user's active session and redirects back.
func (s *ManageServer) HandleDisconnect(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		s.WriteUnauthorized(w, r, http.StatusUnauthorized, auth.MsgAuthRequired)
		return
	}
	if !canDisconnectFromManagePage(id, s.connectClient) {
		auditScopeDenied(r, s.store, id, "POST /telegram/connect/manage/disconnect")
		renderManage(w, http.StatusForbidden, manageErrorTemplate, manageErrorData{Message: msgManageCannotDisconnect})
		return
	}
	tool := "POST /telegram/connect/manage/disconnect"
	if s.canary.Contains(id.TelegramID) {
		// The first submission only asks again; nothing is revoked until the
		// confirmation form comes back with confirm_canary set.
		if r.PostFormValue("confirm_canary") != "1" {
			renderManage(w, http.StatusOK, manageCanaryConfirmTemplate, nil)
			return
		}
		tool += canaryguard.OverrideSuffix
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
	// Audited on both outcomes, like POST /api/account/disconnect, so the
	// audit log shows the disconnect that ended the session and not only
	// the refused ones.
	s.auditManage(r, id, tool, err)
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

// HandleToggleSend flips the send_enabled flag and redirects back. It is the
// manage-page twin of set_send_consent and requires account:manage like it,
// with no browser sign-in exception: send consent is the gate a connector
// holding the send scope sends through, so a read-only credential must not
// be able to open it.
func (s *ManageServer) HandleToggleSend(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		s.WriteUnauthorized(w, r, http.StatusUnauthorized, auth.MsgAuthRequired)
		return
	}
	if !canManageAccount(id) {
		auditScopeDenied(r, s.store, id, "POST /telegram/connect/manage/toggle-send")
		renderManage(w, http.StatusForbidden, manageErrorTemplate, manageErrorData{Message: msgManageCannotChangeSend})
		return
	}
	_, err := s.store.ToggleSendEnabled(r.Context(), id.UserID)
	s.auditManage(r, id, "POST /telegram/connect/manage/toggle-send", err)
	if err != nil {
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
	// CanDisconnect and CanManage are the handlers' own checks
	// (HandleDisconnect, and HandleToggleSend / HandleSetNotifications), so
	// the page never offers a control the server would refuse.
	CanDisconnect bool
	CanManage     bool
	// IsCanary marks the monitoring canary's account (CANARY_TELEGRAM_IDS).
	IsCanary bool
	// NotificationsReduceOnly shows the notification form to a browser
	// sign-in without account:manage, with every currently-off category
	// disabled, so it submits only what HandleSetNotifications accepts.
	NotificationsReduceOnly bool
	Issuer                  string
	Notifications           []notificationRow
	Bot                     *botReachabilityView
	// Exactly one of NotChosen, Chosen and ChoiceUnknown is true.
	NotChosen     bool
	Chosen        bool
	ChoiceUnknown bool
	Onboarding    bool
	// Assistant is the assistant section; nil hides it (no install
	// service on this deployment).
	Assistant *assistantSectionView
}

// choiceState is whether the client has explicitly chosen product_updates.
type choiceState int

const (
	choiceUnknown choiceState = iota // the preference read failed
	choiceNotChosen
	choiceChosen
)

const manageExtraCSS = `
  body { min-height: 100dvh; display: flex; flex-direction: column; }
  body > .mctl-site-container { flex: 1 0 auto; width: 100%; }
  .field-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid var(--border); font-size: 14px; }
  .field-row:last-of-type { border-bottom: none; }
  .field-label { color: var(--text-dim); }
  .field-value { font-weight: 500; color: var(--text); }
  .btn-danger {
    display: inline-block; margin-top: 16px; font-family: var(--font-display), system-ui, sans-serif;
    font-size: 14px; font-weight: 600; padding: 9px 16px; border: 0; cursor: pointer;
    border-radius: var(--mctl-radius-md); background: var(--danger); color: var(--accent-fg); /* dark ink on dark, cream on light: AA either way */
  }
  .btn-danger:hover { filter: brightness(.92); }
  .card .btn-secondary { margin-top: 16px; margin-left: 8px; }
  .notif-heading { font-size: 16px; margin-top: 24px; margin-bottom: 4px; }
  .notif-row { padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 14px; }
  .notif-row:last-of-type { border-bottom: none; }
  .notif-label { display: flex; align-items: center; gap: 8px; cursor: pointer; }
  .notif-name { font-weight: 500; color: var(--text); }
  .notif-desc { color: var(--text-dim); font-size: 13px; margin-top: 2px; margin-left: 24px; }
  .assistant-form { margin-top: 12px; font-size: 14px; }
  .assistant-form label { display: block; margin-top: 10px; color: var(--text); }
  .assistant-form input, .assistant-form select, .assistant-form textarea { display: block; width: 100%; margin-top: 4px; font: inherit; }
  .assistant-install { margin-top: 12px; border-top: 1px solid var(--border); padding-top: 8px; }
  .assistant-install summary { cursor: pointer; font-weight: 500; }
`

// manageNav is the site navigation of the shared ui_topbar, without the
// theme toggle: these pages run under a CSP with no script, and the CSS-only
// menu (a checkbox and its label) needs none. The Assistants link follows
// the same rule as the shared chrome: it is shown only where /assistants is
// mounted, which is exactly when an install service is wired in.
const manageNav = `
    <input type="checkbox" id="site-nav-toggle" class="nav-toggle" aria-label="Open menu" aria-controls="site-nav">
    <label for="site-nav-toggle" class="nav-burger" title="Menu"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg></label>
    <nav class="site-nav" id="site-nav" aria-label="Main">
      <a href="/docs">Docs</a>
      <a href="/platforms">Platforms</a>
      {{if manageAssistantsMounted}}<a href="/assistants">Assistants</a>{{end}}
      <a href="/demo">Demo</a>
      <a href="/telegram/connect/manage" class="nav-manage active" aria-current="page">Manage</a>
      <a href="https://github.com/mctlhq/mctl-telegram" target="_blank" rel="noopener" aria-label="GitHub" title="GitHub" class="gh-link"><svg viewBox="0 0 16 16" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.65 7.65 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg></a>
    </nav>`

// manageTopbarClose is where the lite topbar's inner box ends; the nav goes
// just before it so it sits beside the wordmark as on every other page.
const manageTopbarClose = "\n    </div>\n  </header>"

// manageTopbar is ui.TopbarLite with manageNav added. It panics at init if
// the lite topbar no longer ends the way manageTopbarClose expects, so a
// change there cannot silently drop the navigation.
var manageTopbar = func() string {
	if strings.Count(ui.TopbarLite, manageTopbarClose) != 1 || !strings.HasSuffix(ui.TopbarLite, manageTopbarClose) {
		panic("web: ui.TopbarLite changed shape; update manageTopbar")
	}
	return strings.TrimSuffix(ui.TopbarLite, manageTopbarClose) + manageNav + manageTopbarClose
}()

// manageAssistantsMounted backs the nav's Assistants link, mirroring ui's
// assistantsMounted: set once at startup, read at render time.
var manageAssistantsMounted atomic.Bool

// SetAssistantsMounted tells the manage pages' header whether /assistants
// is served. main sets it beside ui.SetAssistantsMounted.
func SetAssistantsMounted(on bool) { manageAssistantsMounted.Store(on) }

// newManageTemplate parses one manage page with the nav's template func.
func newManageTemplate(name, body string) *template.Template {
	return template.Must(template.New(name).Funcs(template.FuncMap{
		"manageAssistantsMounted": manageAssistantsMounted.Load,
	}).Parse(body))
}

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
` + manageTopbar + `
  <div class="mctl-site-container">
  <main class="auth-main">
    <div class="card">
`

var manageFoot = `    </div>
  </main>
  </div>
` + ui.FooterLite + `
</body>
</html>`

var manageTemplate = newManageTemplate("manage", manageHead+`    <h1>Manage your Telegram session</h1>
    {{if .Onboarding}}{{if .NotChosen}}<p id="onboarding"><strong>One more step: choose your notifications.</strong> Connecting your account did not subscribe you to anything; product updates stay off until you save your choice. <a href="#notifications">Choose notifications</a></p>{{else if .Chosen}}<p id="onboarding" class="meta">Your notification choices are saved. <a href="#notifications">Review them</a></p>{{else}}<p id="onboarding" class="meta">We could not load your notification choices right now.</p>{{end}}{{end}}
    {{if .Connected}}
    <div class="field-row"><span class="field-label">Account</span><span class="field-value">{{if .DisplayName}}{{.DisplayName}}{{else}}(unknown){{end}}{{if .Username}} (@{{.Username}}){{end}}</span></div>
    <div class="field-row"><span class="field-label">Connected at</span><span class="field-value">{{.ConnectedAt}}</span></div>
    <div class="field-row"><span class="field-label">Send messages</span><span class="field-value">{{if .SendEnabled}}Enabled{{else}}Disabled{{end}}</span></div>
    {{if .CanManage}}<form method="POST" action="/telegram/connect/manage/toggle-send" style="display:inline">
      <button type="submit" class="btn-secondary">{{if .SendEnabled}}Disable send{{else}}Enable send{{end}}</button>
    </form>{{else}}<p class="meta" id="send-unavailable">`+msgManageCannotChangeSend+`</p>{{end}}
    {{if .IsCanary}}<p class="meta" id="canary-account"><strong>This is the monitoring canary account.</strong> Disconnecting it makes the canary fail until the account is re-linked.</p>{{end}}
    {{if .CanDisconnect}}<form method="POST" action="/telegram/connect/manage/disconnect" style="display:inline">
      <button type="submit" class="btn-danger">Disconnect</button>
    </form>{{else}}<p class="meta" id="disconnect-unavailable">`+msgManageCannotDisconnect+`</p>{{end}}
    {{else}}
    <p>No active Telegram session found.</p>
    {{end}}
    {{if .Bot}}
    <h2 class="notif-heading">Login bot</h2>
    <div class="field-row"><span class="field-label">Reachability</span><span class="field-value">{{.Bot.Label}}</span></div>
    {{if .Bot.Unobserved}}<p class="meta">We have not yet seen your login bot respond; start it to confirm delivery.</p>{{end}}
    {{if .Bot.NotReachable}}{{if .Bot.StartURL}}<p class="meta"><a href="{{.Bot.StartURL}}">Let the bot message you</a></p>{{else}}<p class="meta">To start the login bot, open it in Telegram and press Start.</p>{{end}}{{end}}
    {{if .Bot.NotReachable}}<p class="meta">The login bot cannot deliver the categories you enable until you start it.</p>{{end}}
    {{end}}
    {{if .Notifications}}
    <h2 class="notif-heading" id="notifications">Notifications</h2>
    {{if .NotChosen}}<p class="meta"><strong>You have not chosen yet.</strong> Product updates stay off until you save.</p>{{end}}
    <p class="meta">Choose which categories the login bot may send you. Saving records the time and that the choice was made here.</p>
    {{if .NotificationsReduceOnly}}<p class="meta" id="notifications-reduce-only">`+msgManageNotificationsReduceOnly+`</p>{{end}}
    {{if or .CanManage .NotificationsReduceOnly}}<form method="POST" action="/telegram/connect/manage/notifications">
      <input type="hidden" name="submitted" value="notifications">
      {{range .Notifications}}
      <div class="notif-row">
        <label class="notif-label">
          <input type="checkbox" name="{{.Category}}"{{if .Subscribed}} checked{{else if $.NotificationsReduceOnly}} disabled{{end}}>
          <span class="notif-name">{{.Label}}</span>
        </label>
        <div class="notif-desc">{{.Description}}
          {{- if .Operational}} Operational notice, never treated as marketing consent.{{end}}
          {{- if .Explicit}} Set {{if .DecidedAt}}{{.DecidedAt}}{{end}}{{if .Source}} via {{.Source}}{{end}}.{{else}} Never changed; showing the default.{{end}}
        </div>
      </div>
      {{end}}
      <button type="submit" class="btn-secondary">Save notification preferences</button>
    </form>{{else}}<p class="meta" id="notifications-unavailable">`+msgManageCannotChangeNotifications+`</p>{{end}}
    {{end}}
    {{with .Assistant}}`+manageAssistantSection+`{{end}}
    <p class="meta"><a href="{{.Issuer}}/telegram/connect">Reconnect</a></p>
`+manageFoot)

// manageCanaryConfirmTemplate is the second confirmation before a canary
// account is disconnected (issue #961). Cancel is a plain link back, so the
// destructive form is the only way to proceed.
var manageCanaryConfirmTemplate = newManageTemplate("manageCanaryConfirm", manageHead+`    <h1>Disconnect the monitoring canary?</h1>
    <div class="error" id="canary-confirm">This Telegram account is the monitoring canary. If you disconnect it, the canary fails and alerts until the account is re-linked.</div>
    <form method="POST" action="/telegram/connect/manage/disconnect" style="display:inline">
      <input type="hidden" name="confirm_canary" value="1">
      <button type="submit" class="btn-danger">Disconnect the canary account</button>
    </form>
    <p class="meta"><a href="/telegram/connect/manage">Cancel</a></p>
`+manageFoot)

var manageErrorTemplate = newManageTemplate("manageError", manageHead+`    <h1>Error</h1>
    <div class="error">{{.Message}}</div>
    <p class="meta"><a href="/telegram/connect/manage">Back</a></p>
`+manageFoot)

type manageErrorData struct {
	Message string
}

type manageNeedAuthData struct {
	ConnectURL             string
	LocalBridgeDocsURL     string
	LocalBridgeActivateURL string
	InvalidSession         bool
	// Assistants mentions the assistant section, which only a deployment
	// with an install service shows.
	Assistants bool
}

var manageNeedAuthTemplate = newManageTemplate("manageNeedAuth", manageHead+`    <h1>Manage your Telegram connection</h1>
    {{if .InvalidSession}}
    <p>Your connect session is missing, expired, or invalid, so it was rejected. Sign in with Telegram again to configure send permissions{{if .Assistants}}, manage assistants,{{end}} or revoke access.</p>
    {{else}}
    <p>Sign in with Telegram to configure send permissions{{if .Assistants}}, manage assistants,{{end}} or revoke access.</p>
    {{end}}
    <a class="btn" href="{{.ConnectURL}}">Connect with Telegram</a>
    <p class="meta">Using Local Bridge? <a href="{{.LocalBridgeDocsURL}}">Setup guide</a>
       &#183; <a href="{{.LocalBridgeActivateURL}}">Activate a device</a></p>
`+manageFoot)

func renderManageNeedAuth(w http.ResponseWriter, status int, data manageNeedAuthData) {
	renderManage(w, status, manageNeedAuthTemplate, data)
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
