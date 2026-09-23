package web

// broadcasts.go is the human approval surface for client broadcasts
// (issue-439): /telegram/connect/broadcasts lists prepared campaigns with
// their exact text, audience selector and preview counts, and is the ONLY
// place a campaign can be approved for delivery.
//
// Why approval is here and not an MCP tool: an assistant holding an MCP token
// could call an approve tool on the very campaign it prepared, and "a human
// approves any mass send" would be decoration. This page therefore requires
// a credential no MCP client can hold -- an access token issued to the
// built-in self-connect OAuth client, which is only ever minted by
// ExchangeConnect at the end of the browser Telegram login. The requirement
// is on the token's client_id claim (a property the issuer stamped at mint
// time), not on how the request carried it: the connect cookie holds an
// ordinary access token, and a Bearer holder could present its own token as
// that cookie, so "arrived as a cookie" would prove nothing.
//
// Every request additionally requires admin:broadcast (platform admin AND
// BROADCAST_OPERATORS) and operator membership in the service, and every POST
// a same-origin Origin header on top of the SameSite=Lax cookie. The page is
// served under the manage CSP: no script, form-action 'self'.

import (
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/broadcast"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// broadcastFormLimit caps a parsed approve/cancel body: three short fields.
const broadcastFormLimit = 8 << 10

// BroadcastServer serves the approval page. connectClient is the only OAuth
// client whose tokens may use it -- the self-connect client
// (oauth.ConnectClientID), passed in by the caller.
type BroadcastServer struct {
	store         *db.Store
	svc           *broadcast.Service
	issuer        string
	connectClient string
	now           func() time.Time
}

// NewBroadcastServer builds the approval page. connectClientID must be the
// self-connect OAuth client id.
func NewBroadcastServer(store *db.Store, svc *broadcast.Service, issuer, connectClientID string) *BroadcastServer {
	return &BroadcastServer{store: store, svc: svc, issuer: strings.TrimRight(issuer, "/"), connectClient: connectClientID, now: time.Now}
}

// authorize returns the operator actor, or writes the refusal and returns
// ok=false. Refusals are deliberately generic in the page body; the reason
// goes to the audit log.
func (b *BroadcastServer) authorize(w http.ResponseWriter, r *http.Request, action string) (broadcast.Actor, bool) {
	id := auth.From(r.Context())
	if id == nil {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return broadcast.Actor{}, false
	}
	var reason string
	switch {
	case b.svc == nil || !b.svc.Enabled():
		reason = "broadcasts not enabled"
	case b.connectClient == "" || id.ClientID != b.connectClient:
		// Covers MCP client tokens, worker/bridge/agent credentials and
		// tokens minted before the client_id claim existed.
		reason = "credential was not issued by the browser Telegram sign-in"
	case !id.HasScope("admin:broadcast") || !b.svc.IsOperator(id.TelegramID):
		reason = "not a broadcast operator"
	case r.Method == http.MethodPost && !b.sameOrigin(r):
		reason = "cross-origin or origin-less submission"
	}
	if reason != "" {
		// Refused POSTs are the boundary and are audited. A refused page
		// view is only logged: any signed-in user can load the URL, and an
		// audit row per reload would be free rows in the primary DB.
		if r.Method == http.MethodPost {
			b.store.LogToolCall(r.Context(), id.UserID, action, "", "error", reason, "")
		}
		slog.Warn("broadcast web: refused", "action", action, "user_id", id.UserID, "reason", reason)
		http.Error(w, "forbidden: this page requires a broadcast operator signed in with Telegram in a browser", http.StatusForbidden)
		return broadcast.Actor{}, false
	}
	return broadcast.Actor{UserID: id.UserID, TelegramID: id.TelegramID, Surface: "web"}, true
}

// sameOrigin requires the Origin header to name this service. Browsers send
// Origin on every form POST; a request without one did not come from this
// page.
func (b *BroadcastServer) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	want, err := url.Parse(b.issuer)
	if err != nil {
		return false
	}
	return normalizeOrigin(origin) == normalizeOrigin(want.Scheme+"://"+want.Host)
}

type broadcastRow struct {
	ID           string
	State        string
	EndReason    string
	Category     string
	Selector     string
	Text         string
	Preview      string
	ContentHash  string
	SelectorHash string
	CreatedBy    int64
	Surface      string
	CreatedAt    string
	ExpiresAt    string
	Report       *broadcast.Report
}

type broadcastPageData struct {
	Pending []broadcastRow
	Recent  []broadcastRow
	Notice  string
}

// HandleList renders pending campaigns (approvable) and recent ones.
func (b *BroadcastServer) HandleList(w http.ResponseWriter, r *http.Request) {
	if _, ok := b.authorize(w, r, "broadcast_page_web"); !ok {
		return
	}
	ctx := r.Context()
	pending, err := b.store.ListBroadcastCampaigns(ctx, 50, db.CampaignPrepared)
	if err != nil {
		slog.Warn("broadcast web: list pending", "err", err)
		renderManageError(w, "Could not load broadcasts.")
		return
	}
	recent, err := b.store.ListBroadcastCampaigns(ctx, 20,
		db.CampaignApproved, db.CampaignSending, db.CampaignCompleted, db.CampaignCancelled, db.CampaignExpired)
	if err != nil {
		slog.Warn("broadcast web: list recent", "err", err)
		renderManageError(w, "Could not load broadcasts.")
		return
	}
	// Only the two known actions produce a notice; the query string is not
	// echoed, so a crafted link cannot put arbitrary text on this page.
	data := broadcastPageData{Notice: map[string]string{
		"broadcast_approve_web": "campaign approved for delivery",
		"broadcast_cancel_web":  "campaign cancelled",
	}[r.URL.Query().Get("done")]}
	now := b.now()
	for _, c := range pending {
		if !c.ExpiresAt.After(now) {
			continue // no longer approvable; the worker moves it to expired
		}
		data.Pending = append(data.Pending, toRow(c, nil))
	}
	for _, c := range recent {
		rep, err := broadcast.BuildReport(ctx, b.store, c.ID)
		if err != nil {
			slog.Warn("broadcast web: report", "campaign_id", c.ID, "err", err)
			rep = nil
		}
		data.Recent = append(data.Recent, toRow(c, rep))
	}
	renderManage(w, http.StatusOK, broadcastTemplate, data)
}

func toRow(c db.BroadcastCampaign, rep *broadcast.Report) broadcastRow {
	return broadcastRow{
		ID: c.ID, State: c.State, EndReason: c.EndReason, Category: c.Category,
		Selector: c.SelectorJSON, Text: c.Content, Preview: c.PreviewCounts,
		ContentHash: c.ContentHash, SelectorHash: c.SelectorHash, CreatedBy: c.CreatedBy, Surface: c.Surface,
		CreatedAt: c.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"),
		ExpiresAt: c.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"),
		Report:    rep,
	}
}

// HandleApprove approves one campaign. The form carries the content and
// selector hashes the page rendered; the store refuses the transition unless
// they still match, the window is open and the campaign was never approved.
func (b *BroadcastServer) HandleApprove(w http.ResponseWriter, r *http.Request) {
	b.handleAction(w, r, "broadcast_approve_web", func(actor broadcast.Actor, form url.Values) error {
		return b.svc.Approve(r.Context(), actor, form.Get("campaign_id"), form.Get("content_hash"), form.Get("selector_hash"))
	})
}

// HandleCancel cancels one campaign that has not finished.
func (b *BroadcastServer) HandleCancel(w http.ResponseWriter, r *http.Request) {
	b.handleAction(w, r, "broadcast_cancel_web", func(actor broadcast.Actor, form url.Values) error {
		return b.svc.Cancel(r.Context(), actor, form.Get("campaign_id"))
	})
}

func (b *BroadcastServer) handleAction(w http.ResponseWriter, r *http.Request, action string, do func(broadcast.Actor, url.Values) error) {
	actor, ok := b.authorize(w, r, action)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, broadcastFormLimit)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	err := do(actor, r.PostForm)
	status, msg := "ok", ""
	if err != nil {
		status, msg = "error", err.Error()
	}
	b.store.LogToolCall(r.Context(), actor.UserID, action, "", status, msg, "")
	if err != nil {
		if !isBroadcastConflict(err) {
			// Not the operator's doing: keep internals out of the page.
			slog.Error("broadcast web: action failed", "action", action, "campaign_id", r.PostForm.Get("campaign_id"), "err", err)
			renderManageError(w, "Could not complete the action. Please try again.")
			return
		}
		slog.Info("broadcast web: action refused", "action", action, "campaign_id", r.PostForm.Get("campaign_id"), "err", err)
		renderManage(w, http.StatusConflict, broadcastErrorTemplate, manageErrorData{Message: err.Error()})
		return
	}
	slog.Info("broadcast web: action done", "action", action, "campaign_id", r.PostForm.Get("campaign_id"), "user_id", actor.UserID)
	http.Redirect(w, r, b.issuer+"/telegram/connect/broadcasts?done="+url.QueryEscape(action), http.StatusSeeOther)
}

// isBroadcastConflict reports whether err is a refusal the operator can act
// on (stale page, closed window, finished campaign). Anything else is an
// internal failure.
func isBroadcastConflict(err error) bool {
	for _, target := range []error{
		db.ErrCampaignNotFound, db.ErrCampaignExpired, db.ErrCampaignNotPrepared,
		db.ErrCampaignMismatch, db.ErrCampaignTerminal, broadcast.ErrNotBroadcastAdmin,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

const broadcastExtraCSS = `
  .bc { border-top: 1px solid var(--border); padding: 12px 0; font-size: 14px; }
  .bc pre { white-space: pre-wrap; word-break: break-word; background: var(--surface-2, #f4f4f4); padding: 10px; border-radius: 6px; }
  .bc code { font-size: 12px; word-break: break-all; }
  .bc .meta { color: var(--text-dim); font-size: 13px; }
`

var broadcastTemplate = template.Must(template.New("broadcasts").Parse(strings.Replace(manageHead, "<title>Manage Telegram session</title>", "<title>Client broadcasts</title>", 1) + `<style>` + broadcastExtraCSS + `</style>
    <h1>Client broadcasts</h1>
    {{if .Notice}}<p class="meta">Done: {{.Notice}}.</p>{{end}}
    <p class="meta">Approving releases the exact text below to the audience the server resolves <strong>at send time</strong>. Consent is re-checked for every recipient just before their message. An approval is single-use and bound to this text and selector.</p>
    <h2>Awaiting approval</h2>
    {{range .Pending}}
    <div class="bc">
      <div><strong>{{.Category}}</strong> · <code>{{.ID}}</code> · prepared by user {{.CreatedBy}} via <code>{{.Surface}}</code> at {{.CreatedAt}} · expires {{.ExpiresAt}}</div>
      <pre>{{.Text}}</pre>
      <div class="meta">Selector <code>{{.Selector}}</code></div>
      <div class="meta">Preview <code>{{.Preview}}</code></div>
      <form method="POST" action="/telegram/connect/broadcasts/approve" style="display:inline">
        <input type="hidden" name="campaign_id" value="{{.ID}}">
        <input type="hidden" name="content_hash" value="{{.ContentHash}}">
        <input type="hidden" name="selector_hash" value="{{.SelectorHash}}">
        <button type="submit" class="btn">Approve and send</button>
      </form>
      <form method="POST" action="/telegram/connect/broadcasts/cancel" style="display:inline">
        <input type="hidden" name="campaign_id" value="{{.ID}}">
        <button type="submit" class="btn-secondary">Cancel</button>
      </form>
    </div>
    {{else}}
    <p class="meta">Nothing is awaiting approval.</p>
    {{end}}
    <h2>Recent</h2>
    {{range .Recent}}
    <div class="bc">
      <div><strong>{{.State}}</strong>{{if .EndReason}} ({{.EndReason}}){{end}} · {{.Category}} · <code>{{.ID}}</code></div>
      {{with .Report}}<div class="meta">queued {{.Queued}} · delivered {{.Delivered}} · pending {{.Pending}} · transient failures {{.TransientFailure}} · outcome unknown {{.OutcomeUnknown}} · skipped {{range $k, $v := .Skipped}}{{$k}}={{$v}} {{end}} · permanent {{range $k, $v := .PermanentFailure}}{{$k}}={{$v}} {{end}}</div>{{end}}
      {{if eq .State "approved"}}<form method="POST" action="/telegram/connect/broadcasts/cancel"><input type="hidden" name="campaign_id" value="{{.ID}}"><button type="submit" class="btn-secondary">Cancel</button></form>{{end}}
      {{if eq .State "sending"}}<form method="POST" action="/telegram/connect/broadcasts/cancel"><input type="hidden" name="campaign_id" value="{{.ID}}"><button type="submit" class="btn-secondary">Stop sending</button></form>{{end}}
    </div>
    {{else}}
    <p class="meta">No recent campaigns.</p>
    {{end}}
    <p class="meta">"Delivered" means Telegram accepted the message; it is not a read receipt.</p>
` + manageFoot))

var broadcastErrorTemplate = template.Must(template.New("broadcastError").Parse(manageHead + `    <h1>Not done</h1>
    <div class="error">{{.Message}}</div>
    <p class="meta"><a href="/telegram/connect/broadcasts">Back to broadcasts</a></p>
` + manageFoot))
