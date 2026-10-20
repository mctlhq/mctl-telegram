package web

// manage_notifications.go adds notification-preference controls to the
// browser-based management dashboard (/telegram/connect/manage).
//
// Why a form POST and not the JSON API: the manage page is served with
// `default-src 'none'` and no `script-src` (see renderManage), so no
// JavaScript runs on it and the GET/PUT /api/account/notifications pair it
// would otherwise call is unreachable from that page by construction. Issue
// mctlhq/mctl-telegram#622 specifies the form-POST pattern for exactly this
// reason. The API and the MCP tools stay as they are; this is the
// human-facing surface for the same store calls.
//
// Authorization and CSRF follow the existing manage handlers: the route is
// wrapped in the same auth middleware, the identity comes from
// auth.From(r.Context()) and must hold account:manage, like its MCP twin
// set_my_notification_preferences -- except that the browser sign-in token
// may turn notifications off (see HandleSetNotifications) -- and cross-site
// submission is refused by the SameSite=Lax connect-session cookie. No new token scheme is introduced,
// because a second, different one on the same page would be the more likely
// source of a mistake.
//
// The page's `form-action 'self'` is deliberately NOT counted here. It
// constrains where THIS page may submit; an attacker's page serves its own
// CSP or none, so it contributes nothing against cross-site submission.
// SameSite=Lax carries that alone -- which is why HandleSetNotifications does
// not rely on it to keep a destructive default out of reach (see the sentinel
// check there).

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// manageNotificationsFormLimit caps the parsed form body. The form carries at
// most one checkbox per category, so anything larger is not a real
// submission from this page.
const manageNotificationsFormLimit = 16 << 10 // 16 KiB

// manageNotificationsSentinel is a hidden field the form always submits. See
// HandleSetNotifications for why an empty PostForm cannot otherwise be told
// apart from a user who cleared every checkbox.
const (
	manageNotificationsSentinel      = "submitted"
	manageNotificationsSentinelValue = "notifications"
)

// HandleSetNotifications applies a notification-preference form submission
// and redirects back to the dashboard.
//
// The form submits one checkbox per category. An unchecked checkbox sends
// nothing at all, which is why every known category is written on every
// submission rather than only the ones present in the body: "absent" here
// means "the user cleared it", not "leave it alone". That is the opposite of
// the PUT endpoint's partial-update semantics, and it is what an HTML form
// can express.
func (s *ManageServer) HandleSetNotifications(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		s.WriteUnauthorized(w, r, http.StatusUnauthorized, auth.MsgAuthRequired)
		return
	}
	// account:manage may change any category. Without it, only the browser
	// sign-in token gets through, and only to turn notifications off: it is
	// issued to the owner whatever tier they resolve to, including none, and
	// withdrawing consent must not need an operator. Turning anything on
	// grants the server a permission, so that stays behind the scope.
	fullAccess := canManageAccount(id)
	if !fullAccess && !isBrowserSignIn(id, s.connectClient) {
		auditScopeDenied(r, s.store, id, manageNotificationsRoute)
		renderManage(w, http.StatusForbidden, manageErrorTemplate, manageErrorData{Message: msgManageCannotChangeNotifications})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, manageNotificationsFormLimit)
	if err := r.ParseForm(); err != nil {
		slog.Warn("manage: parse notifications form", "err", err)
		renderManageError(w, "Could not read your selection. Please try again.")
		return
	}
	// ParseForm does NOT report "this body was not a form". It returns a nil
	// error with an empty PostForm whenever the Content-Type is absent,
	// text/plain or application/json, because parsePostForm matches neither
	// case of its switch. Without this check that request is indistinguishable
	// from "the user unticked every box", and the write-every-category rule
	// below would then record a deliberate unsubscribe from maintenance and
	// security notices that the user never made.
	//
	// The sentinel is what separates the two cases. It is not a CSRF token and
	// is not relied on as one -- cross-site submission is refused by the
	// SameSite=Lax session cookie -- it exists so the handler does not depend
	// on that cookie attribute to keep a destructive default out of reach, and
	// so the semantics stated above are actually testable.
	if r.PostForm.Get(manageNotificationsSentinel) != manageNotificationsSentinelValue {
		slog.Warn("manage: notifications form missing sentinel",
			"content_type", r.Header.Get("Content-Type"))
		renderManageError(w, "Could not read your selection. Please try again.")
		return
	}

	cats := db.NotificationCategories()
	changes := make(map[string]string, len(cats))
	for _, c := range cats {
		state := db.PrefUnsubscribed
		// Presence, not value: an unvalued checkbox submits "on" today, but
		// that is a browser default, not a property of this form. Testing
		// presence keeps adding value="..." in the template from silently
		// unsubscribing every category.
		if _, ok := r.PostForm[string(c)]; ok {
			state = db.PrefSubscribed
		}
		changes[string(c)] = state
	}

	if !fullAccess {
		// The new enabled set must be a subset of the current one. A
		// submission that turns any category on is refused whole, even if it
		// also turns another off. A failed read of the current set is not an
		// empty set: nothing is written.
		current, err := s.store.ResolveNotificationPrefs(r.Context(), id.UserID)
		if err != nil {
			slog.Warn("manage: resolve notification prefs for a reduce-only change", "err", err)
			renderManageError(w, "Could not read your current notification preferences. Please try again.")
			return
		}
		if enablesAny(current, changes) {
			auditScopeDenied(r, s.store, id, manageNotificationsRoute)
			renderManage(w, http.StatusForbidden, manageErrorTemplate, manageErrorData{Message: msgManageNotificationsReduceOnly})
			return
		}
	}

	err := s.store.SetNotificationPrefs(r.Context(), id.UserID, changes, "manage_page")
	// Audited like the other two write paths (AccountHandlers.audit for
	// PUT /api/account/notifications, and the MCP set_my_notification_
	// preferences tool). Without this the one surface a non-technical user
	// can actually reach would be the only consent write absent from
	// GET /api/account/audit, which privacy.html presents to users as the
	// record of actions on their account -- and since the prefs row is
	// overwritten in place, the earlier decision would leave no trace at all.
	s.auditManage(r, id, manageNotificationsRoute, err)
	if err != nil {
		slog.Warn("manage: set notification prefs", "err", err)
		renderManageError(w, "Could not save your notification preferences. Please try again.")
		return
	}
	http.Redirect(w, r, s.issuer+"/telegram/connect/manage", http.StatusFound)
}

// manageNotificationsRoute names the notification form in audit rows.
const manageNotificationsRoute = "POST /telegram/connect/manage/notifications"

// enablesAny reports whether changes would turn on a category that current
// does not have on. A category missing from current counts as off.
func enablesAny(current []db.ResolvedPref, changes map[string]string) bool {
	on := make(map[string]bool, len(current))
	for _, p := range current {
		on[p.Category] = p.State == db.PrefSubscribed
	}
	for cat, state := range changes {
		if state == db.PrefSubscribed && !on[cat] {
			return true
		}
	}
	return false
}

// auditManage writes the tamper-evident audit row for a manage-page change
// (disconnect, send consent, notification preferences), mirroring
// AccountHandlers.audit. Like auditScopeDenied, the write is detached from
// the request's cancellation but bounded, so a client that hangs up right
// after a change that committed still leaves its row.
func (s *ManageServer) auditManage(r *http.Request, id *auth.Identity, tool string, err error) {
	status := "ok"
	msg := ""
	if err != nil {
		status = "error"
		msg = err.Error()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	s.store.LogToolCall(ctx, id.UserID, tool, "", status, msg, "", "")
}

// notificationRow is one rendered checkbox on the dashboard.
type notificationRow struct {
	Category    string
	Label       string
	Description string
	Subscribed  bool
	Operational bool
	Explicit    bool
	DecidedAt   string
	Source      string
}

// notificationLabels keeps the human-facing copy next to the category
// constants it describes. A category with no entry here degrades silently to
// its bare identifier and an empty description rather than failing, so
// TestNotificationLabels_CoverEveryCategory asserts the map stays complete;
// that test, not this map, is what stops a new category shipping unnamed.
var notificationLabels = map[string]struct{ Label, Description string }{
	string(db.CategoryProductUpdates): {
		Label:       "Product updates",
		Description: "New features and product news. Off unless you turn it on.",
	},
	string(db.CategoryMaintenance): {
		Label:       "Maintenance",
		Description: "Planned downtime and service changes that affect your account.",
	},
	string(db.CategorySecurity): {
		Label:       "Security",
		Description: "Security notices about your account.",
	},
}

// buildNotificationRows turns resolved preferences into template rows.
// DecidedAt and Source are rendered only for an explicit choice: showing a
// timestamp for a default the user never made would claim a decision that
// never happened, which is the same distinction ResolveNotificationPrefs
// draws by not writing default rows.
func buildNotificationRows(prefs []db.ResolvedPref) []notificationRow {
	rows := make([]notificationRow, 0, len(prefs))
	for _, p := range prefs {
		meta := notificationLabels[p.Category]
		label := meta.Label
		if label == "" {
			label = p.Category
		}
		row := notificationRow{
			Category:    p.Category,
			Label:       label,
			Description: meta.Description,
			Subscribed:  p.State == db.PrefSubscribed,
			Operational: p.Classification == db.ClassificationOperational,
			Explicit:    p.Explicit,
			Source:      p.Source,
		}
		if p.Explicit && p.DecidedAt != nil {
			row.DecidedAt = p.DecidedAt.Format("2006-01-02 15:04 UTC")
		}
		rows = append(rows, row)
	}
	return rows
}
