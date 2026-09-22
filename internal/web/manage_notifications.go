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
// Authorization and CSRF follow the existing manage handlers unchanged: the
// route is wrapped in the same auth middleware, the identity comes from
// auth.From(r.Context()), and cross-site submission is refused by the
// SameSite=Lax connect-session cookie plus the page's own
// `form-action 'self'` CSP. No new token scheme is introduced, because a
// second, different one on the same page would be the more likely source of
// a mistake.

import (
	"log/slog"
	"net/http"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// manageNotificationsFormLimit caps the parsed form body. The form carries at
// most one checkbox per category, so anything larger is not a real
// submission from this page.
const manageNotificationsFormLimit = 16 << 10 // 16 KiB

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
	r.Body = http.MaxBytesReader(w, r.Body, manageNotificationsFormLimit)
	if err := r.ParseForm(); err != nil {
		slog.Warn("manage: parse notifications form", "err", err)
		renderManageError(w, "Could not read your selection. Please try again.")
		return
	}

	changes := make(map[string]string, len(db.NotificationCategories()))
	for _, c := range db.NotificationCategories() {
		state := db.PrefUnsubscribed
		if r.PostForm.Get(string(c)) == "on" {
			state = db.PrefSubscribed
		}
		changes[string(c)] = state
	}

	if err := s.store.SetNotificationPrefs(r.Context(), id.UserID, changes, "manage_page"); err != nil {
		slog.Warn("manage: set notification prefs", "err", err)
		renderManageError(w, "Could not save your notification preferences. Please try again.")
		return
	}
	http.Redirect(w, r, s.issuer+"/telegram/connect/manage", http.StatusFound)
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
// constants it describes, so a new category cannot be added to the store
// without this page failing to name it.
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
