package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func newManageNotifTestServer(t *testing.T) (*ManageServer, *db.Store) {
	t.Helper()
	store := newAccountTestStore(t)
	return NewManageServer(store, nil, "https://tg.mctl.ai"), store
}

// seedManageUser creates a user the manage handlers can act for.
func seedManageUser(t *testing.T, store *db.Store, tgID int64) int64 {
	t.Helper()
	uid, err := store.EnsureUserByTelegramID(context.Background(), tgID, "notifuser", "Notif User")
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return uid
}

// TestManagePage_RendersNotificationFormWithoutScript is the CSP contract this
// whole surface exists for. The manage page is served with
// `default-src 'none'` and no `script-src`, so the JSON PUT endpoint cannot be
// called from it; the controls must therefore be a plain form. If a future
// change replaces the form with fetch(), this test fails rather than the page
// silently doing nothing in a browser.
func TestManagePage_RendersNotificationFormWithoutScript(t *testing.T) {
	srv, store := newManageNotifTestServer(t)
	uid := seedManageUser(t, store, 5001)

	w := httptest.NewRecorder()
	req := withIdentity(httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil), uid)
	srv.HandleManage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()

	if !strings.Contains(body, `<form method="POST" action="/telegram/connect/manage/notifications">`) {
		t.Error("manage page does not render the notification form")
	}
	for _, c := range db.NotificationCategories() {
		if !strings.Contains(body, `name="`+string(c)+`"`) {
			t.Errorf("no checkbox for category %q", c)
		}
	}
	if strings.Contains(body, "<script") || strings.Contains(body, "fetch(") {
		t.Error("manage page introduced script; its CSP has no script-src, so it would never run")
	}

	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP = %q, want it to keep default-src 'none'", csp)
	}
	if strings.Contains(csp, "script-src") {
		t.Errorf("CSP = %q gained a script-src; the form exists so it does not need one", csp)
	}
	if !strings.Contains(csp, "form-action 'self'") {
		t.Errorf("CSP = %q lost form-action 'self', which is what refuses a cross-site POST", csp)
	}
}

// TestManageNotifications_UserChangesPreferenceAndSeesIt is the acceptance
// criterion of issue #622 end to end: a user turns product updates on through
// the HTML form and the reloaded page shows the saved state, with the
// provenance the consent model promises.
func TestManageNotifications_UserChangesPreferenceAndSeesIt(t *testing.T) {
	srv, store := newManageNotifTestServer(t)
	uid := seedManageUser(t, store, 5002)

	// Default: product updates off, and the page says the default was never
	// changed rather than claiming a decision.
	w := httptest.NewRecorder()
	srv.HandleManage(w, withIdentity(httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil), uid))
	before := w.Body.String()
	if !strings.Contains(before, "Never changed; showing the default.") {
		t.Error("page does not distinguish a default from a decision before any choice is made")
	}
	if productUpdatesChecked(before) {
		t.Error("product_updates is checked by default; marketing consent must be an affirmative act")
	}

	// Submit the form with product updates ticked. maintenance/security are
	// omitted, which is how an unchecked HTML checkbox arrives.
	form := url.Values{
		"submitted":                       {"notifications"},
		string(db.CategoryProductUpdates): {"on"},
	}
	post := httptest.NewRequest(http.MethodPost, "/telegram/connect/manage/notifications",
		strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pw := httptest.NewRecorder()
	srv.HandleSetNotifications(pw, withIdentity(post, uid))

	if pw.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 back to the dashboard; body: %s", pw.Code, pw.Body.String())
	}
	if loc := pw.Header().Get("Location"); loc != "https://tg.mctl.ai/telegram/connect/manage" {
		t.Errorf("Location = %q, want the manage dashboard", loc)
	}

	// Reload: the saved state is visible, and it is recorded as an explicit
	// decision made here.
	w2 := httptest.NewRecorder()
	srv.HandleManage(w2, withIdentity(httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil), uid))
	after := w2.Body.String()
	if !productUpdatesChecked(after) {
		t.Error("product_updates is not checked after the form saved it")
	}
	if !strings.Contains(after, "via manage_page") {
		t.Error("page does not show that the choice was made on this surface")
	}
	if strings.Contains(after, "Never changed; showing the default.") &&
		!strings.Contains(after, "Set ") {
		t.Error("page still reports a default after an explicit choice")
	}

	// And the store agrees, not only the rendering.
	prefs, err := store.ResolveNotificationPrefs(context.Background(), uid)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var found bool
	for _, p := range prefs {
		if p.Category != string(db.CategoryProductUpdates) {
			continue
		}
		found = true
		if p.State != db.PrefSubscribed {
			t.Errorf("stored state = %q, want subscribed", p.State)
		}
		if !p.Explicit {
			t.Error("stored preference is not marked explicit")
		}
		if p.Source != "manage_page" {
			t.Errorf("stored source = %q, want manage_page", p.Source)
		}
		if p.DecidedAt == nil {
			t.Error("stored preference has no decided_at timestamp")
		}
	}
	if !found {
		t.Fatal("product_updates missing from resolved preferences")
	}
}

// TestManageNotifications_UncheckedBoxUnsubscribes pins the semantics an HTML
// form forces and the JSON PUT does not: an omitted field means "the user
// cleared it", so every category is written on every submission. Getting this
// wrong would make it impossible to turn an operational category back off.
func TestManageNotifications_UncheckedBoxUnsubscribes(t *testing.T) {
	srv, store := newManageNotifTestServer(t)
	uid := seedManageUser(t, store, 5003)
	ctx := context.Background()

	// maintenance defaults to subscribed; submit an empty form to clear it.
	post := httptest.NewRequest(http.MethodPost, "/telegram/connect/manage/notifications",
		strings.NewReader(url.Values{"submitted": {"notifications"}}.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pw := httptest.NewRecorder()
	srv.HandleSetNotifications(pw, withIdentity(post, uid))
	if pw.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", pw.Code)
	}

	prefs, err := store.ResolveNotificationPrefs(ctx, uid)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, p := range prefs {
		if p.State != db.PrefUnsubscribed {
			t.Errorf("category %q = %q after an empty form, want unsubscribed", p.Category, p.State)
		}
		if !p.Explicit {
			t.Errorf("category %q is not explicit after an empty form; a cleared box is a decision", p.Category)
		}
	}
}

// TestManageNotifications_AnonymousIsRejected matches the sibling manage
// handlers: no identity, no write.
func TestManageNotifications_AnonymousIsRejected(t *testing.T) {
	srv, store := newManageNotifTestServer(t)
	uid := seedManageUser(t, store, 5004)

	post := httptest.NewRequest(http.MethodPost, "/telegram/connect/manage/notifications",
		strings.NewReader(url.Values{"submitted": {"notifications"}, string(db.CategoryProductUpdates): {"on"}}.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.HandleSetNotifications(w, post) // no identity in context

	if w.Code == http.StatusFound {
		t.Fatal("anonymous POST was accepted and redirected")
	}
	prefs, err := store.ResolveNotificationPrefs(context.Background(), uid)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	for _, p := range prefs {
		if p.Explicit {
			t.Errorf("category %q recorded an explicit decision from an anonymous request", p.Category)
		}
	}
}

// productUpdatesChecked reports whether the product_updates checkbox is
// rendered checked, without depending on attribute order elsewhere in the row.
func productUpdatesChecked(body string) bool {
	needle := `name="` + string(db.CategoryProductUpdates) + `"`
	i := strings.Index(body, needle)
	if i < 0 {
		return false
	}
	rest := body[i+len(needle):]
	end := strings.Index(rest, ">")
	if end < 0 {
		return false
	}
	return strings.Contains(rest[:end], "checked")
}

// TestManageNotifications_NonFormBodyIsRejected pins the distinction the
// sentinel exists for. ParseForm returns a nil error with an empty PostForm
// when the Content-Type is absent, text/plain or application/json, which is
// byte-for-byte the same state as "the user unticked every box". Without the
// sentinel such a request would record a deliberate unsubscribe from security
// and maintenance notices that the user never made.
func TestManageNotifications_NonFormBodyIsRejected(t *testing.T) {
	for _, ct := range []string{"", "text/plain", "application/json"} {
		name := ct
		if name == "" {
			name = "no-content-type"
		}
		t.Run(name, func(t *testing.T) {
			srv, store := newManageNotifTestServer(t)
			uid := seedManageUser(t, store, 5100+int64(len(name)))
			ctx := context.Background()

			// Start from a real decision, so a wipe would be visible.
			if err := store.SetNotificationPrefs(ctx, uid,
				map[string]string{string(db.CategorySecurity): db.PrefSubscribed},
				"test_seed"); err != nil {
				t.Fatalf("seed: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost,
				"/telegram/connect/manage/notifications", strings.NewReader(""))
			if ct != "" {
				req.Header.Set("Content-Type", ct)
			}
			w := httptest.NewRecorder()
			srv.HandleSetNotifications(w, withIdentity(req, uid))

			if w.Code == http.StatusFound {
				t.Error("a body that never parsed as a form was accepted as a cleared form")
			}

			prefs, err := store.ResolveNotificationPrefs(ctx, uid)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			for _, p := range prefs {
				if p.Category != string(db.CategorySecurity) {
					continue
				}
				if p.State != db.PrefSubscribed || p.Source != "test_seed" {
					t.Errorf("security pref = %q from %q; the seeded decision was overwritten",
						p.State, p.Source)
				}
			}
		})
	}
}

// TestManageNotifications_IsAudited: the manage page is the only consent
// surface a non-technical user can reach, and privacy.html presents
// GET /api/account/audit as the record of actions on their account. Since
// SetNotificationPrefs overwrites the row in place, an unaudited change would
// leave no trace of the earlier decision anywhere.
func TestManageNotifications_IsAudited(t *testing.T) {
	srv, store := newManageNotifTestServer(t)
	uid := seedManageUser(t, store, 5006)
	ctx := context.Background()

	form := url.Values{"submitted": {"notifications"}, string(db.CategoryProductUpdates): {"on"}}
	req := httptest.NewRequest(http.MethodPost, "/telegram/connect/manage/notifications",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.HandleSetNotifications(w, withIdentity(req, uid))
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}

	entries, err := store.ListAuditFor(ctx, uid, 20, time.Time{})
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var found bool
	for _, e := range entries {
		if e.ToolName == "POST /telegram/connect/manage/notifications" {
			found = true
			if e.Status != "ok" {
				t.Errorf("audit status = %q, want ok", e.Status)
			}
		}
	}
	if !found {
		t.Error("manage-page consent change wrote no audit row")
	}
}

// TestNotificationLabels_CoverEveryCategory is what actually stops a new
// category shipping unnamed: buildNotificationRows degrades to the bare
// identifier rather than failing, so nothing at runtime would catch it.
func TestNotificationLabels_CoverEveryCategory(t *testing.T) {
	for _, c := range db.NotificationCategories() {
		meta, ok := notificationLabels[string(c)]
		if !ok || meta.Label == "" || meta.Description == "" {
			t.Errorf("category %q has no label/description; the page would render a bare identifier", c)
		}
	}
}

// TestManagePage_PreferenceReadFailureDoesNotBlockDisconnect covers the
// degradation the design turns on: disconnect is the page's safety-critical
// control, so a preferences problem must never take it down with it.
func TestManagePage_PreferenceReadFailureDoesNotBlockDisconnect(t *testing.T) {
	srv, store := newManageNotifTestServer(t)
	uid := seedManageUser(t, store, 5007)

	// The disconnect control only renders for a connected account, so the
	// property under test is only observable with a session seeded.
	now := time.Now().UTC()
	if _, err := store.DB.ExecContext(context.Background(),
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, display_name, username, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7)`,
		uid, int64(5007), "Notif User", "notifuser", []byte("blob"), now, now.Add(24*time.Hour),
	); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	// Drop only the preferences table, not the connection: closing the handle
	// would also fail the account read that runs first, which errors the page
	// for a legitimate reason and would never reach the branch under test.
	if _, err := store.DB.Exec(`DROP TABLE client_notification_prefs`); err != nil {
		t.Fatalf("drop prefs table: %v", err)
	}

	w := httptest.NewRecorder()
	srv.HandleManage(w, withIdentity(httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil), uid))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 -- a preferences failure must not error the page", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "/telegram/connect/manage/notifications") {
		t.Error("notification form rendered despite the preference read failing")
	}
	if !strings.Contains(body, "/telegram/connect/manage/disconnect") {
		t.Error("disconnect control is missing; a preferences failure took it down")
	}
}
