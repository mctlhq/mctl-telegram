package web

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/broadcast"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

func getManage(t *testing.T, srv *ManageServer, uid int64) string {
	t.Helper()
	return getManagePath(t, srv, uid, "/telegram/connect/manage")
}

func getManagePath(t *testing.T, srv *ManageServer, uid int64, path string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req = req.WithContext(auth.With(req.Context(), &auth.Identity{UserID: uid}))
	rec := httptest.NewRecorder()
	srv.HandleManage(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestManagePage_BotReachabilityBlock(t *testing.T) {
	ctx := context.Background()
	srv, store := newIsolatedManageServer(t)
	uid := seedManageUser(t, store, 5151)

	body := getManage(t, srv, uid)
	if !strings.Contains(body, "Not yet observed") || !strings.Contains(body, "We have not yet seen your login bot respond") {
		t.Errorf("unknown copy missing: %s", body)
	}
	for _, bad := range []string{"have not started", "did not start"} {
		if strings.Contains(body, bad) {
			t.Errorf("unknown copy claims %q", bad)
		}
	}
	if strings.Contains(body, "t.me/") {
		t.Error("link rendered without a configured username")
	}
	if !strings.Contains(body, "cannot deliver the categories") {
		t.Error("not-reachable note missing")
	}
	var n int
	_ = store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM client_bot_reachability`).Scan(&n)
	if n != 0 {
		t.Errorf("GET wrote %d reachability rows", n)
	}
	if err := store.RecordBotReachability(ctx, uid, notify.DeliveryOutcome{State: notify.StateBlocked, ReasonCode: "blocked", Conclusive: true}, "digest"); err != nil {
		t.Fatal(err)
	}
	if body := getManage(t, srv, uid); !strings.Contains(body, "Blocked") {
		t.Errorf("blocked label missing")
	}
	if err := store.RecordBotReachability(ctx, uid, notify.DeliveryOutcome{State: notify.StateReachable, ReasonCode: "bot_start", Conclusive: true}, "bot_start"); err != nil {
		t.Fatal(err)
	}
	body = getManage(t, srv, uid)
	if !strings.Contains(body, "Reachable") || strings.Contains(body, "cannot deliver the categories") {
		t.Errorf("reachable rendering wrong: %s", body)
	}

	srv.loginBotUsername = "mctl_demo_bot"
	if body := getManage(t, srv, uid); !strings.Contains(body, `https://t.me/mctl_demo_bot?start=onboarding`) {
		t.Errorf("start link missing")
	}
}

func TestManagePage_ReachabilityReadFailureHidesBlock(t *testing.T) {
	srv, store := newIsolatedManageServer(t)
	uid := seedManageUser(t, store, 5151)
	if _, err := store.DB.Exec(`DROP TABLE client_bot_reachability`); err != nil {
		t.Fatal(err)
	}
	body := getManage(t, srv, uid)
	if strings.Contains(body, "Login bot") {
		t.Error("block rendered despite read failure")
	}
	if !strings.Contains(body, "Notifications") {
		t.Error("page broken by reachability read failure")
	}
}

func TestManagePage_NotChosenPromptUntilSaved(t *testing.T) {
	srv, store := newIsolatedManageServer(t)
	uid := seedManageUser(t, store, 5151)
	body := getManage(t, srv, uid)
	if !strings.Contains(body, "You have not chosen yet") || !strings.Contains(body, `id="notifications"`) {
		t.Errorf("prompt or anchor missing: %s", body)
	}
	form := strings.NewReader("submitted=notifications")
	req := httptest.NewRequest(http.MethodPost, "/telegram/connect/manage/notifications", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = req.WithContext(auth.With(req.Context(), &auth.Identity{UserID: uid}))
	srv.HandleSetNotifications(httptest.NewRecorder(), req)
	if body := getManage(t, srv, uid); strings.Contains(body, "You have not chosen yet") {
		t.Error("prompt still shown after save")
	}
}

func TestLoginBotStartURL(t *testing.T) {
	if got := loginBotStartURL(""); got != "" {
		t.Errorf("got %q", got)
	}
	if got := loginBotStartURL("x_bot"); got != "https://t.me/x_bot?start=onboarding" {
		t.Errorf("got %q", got)
	}
}

func TestConnectSuccessPage_ExplicitChoiceStep(t *testing.T) {
	for _, tc := range []struct {
		user     string
		wantLink bool
	}{{"mctl_demo_bot", true}, {"", false}} {
		rec := httptest.NewRecorder()
		renderConnectSuccess(rec, connectSuccessData{
			ClaudeURL: "https://claude.test", MCPURL: "https://tg.test/mcp",
			LoginBotStartURL: loginBotStartURL(tc.user),
		})
		body := rec.Body.String()
		if !strings.Contains(body, "/telegram/connect/manage?onboarding=1#notifications") {
			t.Errorf("choice link missing")
		}
		if got := strings.Contains(body, "https://t.me/mctl_demo_bot?start=onboarding"); got != tc.wantLink {
			t.Errorf("t.me link present=%v, want %v", got, tc.wantLink)
		}
		if !tc.wantLink && !strings.Contains(body, "press Start") {
			t.Error("plain-text instructions missing")
		}
	}
}

// ?onboarding=1 is where the connect success page sends a new client: the page
// leads with the explicit category choice, and the parameter writes nothing.
func TestManagePage_OnboardingParamLeadsWithChoice(t *testing.T) {
	ctx := context.Background()
	srv, store := newIsolatedManageServer(t)
	uid := seedManageUser(t, store, 5252)

	plain := getManage(t, srv, uid)
	if strings.Contains(plain, `id="onboarding"`) {
		t.Error("onboarding callout rendered without ?onboarding=1")
	}
	body := getManagePath(t, srv, uid, "/telegram/connect/manage?onboarding=1")
	if !strings.Contains(body, `id="onboarding"`) || !strings.Contains(body, `href="#notifications"`) {
		t.Errorf("onboarding callout missing: %s", body)
	}
	if strings.Index(body, `id="onboarding"`) > strings.Index(body, `id="notifications"`) {
		t.Error("onboarding callout is not ahead of the notifications form")
	}
	var n int
	_ = store.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM client_notification_prefs`).Scan(&n)
	if n != 0 {
		t.Errorf("GET ?onboarding=1 wrote %d preference rows", n)
	}
}

// The unknown-state explanation hangs off the typed Unobserved flag, not the
// display label, so rewording the label cannot drop it.
func TestBotReachabilityView_UnobservedIsTyped(t *testing.T) {
	v := buildBotReachabilityView(nil, "")
	if !v.Unobserved || !v.NotReachable {
		t.Errorf("nil row: %+v, want Unobserved and NotReachable", v)
	}
	for _, st := range []string{notify.StateReachable, notify.StateBlocked, notify.StateCannotInitiate} {
		if v := buildBotReachabilityView(&db.BotReachability{State: st}, ""); v.Unobserved {
			t.Errorf("state %q marked Unobserved", st)
		}
	}
	var buf bytes.Buffer
	data := managePageData{Bot: &botReachabilityView{Label: "Reworded", Unobserved: true, NotReachable: true}}
	if err := manageTemplate.Execute(&buf, data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "We have not yet seen your login bot respond") {
		t.Error("unknown-state explanation depends on the label text")
	}
}

// T8: the broadcast audience respects the explicit choice. Before any save a
// product_updates campaign skips the client as unsubscribed (authentication
// is not consent); after the client saves product_updates on the manage page,
// the same evaluation includes them.
func TestBroadcastRespectsExplicitChoice(t *testing.T) {
	ctx := context.Background()
	srv, store := newIsolatedManageServer(t)
	uid := seedManageUser(t, store, 5353)
	if _, err := store.DB.ExecContext(ctx, `UPDATE users SET identity_captured_at = $1, access_tier = 'client' WHERE id = $2`, time.Now().UTC(), uid); err != nil {
		t.Fatalf("capture identity: %v", err)
	}
	sel, err := broadcast.Selector{Category: string(db.CategoryProductUpdates), Tiers: []string{broadcast.TierClient}}.Normalize()
	if err != nil {
		t.Fatalf("selector: %v", err)
	}
	evaluate := func() broadcast.Decision {
		t.Helper()
		f, err := store.GetBroadcastRecipientFacts(ctx, uid, time.Now())
		if err != nil || f == nil {
			t.Fatalf("facts: %v %v", f, err)
		}
		return broadcast.Evaluate(sel, *f, broadcast.Policy{}, time.Now())
	}

	if d := evaluate(); d.Eligible || d.Reason != broadcast.SkipUnsubscribed {
		t.Fatalf("before any save: %+v, want skipped as unsubscribed", d)
	}

	form := url.Values{"submitted": {"notifications"}, string(db.CategoryProductUpdates): {"on"}}
	post := httptest.NewRequest(http.MethodPost, "/telegram/connect/manage/notifications", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pw := httptest.NewRecorder()
	srv.HandleSetNotifications(pw, withIdentity(post, uid))
	if pw.Code != http.StatusFound {
		t.Fatalf("save: status %d: %s", pw.Code, pw.Body.String())
	}

	if d := evaluate(); !d.Eligible {
		t.Fatalf("after saving product_updates: %+v, want eligible", d)
	}
}
