package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

func getManage(t *testing.T, srv *ManageServer, uid int64) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
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
