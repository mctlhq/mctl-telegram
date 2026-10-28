package oauth

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// TestEnableAccess_PassesTheProvenAccountToLogin pins the wiring half of
// #899: the login must know which account OIDC proved, or it cannot log a
// different one out before enable_access refuses it.
func TestEnableAccess_PassesTheProvenAccountToLogin(t *testing.T) {
	gotWant := make(chan int64, 1)
	login := func(ctx context.Context, apiID int, apiHash string, store *db.Store,
		uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		cfgs ...telegram.LoginConfig,
	) (int64, string, string, error) {
		var want int64
		if len(cfgs) > 0 {
			want = cfgs[0].WantTelegramID
		}
		gotWant <- want
		return stubLoginWrongAccount()(ctx, apiID, apiHash, store, uid, phone, askCode, askPassword, cfgs...)
	}
	_, mux := newEnableTestServer(t, login)
	esTok := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {esTok}, "phone": {"+14155551234"}}); !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen: %s", rec.Body.String())
	}
	postForm(t, mux, "/oauth/telegram/enable_access/code", url.Values{"es": {esTok}, "code": {"12345"}})

	if want := <-gotWant; want != 500100101 {
		t.Fatalf("login got WantTelegramID = %d, want the OIDC-proven 500100101", want)
	}
}
