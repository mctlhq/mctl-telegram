package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/acquisition"
	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
)

// signUpWithCookie drives /oauth/authorize (optionally carrying the
// acquisition cookie) and the OIDC callback for the default fake identity.
func signUpWithCookie(t *testing.T, srv *Server, mux *mockRouter, cookie *http.Cookie) {
	t.Helper()
	_, challenge := pkceVerifierAndChallenge()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"claude.ai"},
		"redirect_uri":          {"https://claude.ai/cb"},
		"state":                 {"client-state-abc"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status = %d", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	authCodeRedirect(t, callbackWithState(t, mux, loc.Query().Get("state")))
}

func acqCookie(snap acquisition.Snapshot) *http.Cookie {
	return &http.Cookie{Name: acquisition.CookieName, Value: acquisition.Encode(acquisition.DeriveKey(testJWTSecret), snap)}
}

func readAcq(t *testing.T, srv *Server, tgID int64) (state, utmSource, campaign, host, client string, n int) {
	t.Helper()
	ctx := context.Background()
	if err := srv.store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_acquisition a JOIN users u ON u.id=a.user_id WHERE u.telegram_login_id=$1`, tgID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		return
	}
	if err := srv.store.DB.QueryRowContext(ctx,
		`SELECT a.state, a.utm_source, a.utm_campaign, a.referrer_host, a.mcp_client
		   FROM user_acquisition a JOIN users u ON u.id=a.user_id WHERE u.telegram_login_id=$1`, tgID).
		Scan(&state, &utmSource, &campaign, &host, &client); err != nil {
		t.Fatal(err)
	}
	return
}

func danaIdentity(tgID int64) *telegramoidc.Identity {
	return &telegramoidc.Identity{TelegramID: tgID, Username: "dana_tg", FirstName: "Dana"}
}

func TestSignUp_RecordsAttributedAcquisition(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	const tg = 500100201
	authFake(srv).identity = danaIdentity(tg)
	snap := acquisition.Snapshot{State: acquisition.StateAttributed, UTMSource: "x", UTMCampaign: "y",
		ReferrerHost: "news.example", LandingPath: "/docs", CapturedAt: time.Now()}
	signUpWithCookie(t, srv, mux, acqCookie(snap))
	state, src, camp, host, client, n := readAcq(t, srv, tg)
	if n != 1 || state != "attributed" || src != "x" || camp != "y" || host != "news.example" || client != "claude" {
		t.Fatalf("row = %q %q %q %q %q n=%d", state, src, camp, host, client, n)
	}
}

func TestSignUp_DirectUnknownNeverCrossed(t *testing.T) {
	key := acquisition.DeriveKey(testJWTSecret)
	expired := acquisition.Snapshot{State: acquisition.StateDirect, CapturedAt: time.Now().Add(-48 * time.Hour)}
	cases := []struct {
		name   string
		tg     int64
		cookie *http.Cookie
		want   string
	}{
		{"direct", 500100211, acqCookie(acquisition.Snapshot{State: acquisition.StateDirect, CapturedAt: time.Now()}), "direct"},
		{"missing", 500100212, nil, "unknown"},
		{"tampered", 500100213, &http.Cookie{Name: acquisition.CookieName, Value: acquisition.Encode(key, acquisition.Snapshot{State: acquisition.StateDirect, CapturedAt: time.Now()}) + "x"}, "unknown"},
		{"expired", 500100214, acqCookie(expired), "unknown"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newTestServer(t)
			mux := newMockRouter()
			srv.Register(mux)
			authFake(srv).identity = danaIdentity(c.tg)
			signUpWithCookie(t, srv, mux, c.cookie)
			state, _, _, _, client, n := readAcq(t, srv, c.tg)
			if n != 1 || state != c.want || client != "claude" {
				t.Fatalf("state = %q client = %q n = %d, want %q", state, client, n, c.want)
			}
		})
	}
}

func TestSignUp_ReturningUserKeepsFirstAcquisition(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	const tg = 500100221
	authFake(srv).identity = danaIdentity(tg)
	signUpWithCookie(t, srv, mux, acqCookie(acquisition.Snapshot{State: acquisition.StateAttributed, UTMSource: "a", CapturedAt: time.Now()}))
	signUpWithCookie(t, srv, mux, acqCookie(acquisition.Snapshot{State: acquisition.StateAttributed, UTMSource: "b", CapturedAt: time.Now()}))
	if _, src, _, _, _, n := readAcq(t, srv, tg); n != 1 || src != "a" {
		t.Fatalf("src = %q n = %d, want first touch a", src, n)
	}
}
