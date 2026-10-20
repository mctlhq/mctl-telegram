package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/oauth"
	"github.com/mctlhq/mctl-telegram/internal/workertoken"
)

// These tests run the real credentials through the real middleware: a worker
// token from workertoken.Minter, a browser sign-in token from
// oauth.Server.ExchangeConnect, an access token signed the way
// oauth.Server.mintAccessToken signs one, and localjwt.Provider verifying
// all of them. A hand-built auth.Identity would prove the check, not that the
// credentials the server actually issues land on the right side of it.

const (
	accountManageSecret = "account-manage-test-secret-32-bytes!"
	accountManageIssuer = "https://tg.test"
)

type accountManageFixture struct {
	store      *db.Store
	uid        int64
	tgID       int64
	api        http.Handler
	manage     http.Handler
	managePage http.Handler
	toggleSend http.Handler
	setNotifs  http.Handler
	minter     *workertoken.Minter
	signer     *localjwt.Issuer
	oauthSrv   *oauth.Server
	oauthMux   http.Handler
	t          *testing.T
}

func newAccountManageFixture(t *testing.T, tgID int64) *accountManageFixture {
	t.Helper()
	ctx := context.Background()
	store := newManageTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, tgID, "dana_tg", "")
	if err != nil {
		t.Fatalf("EnsureUserByTelegramID: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, display_name, username, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7)`,
		uid, tgID, "Dana", "dana_tg", []byte("blob"), now, now.Add(time.Hour),
	); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	provider, err := localjwt.NewProvider(store, localjwt.ProviderConfig{
		Secret: []byte(accountManageSecret), ExpectedIssuer: accountManageIssuer,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	minter, err := workertoken.NewMinter([]byte(accountManageSecret), accountManageIssuer, "")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	signer, err := localjwt.NewIssuer([]byte(accountManageSecret), accountManageIssuer)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	oauthSrv, err := oauth.New(ctx, oauth.Config{
		Issuer:            accountManageIssuer,
		JWTSecret:         []byte(accountManageSecret),
		TelegramOIDC:      stubOIDC{tgID: tgID},
		ClientTelegramIDs: map[int64]bool{tgID: true},
		AccessTokenTTL:    time.Hour,
		CodeTTL:           time.Minute,
	}, store)
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}
	oauthRouter := chi.NewRouter()
	oauthSrv.Register(oauthRouter)
	rm := auth.ResourceMetadata{BaseURL: accountManageIssuer}

	// Wired exactly as cmd/server/main.go wires them.
	router := chi.NewRouter()
	NewAccountHandlers(store, nil).Register(router)
	manageSrv := NewManageServer(store, nil, accountManageIssuer, "", oauth.ConnectClientID)
	withAuth := auth.MiddlewareWithHTML(provider, true, nil, rm, manageSrv.WriteUnauthorized)

	return &accountManageFixture{
		store:      store,
		uid:        uid,
		tgID:       tgID,
		api:        auth.Middleware(provider, true, nil, rm)(router),
		manage:     withAuth(http.HandlerFunc(manageSrv.HandleDisconnect)),
		managePage: withAuth(http.HandlerFunc(manageSrv.HandleManage)),
		toggleSend: withAuth(http.HandlerFunc(manageSrv.HandleToggleSend)),
		setNotifs:  withAuth(http.HandlerFunc(manageSrv.HandleSetNotifications)),
		minter:     minter,
		signer:     signer,
		oauthSrv:   oauthSrv,
		oauthMux:   oauthRouter,
		t:          t,
	}
}

// stubOIDC stands in for Telegram's OIDC leg: it reports the fixture's
// account as the one that signed in. Everything after it -- the authorization
// code, scope resolution and the token itself -- is the real oauth.Server.
type stubOIDC struct{ tgID int64 }

func (o stubOIDC) AuthCodeURL(state, _, _ string) string {
	return "https://oauth.telegram.test/auth?" + url.Values{"state": {state}}.Encode()
}
func (o stubOIDC) Exchange(context.Context, string, string, string) (*telegramoidc.Identity, error) {
	return &telegramoidc.Identity{TelegramID: o.tgID, Username: "dana_tg", FirstName: "Dana"}, nil
}

// browserToken is the browser Telegram sign-in token, minted the way
// /telegram/connect mints it: a real /oauth/authorize and Telegram callback
// for the built-in connect client, then oauth.Server.ExchangeConnect.
// requested is the authorize request's scope parameter, which narrows the
// grant; the token is checked to carry exactly what the
// caller expects about account:manage, so a change in ResolveScopes cannot
// quietly turn a refusal test into a pass.
func (f *accountManageFixture) browserToken(requested string, wantManage bool) string {
	f.t.Helper()
	verifier := "browser-verifier-" + strings.Repeat("x", 40)
	sum := sha256.Sum256([]byte(verifier))
	redirect := accountManageIssuer + "/telegram/connect/done"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {oauth.ConnectClientID},
		"redirect_uri":          {redirect},
		"state":                 {"connect-state"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	if requested != "" {
		q.Set("scope", requested)
	}
	rec := httptest.NewRecorder()
	f.oauthMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		f.t.Fatalf("authorize status = %d: %s", rec.Code, rec.Body.String())
	}
	toTelegram, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		f.t.Fatalf("authorize redirect: %v", err)
	}
	cb := url.Values{"state": {toTelegram.Query().Get("state")}, "code": {"tg-auth-code"}}
	rec = httptest.NewRecorder()
	f.oauthMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/oauth/telegram/callback?"+cb.Encode(), nil))
	loc := rec.Header().Get("Location")
	if rec.Code == http.StatusOK {
		// The success interstitial carries the redirect as a link.
		if m := regexp.MustCompile(`href="([^"]*code=[^"]*)"`).FindStringSubmatch(rec.Body.String()); m != nil {
			loc = html.UnescapeString(m[1])
		}
	}
	back, err := url.Parse(loc)
	if err != nil || back.Query().Get("code") == "" {
		f.t.Fatalf("callback status = %d gave no code (location %q): %s", rec.Code, loc, rec.Body.String())
	}
	tok, err := f.oauthSrv.ExchangeConnect(context.Background(), back.Query().Get("code"), verifier, oauth.ConnectClientID, redirect)
	if err != nil {
		f.t.Fatalf("ExchangeConnect: %v", err)
	}
	c, err := localjwt.Verify(tok, []byte(accountManageSecret), accountManageIssuer)
	if err != nil {
		f.t.Fatalf("verify browser token: %v", err)
	}
	if c.ClientID != oauth.ConnectClientID {
		f.t.Fatalf("browser token client_id = %q, want %q", c.ClientID, oauth.ConnectClientID)
	}
	if got := slices.Contains(c.Scopes, "account:manage"); got != wantManage {
		f.t.Fatalf("browser token scopes = %v; account:manage present = %v, want %v", c.Scopes, got, wantManage)
	}
	return tok
}

// narrowedBrowserToken is a browser sign-in token without account:manage.
func (f *accountManageFixture) narrowedBrowserToken() string {
	return f.browserToken("telegram:dialogs:read telegram:messages:read", false)
}

func (f *accountManageFixture) workerToken(purpose string) string {
	f.t.Helper()
	mt, err := f.minter.Mint(workertoken.MintRequest{TelegramID: f.tgID, Purpose: purpose})
	if err != nil {
		f.t.Fatalf("Mint(%q): %v", purpose, err)
	}
	return mt.Token
}

// deviceToken is a Local Bridge device credential from the real
// MintForDevice, carrying the widest scope set a device can ever hold (a
// refresh after the owner granted send consent).
func (f *accountManageFixture) deviceToken() string {
	f.t.Helper()
	mt, err := f.minter.MintForDevice(workertoken.DeviceMintRequest{
		TelegramID:       f.tgID,
		DeviceID:         "dev_accountmanagetest",
		Scopes:           deviceScopes,
		Jti:              "jti-accountmanagetest",
		OriginalIssuedAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		f.t.Fatalf("MintForDevice: %v", err)
	}
	return mt.Token
}

var deviceScopes = []string{"telegram:dialogs:read", "telegram:messages:read", "telegram:messages:send", "telegram:messages:pin"}

// accessToken signs an access token the way oauth.Server.mintAccessToken does.
func (f *accountManageFixture) accessToken(clientID string, scopes ...string) string {
	f.t.Helper()
	tok, err := f.signer.Mint(localjwt.Claims{
		Subject:    fmt.Sprintf("tg:%d", f.tgID),
		TelegramID: f.tgID,
		Scopes:     scopes,
		ClientID:   clientID,
	}, time.Hour)
	if err != nil {
		f.t.Fatalf("Mint access token: %v", err)
	}
	return tok
}

// call sends method path to the account API (path under /api/account), for
// path "manage" to the manage page's disconnect, for "manage-page" to the
// manage page itself, and for "toggle-send" / "manage-notifications" to the
// manage page's send toggle and notification form. bearer and cookie are the
// two ways a localjwt credential reaches the server. The two write paths that
// take a body get a valid one, so a refusal is the authorization and not the
// input.
func (f *accountManageFixture) call(method, path, bearer, cookie string) *httptest.ResponseRecorder {
	f.t.Helper()
	h, target := f.api, path
	var body io.Reader
	contentType := ""
	switch path {
	case "manage":
		h, target = f.manage, "/telegram/connect/manage/disconnect"
	case "manage-page":
		h, target = f.managePage, "/telegram/connect/manage"
	case "toggle-send":
		h, target = f.toggleSend, "/telegram/connect/manage/toggle-send"
	case "manage-notifications":
		h, target = f.setNotifs, "/telegram/connect/manage/notifications"
		body, contentType = strings.NewReader("submitted=notifications&product_updates=on"), "application/x-www-form-urlencoded"
	case "/notifications":
		body, contentType = strings.NewReader(`{"product_updates":"subscribed"}`), "application/json"
	}
	req := httptest.NewRequest(method, target, body)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "mctl_connect_token", Value: cookie})
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func (f *accountManageFixture) count(query string) int {
	f.t.Helper()
	var n int
	if err := f.store.DB.QueryRowContext(context.Background(), query, f.uid).Scan(&n); err != nil {
		f.t.Fatalf("count: %v", err)
	}
	return n
}

func (f *accountManageFixture) activeSessions() int {
	return f.count(`SELECT count(*) FROM telegram_accounts WHERE user_id = $1 AND revoked_at IS NULL`)
}

func (f *accountManageFixture) accountRows() int {
	return f.count(`SELECT count(*) FROM telegram_accounts WHERE user_id = $1`)
}

func (f *accountManageFixture) sendEnabled() bool {
	return f.count(`SELECT count(*) FROM telegram_accounts WHERE user_id = $1 AND send_enabled`) == 1
}

func (f *accountManageFixture) notificationPrefRows() int {
	return f.count(`SELECT count(*) FROM client_notification_prefs WHERE user_id = $1`)
}

func (f *accountManageFixture) latestAudit() (tool, status, reason string) {
	f.t.Helper()
	var r *string
	if err := f.store.DB.QueryRowContext(context.Background(),
		`SELECT tool_name, status, reason FROM audit_logs WHERE user_id = $1 ORDER BY id DESC LIMIT 1`, f.uid,
	).Scan(&tool, &status, &r); err != nil {
		f.t.Fatalf("latest audit: %v", err)
	}
	if r != nil {
		reason = *r
	}
	return tool, status, reason
}

// TestAccountEndpoints_RestrictedCredentialsCannotEndTheSession: a credential
// without account:manage can neither disconnect nor delete through the API,
// and only the browser sign-in token may disconnect on the manage page. Each
// refusal is a 403, leaves the session active and the row in place, and is
// audited as scope_denied against the account owner.
func TestAccountEndpoints_RestrictedCredentialsCannotEndTheSession(t *testing.T) {
	type path struct {
		method, path, audited, wantMsg string
	}
	disconnectAPI := path{http.MethodPost, "/disconnect", "POST /api/account/disconnect", msgDisconnectNeedsManage}
	deleteAPI := path{http.MethodDelete, "/", "DELETE /api/account", msgDeleteNeedsManage}
	managePage := path{http.MethodPost, "manage", "POST /telegram/connect/manage/disconnect", msgManageCannotDisconnect}
	creds := []struct {
		name  string
		token func(f *accountManageFixture) string
		paths []path
	}{
		{"read-only worker token", func(f *accountManageFixture) string { return f.workerToken("") }, []path{disconnectAPI, deleteAPI, managePage}},
		{"local-bridge worker token", func(f *accountManageFixture) string { return f.workerToken("local-bridge") }, []path{disconnectAPI, deleteAPI, managePage}},
		{"Local Bridge device credential", func(f *accountManageFixture) string { return f.deviceToken() }, []path{disconnectAPI, deleteAPI, managePage}},
		{"connector token without account:manage", func(f *accountManageFixture) string {
			return f.accessToken("dcr-client", "telegram:dialogs:read", "telegram:messages:read")
		}, []path{disconnectAPI, deleteAPI, managePage}},
		// The browser sign-in token's exception is the manage page's
		// disconnect only. Presented to the API as a bearer (the cookie's
		// Path keeps a browser from sending it there, but that is not the
		// authorization), it is refused like any other credential.
		{"browser sign-in token without account:manage", func(f *accountManageFixture) string { return f.narrowedBrowserToken() }, []path{disconnectAPI, deleteAPI}},
	}
	for _, c := range creds {
		for _, p := range c.paths {
			t.Run(c.name+"/"+p.audited, func(t *testing.T) {
				f := newAccountManageFixture(t, 7700101)
				rec := f.call(p.method, p.path, c.token(f), "")
				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
				}
				if body := rec.Body.String(); !strings.Contains(body, p.wantMsg) {
					t.Fatalf("body = %s, want the refusal %q", body, p.wantMsg)
				}
				if n := f.activeSessions(); n != 1 {
					t.Fatalf("active sessions = %d after a refused call, want 1", n)
				}
				if n := f.accountRows(); n != 1 {
					t.Fatalf("account rows = %d after a refused call, want 1", n)
				}
				tool, status, reason := f.latestAudit()
				if tool != p.audited || status != "error" || reason != reasonScopeDenied {
					t.Fatalf("audit = (%q, %q, %q), want (%q, error, %q)", tool, status, reason, p.audited, reasonScopeDenied)
				}
			})
		}
	}
}

// TestAccountEndpoints_RefusalIsAuditedAfterClientHangsUp: the refusal row is
// written detached from the request, so a cancelled request still leaves it.
func TestAccountEndpoints_RefusalIsAuditedAfterClientHangsUp(t *testing.T) {
	f := newAccountManageFixture(t, 7700102)
	// Authentication itself needs a live context, so the cancelled one is
	// handed straight to the handler with the identity a worker token
	// resolves to.
	ctx, cancel := context.WithCancel(auth.With(context.Background(), &auth.Identity{
		UserID: f.uid, TelegramID: f.tgID, Scopes: []string{"telegram:dialogs:read", "telegram:messages:read"},
	}))
	cancel()
	h := NewAccountHandlers(f.store, nil)
	rec := httptest.NewRecorder()
	h.delete(rec, httptest.NewRequest(http.MethodDelete, "/", nil).WithContext(ctx))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if _, _, reason := f.latestAudit(); reason != reasonScopeDenied {
		t.Fatalf("reason = %q, want %q", reason, reasonScopeDenied)
	}
}

func TestAccountEndpoints_AccountManageDisconnects(t *testing.T) {
	f := newAccountManageFixture(t, 7700103)
	rec := f.call(http.MethodPost, "/disconnect", f.accessToken("dcr-client", "telegram:messages:read", "account:manage"), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if n := f.activeSessions(); n != 0 {
		t.Fatalf("active sessions = %d after disconnect, want 0", n)
	}
	if tool, status, _ := f.latestAudit(); tool != "POST /api/account/disconnect" || status != "ok" {
		t.Fatalf("audit = (%q, %q), want the disconnect recorded as ok", tool, status)
	}
}

func TestAccountEndpoints_AccountManageDeletes(t *testing.T) {
	f := newAccountManageFixture(t, 7700104)
	rec := f.call(http.MethodDelete, "/", f.accessToken("dcr-client", "telegram:messages:read", "account:manage"), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if n := f.accountRows(); n != 0 {
		t.Fatalf("account rows = %d after delete, want 0", n)
	}
}

// TestManageDisconnect_BrowserSignInAlwaysWorks: the owner's way out does not
// depend on the scopes a connector was narrowed to. The real browser sign-in
// token (client_id = oauth.ConnectClientID), narrowed below account:manage,
// reaches the manage page as the connect-session cookie and disconnects.
func TestManageDisconnect_BrowserSignInAlwaysWorks(t *testing.T) {
	f := newAccountManageFixture(t, 7700105)
	rec := f.call(http.MethodPost, "manage", "", f.narrowedBrowserToken())
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if n := f.activeSessions(); n != 0 {
		t.Fatalf("active sessions = %d after the owner disconnected, want 0", n)
	}
	// The disconnect that ended the session is in the audit log, not only
	// the refused ones.
	if tool, status, _ := f.latestAudit(); tool != "POST /telegram/connect/manage/disconnect" || status != "ok" {
		t.Fatalf("audit = (%q, %q), want the manage-page disconnect recorded as ok", tool, status)
	}
}

// TestManagePage_DisconnectButtonFollowsTheServerCheck: the page offers the
// Disconnect button exactly when HandleDisconnect would accept the caller, and
// otherwise says why in its place.
func TestManagePage_DisconnectButtonFollowsTheServerCheck(t *testing.T) {
	const button = `action="/telegram/connect/manage/disconnect"`
	cases := []struct {
		name       string
		bearer     func(f *accountManageFixture) string
		cookie     func(f *accountManageFixture) string
		wantButton bool
	}{
		{"browser sign-in cookie without account:manage", nil, func(f *accountManageFixture) string { return f.narrowedBrowserToken() }, true},
		{"browser sign-in cookie with account:manage", nil, func(f *accountManageFixture) string { return f.browserToken("", true) }, true},
		{"connector with account:manage", func(f *accountManageFixture) string {
			return f.accessToken("dcr-client", "telegram:messages:read", "account:manage")
		}, nil, true},
		{"read-only worker token", func(f *accountManageFixture) string { return f.workerToken("") }, nil, false},
		{"Local Bridge device credential", func(f *accountManageFixture) string { return f.deviceToken() }, nil, false},
		{"connector without account:manage", func(f *accountManageFixture) string {
			return f.accessToken("dcr-client", "telegram:messages:read")
		}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAccountManageFixture(t, 7700106)
			var bearer, cookie string
			if tc.bearer != nil {
				bearer = tc.bearer(f)
			}
			if tc.cookie != nil {
				cookie = tc.cookie(f)
			}
			rec := f.call(http.MethodGet, "manage-page", bearer, cookie)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if got := strings.Contains(body, button); got != tc.wantButton {
				t.Fatalf("Disconnect button shown = %v, want %v", got, tc.wantButton)
			}
			if got := strings.Contains(body, msgManageCannotDisconnect); got == tc.wantButton {
				t.Fatalf("refusal note shown = %v, want %v", got, !tc.wantButton)
			}
			// The page and the handler must agree: where the button is
			// shown, pressing it works; where it is not, it is refused.
			post := f.call(http.MethodPost, "manage", bearer, cookie)
			if accepted := post.Code == http.StatusFound; accepted != tc.wantButton {
				t.Fatalf("disconnect status = %d; accepted = %v, want %v", post.Code, accepted, tc.wantButton)
			}
		})
	}
}

// TestManageAccessChecks_FailClosed: an empty connectClient adds nothing to
// account:manage, and a nil identity passes neither check.
func TestManageAccessChecks_FailClosed(t *testing.T) {
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:read"}}
	if canDisconnectFromManagePage(id, "") {
		t.Fatal("an identity with no client_id passed with an empty connectClient")
	}
	browser := &auth.Identity{UserID: 1, ClientID: oauth.ConnectClientID, Scopes: []string{"telegram:messages:read"}}
	if canManageAccount(browser) {
		t.Fatal("canManageAccount accepted the browser sign-in token without account:manage")
	}
	if canManageAccount(nil) || canDisconnectFromManagePage(nil, oauth.ConnectClientID) {
		t.Fatal("a nil identity passed")
	}
}

// settingsCredential is one credential in the send-consent and notification
// matrix, and how a client would present it.
type settingsCredential struct {
	name     string
	bearer   func(f *accountManageFixture) string
	cookie   func(f *accountManageFixture) string
	accepted bool
}

// settingsCredentials: send consent and notification preferences need
// account:manage on every surface. Unlike the manage page's disconnect, they
// take no browser sign-in exception, so the browser token is listed here
// without account:manage and refused: if that exception spread to these
// routes again, its row would flip.
var settingsCredentials = []settingsCredential{
	{"browser sign-in cookie without account:manage", nil, func(f *accountManageFixture) string { return f.narrowedBrowserToken() }, false},
	{"browser sign-in bearer without account:manage", func(f *accountManageFixture) string { return f.narrowedBrowserToken() }, nil, false},
	{"read-only worker token", func(f *accountManageFixture) string { return f.workerToken("") }, nil, false},
	{"local-bridge worker token", func(f *accountManageFixture) string { return f.workerToken("local-bridge") }, nil, false},
	{"Local Bridge device credential", func(f *accountManageFixture) string { return f.deviceToken() }, nil, false},
	{"connector without account:manage", func(f *accountManageFixture) string {
		return f.accessToken("dcr-client", "telegram:dialogs:read", "telegram:messages:read")
	}, nil, false},
	{"browser sign-in cookie with account:manage", nil, func(f *accountManageFixture) string { return f.browserToken("", true) }, true},
	{"connector with account:manage", func(f *accountManageFixture) string {
		return f.accessToken("dcr-client", "telegram:messages:read", "account:manage")
	}, nil, true},
}

func (c settingsCredential) present(f *accountManageFixture) (bearer, cookie string) {
	if c.bearer != nil {
		bearer = c.bearer(f)
	}
	if c.cookie != nil {
		cookie = c.cookie(f)
	}
	return bearer, cookie
}

// TestAccountSettings_RequireAccountManage: the manage page's send toggle and
// notification form, and PUT /api/account/notifications, accept exactly the
// credentials granted account:manage -- the HTTP twins of set_send_consent
// and set_my_notification_preferences. A refusal is a 403 that changes
// nothing and is audited as scope_denied; an accepted change is audited as
// ok.
func TestAccountSettings_RequireAccountManage(t *testing.T) {
	type route struct {
		method, path, audited, wantMsg string
		okStatus                       int
		changed                        func(f *accountManageFixture) bool
	}
	routes := []route{
		{http.MethodPost, "toggle-send", "POST /telegram/connect/manage/toggle-send", msgManageNeedsManage, http.StatusFound,
			func(f *accountManageFixture) bool { return f.sendEnabled() }},
		{http.MethodPost, "manage-notifications", "POST /telegram/connect/manage/notifications", msgManageNeedsManage, http.StatusFound,
			func(f *accountManageFixture) bool { return f.notificationPrefRows() > 0 }},
		{http.MethodPut, "/notifications", "PUT /api/account/notifications", msgNotificationsNeedsManage, http.StatusOK,
			func(f *accountManageFixture) bool { return f.notificationPrefRows() > 0 }},
	}
	for _, c := range settingsCredentials {
		for _, rt := range routes {
			// The API reads no cookie: a browser credential reaches it only
			// as a bearer, which the cookie row's bearer twin covers.
			if rt.path == "/notifications" && c.cookie != nil {
				continue
			}
			t.Run(c.name+"/"+rt.audited, func(t *testing.T) {
				f := newAccountManageFixture(t, 7700107)
				if f.sendEnabled() || f.notificationPrefRows() != 0 {
					t.Fatal("fixture does not start with send consent off and no saved preferences")
				}
				bearer, cookie := c.present(f)
				rec := f.call(rt.method, rt.path, bearer, cookie)
				tool, status, reason := f.latestAudit()
				if !c.accepted {
					if rec.Code != http.StatusForbidden {
						t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
					}
					if body := rec.Body.String(); !strings.Contains(body, rt.wantMsg) {
						t.Fatalf("body = %s, want the refusal %q", body, rt.wantMsg)
					}
					if rt.changed(f) {
						t.Fatal("a refused call changed the account")
					}
					if tool != rt.audited || status != "error" || reason != reasonScopeDenied {
						t.Fatalf("audit = (%q, %q, %q), want (%q, error, %q)", tool, status, reason, rt.audited, reasonScopeDenied)
					}
					return
				}
				if rec.Code != rt.okStatus {
					t.Fatalf("status = %d, want %d; body=%s", rec.Code, rt.okStatus, rec.Body.String())
				}
				if !rt.changed(f) {
					t.Fatal("an accepted call did not change the account")
				}
				if tool != rt.audited || status != "ok" {
					t.Fatalf("audit = (%q, %q), want (%q, ok)", tool, status, rt.audited)
				}
			})
		}
	}
}

// TestManagePage_SettingsControlsFollowTheServerCheck: the page offers the
// send toggle and the notification form exactly when their handlers would
// accept the caller, and otherwise says why in their place.
func TestManagePage_SettingsControlsFollowTheServerCheck(t *testing.T) {
	controls := []struct {
		form, note, post string
	}{
		{`action="/telegram/connect/manage/toggle-send"`, `id="send-unavailable"`, "toggle-send"},
		{`action="/telegram/connect/manage/notifications"`, `id="notifications-unavailable"`, "manage-notifications"},
	}
	for _, c := range settingsCredentials {
		t.Run(c.name, func(t *testing.T) {
			f := newAccountManageFixture(t, 7700108)
			bearer, cookie := c.present(f)
			rec := f.call(http.MethodGet, "manage-page", bearer, cookie)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			for _, ctl := range controls {
				if got := strings.Contains(body, ctl.form); got != c.accepted {
					t.Fatalf("%s shown = %v, want %v", ctl.form, got, c.accepted)
				}
				if got := strings.Contains(body, ctl.note); got == c.accepted {
					t.Fatalf("%s shown = %v, want %v", ctl.note, got, !c.accepted)
				}
				post := f.call(http.MethodPost, ctl.post, bearer, cookie)
				if accepted := post.Code == http.StatusFound; accepted != c.accepted {
					t.Fatalf("%s status = %d; accepted = %v, want %v", ctl.post, post.Code, accepted, c.accepted)
				}
			}
		})
	}
}
