package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/oauth"
	"github.com/mctlhq/mctl-telegram/internal/workertoken"
)

// These tests run the real credentials through the real middleware: a worker
// token from workertoken.Minter, an access token signed the way
// oauth.Server.mintAccessToken signs one, and localjwt.Provider verifying
// both. A hand-built auth.Identity would prove the check, not that the
// credentials the server actually issues land on the right side of it.

const (
	accountManageSecret = "account-manage-test-secret-32-bytes!"
	accountManageIssuer = "https://tg.test"
)

type accountManageFixture struct {
	store  *db.Store
	uid    int64
	tgID   int64
	api    http.Handler
	manage http.Handler
	minter *workertoken.Minter
	signer *localjwt.Issuer
	t      *testing.T
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
	rm := auth.ResourceMetadata{BaseURL: accountManageIssuer}

	router := chi.NewRouter()
	NewAccountHandlers(store, nil).WithConnectClient(oauth.ConnectClientID).Register(router)
	manageSrv := NewManageServer(store, nil, accountManageIssuer, "").WithConnectClient(oauth.ConnectClientID)

	return &accountManageFixture{
		store:  store,
		uid:    uid,
		tgID:   tgID,
		api:    auth.Middleware(provider, true, nil, rm)(router),
		manage: auth.MiddlewareWithHTML(provider, true, nil, rm, manageSrv.WriteUnauthorized)(http.HandlerFunc(manageSrv.HandleDisconnect)),
		minter: minter,
		signer: signer,
		t:      t,
	}
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

// call sends method path to the account API (path under /api/account) or, for
// path "manage", to the manage page's disconnect. bearer and cookie are the
// two ways a localjwt credential reaches the server.
func (f *accountManageFixture) call(method, path, bearer, cookie string) *httptest.ResponseRecorder {
	f.t.Helper()
	h, target := f.api, path
	if path == "manage" {
		h, target = f.manage, "/telegram/connect/manage/disconnect"
	}
	req := httptest.NewRequest(method, target, nil)
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

// TestAccountEndpoints_RestrictedCredentialsCannotEndTheSession: a read-only
// worker token and a Local Bridge device-style token can neither disconnect
// nor delete through any HTTP path. Each refusal is a 403, leaves the session
// active and the row in place, and is audited as scope_denied against the
// account owner.
func TestAccountEndpoints_RestrictedCredentialsCannotEndTheSession(t *testing.T) {
	paths := []struct {
		method, path, audited string
	}{
		{http.MethodPost, "/disconnect", "POST /api/account/disconnect"},
		{http.MethodDelete, "/", "DELETE /api/account"},
		{http.MethodPost, "manage", "POST /telegram/connect/manage/disconnect"},
	}
	creds := []struct {
		name  string
		token func(f *accountManageFixture) string
	}{
		{"read-only worker token", func(f *accountManageFixture) string { return f.workerToken("") }},
		{"local-bridge worker token", func(f *accountManageFixture) string { return f.workerToken("local-bridge") }},
		{"Local Bridge device credential", func(f *accountManageFixture) string { return f.deviceToken() }},
		{"connector token without account:manage", func(f *accountManageFixture) string {
			return f.accessToken("dcr-client", "telegram:dialogs:read", "telegram:messages:read")
		}},
	}
	for _, c := range creds {
		for _, p := range paths {
			t.Run(c.name+"/"+p.audited, func(t *testing.T) {
				f := newAccountManageFixture(t, 7700101)
				rec := f.call(p.method, p.path, c.token(f), "")
				if rec.Code != http.StatusForbidden {
					t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
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
	h := NewAccountHandlers(f.store, nil).WithConnectClient(oauth.ConnectClientID)
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
// depend on the scopes a connector was narrowed to. The browser sign-in token
// (client_id = oauth.ConnectClientID) reaches the manage page as the
// connect-session cookie and disconnects even without account:manage.
func TestManageDisconnect_BrowserSignInAlwaysWorks(t *testing.T) {
	f := newAccountManageFixture(t, 7700105)
	rec := f.call(http.MethodPost, "manage", "", f.accessToken(oauth.ConnectClientID, "telegram:messages:read"))
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if n := f.activeSessions(); n != 0 {
		t.Fatalf("active sessions = %d after the owner disconnected, want 0", n)
	}
}

// TestMintForDevice_NeverIssuesAccountManage: the refusal above rests on a
// device credential never carrying account:manage. Asking MintForDevice for
// it must fail, not mint a credential that would pass canManageAccount.
func TestMintForDevice_NeverIssuesAccountManage(t *testing.T) {
	f := newAccountManageFixture(t, 7700106)
	_, err := f.minter.MintForDevice(workertoken.DeviceMintRequest{
		TelegramID:       f.tgID,
		DeviceID:         "dev_accountmanagetest",
		Scopes:           append(append([]string{}, deviceScopes...), "account:manage"),
		Jti:              "jti-accountmanagetest",
		OriginalIssuedAt: time.Now().Add(-time.Minute),
	})
	if err == nil {
		t.Fatal("MintForDevice issued a device credential carrying account:manage")
	}
}

// TestCanManageAccount_EmptyConnectClientFailsClosed: an unwired
// ConnectClient must not make a token without a client_id pass the check.
func TestCanManageAccount_EmptyConnectClientFailsClosed(t *testing.T) {
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:read"}}
	if canManageAccount(id, "") {
		t.Fatal("an identity with no client_id passed with an empty connectClient")
	}
	if canManageAccount(nil, oauth.ConnectClientID) {
		t.Fatal("a nil identity passed")
	}
}
