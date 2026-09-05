package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
	_ "modernc.org/sqlite"
)

// newEnableTestStore returns a Store backed by a per-test temp-file SQLite DB
// (real isolation between tests) with a non-nil plaintext-mode crypto, so the
// SaveSession / LoadSession calls the login goroutine makes do not nil-panic.
func newEnableTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "enable.db") + "?_pragma=busy_timeout(5000)"
	conn, err := db.Open(ctx, dsn, 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	crypt, err := crypto.New(nil) // empty key → plaintext-at-rest, fine for tests
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	return db.NewStore(conn, crypt)
}

// seedSession inserts a fresh, valid telegram_accounts row for tgID so the
// widget callback issues an authorization code directly instead of diverting
// into the enable_access flow. The blob bytes are never decrypted by the
// callback path (CheckSessionValid only reads the timestamps), so a raw INSERT
// works even on a Crypt-less test store.
func seedSession(t *testing.T, srv *Server, tgID int64) {
	t.Helper()
	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, tgID, "", "")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	now := time.Now().UTC()
	// telegram_user_id must be set: it is the marker that distinguishes a
	// finalised (SaveSession) session from a mid-login partial one, and
	// CheckSessionValid rejects rows where it is NULL.
	if _, err := srv.store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at)
		 VALUES($1, $2, $3, $4, $5)`,
		uid, tgID, []byte("seed-session"), now, now.Add(24*time.Hour),
	); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func newEnableTestServer(t *testing.T, login LoginFunc, opts ...func(*Config)) (*Server, *chi.Mux) {
	t.Helper()
	cfg := Config{
		Issuer:              testIssuer,
		JWTSecret:           testJWTSecret,
		TelegramOIDC:        newFakeAuthenticator(),
		AdminTelegramIDs:    map[int64]bool{210408407: true},
		AccessTokenTTL:      time.Hour,
		CodeTTL:             time.Minute,
		AllowImplicitClient: true,
		TGAPIID:             99999,
		TGAPIHash:           "test-api-hash",
	}
	for _, o := range opts {
		o(&cfg)
	}
	srv, err := New(context.Background(), cfg, newEnableTestStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if login != nil {
		srv.loginFn = login
	}
	mux := chi.NewRouter()
	srv.Register(&chiAdapter{mux: mux})
	return srv, mux
}

// stubLogin fakes telegram.Login. It always consumes the SMS code; when needPw
// it also consumes the 2FA password. When failErr is non-nil it returns that
// after the inputs are consumed (mimicking PHONE_CODE_INVALID etc.); otherwise
// it persists a session blob and reports success as the admin id.
func stubLogin(needPw bool, failErr error) LoginFunc {
	return func(ctx context.Context, apiID int, apiHash string, store *db.Store,
		uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		_ ...telegram.LoginConfig,
	) (int64, string, string, error) {
		if _, err := askCode(ctx); err != nil {
			return 0, "", "", err
		}
		if needPw {
			if _, err := askPassword(ctx); err != nil {
				return 0, "", "", err
			}
		}
		if failErr != nil {
			return 0, "", "", failErr
		}
		if err := store.UpdateSessionBlob(ctx, uid, []byte("fake-mtproto-session")); err != nil {
			return 0, "", "", err
		}
		return 210408407, "Dmitry", "MashkovD", nil
	}
}

// stubLoginWrongAccount fakes a login that succeeds but resolves to a
// different Telegram account than the widget-proven one (id 210408407). It
// persists session bytes first, mimicking gotd, so the test can assert the
// identity-mismatch path revokes them.
func stubLoginWrongAccount() LoginFunc {
	return func(ctx context.Context, apiID int, apiHash string, store *db.Store,
		uid int64, phone string,
		askCode func(context.Context) (string, error),
		askPassword func(context.Context) (string, error),
		_ ...telegram.LoginConfig,
	) (int64, string, string, error) {
		if _, err := askCode(ctx); err != nil {
			return 0, "", "", err
		}
		if err := store.UpdateSessionBlob(ctx, uid, []byte("wrong-account-session")); err != nil {
			return 0, "", "", err
		}
		return 999000111, "Someone Else", "someoneelse", nil
	}
}

func postForm(t *testing.T, mux *chi.Mux, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// extractInputValue pulls the value="" of the first <input> whose name="" matches.
func extractInputValue(t *testing.T, html, name string) string {
	t.Helper()
	marker := `name="` + name + `"`
	i := strings.Index(html, marker)
	if i < 0 {
		t.Fatalf("input name=%q not found in HTML", name)
	}
	rest := html[i:]
	vi := strings.Index(rest, `value="`)
	if vi < 0 {
		t.Fatalf("no value for input name=%q", name)
	}
	rest = rest[vi+len(`value="`):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		t.Fatalf("unterminated value for input name=%q", name)
	}
	return rest[:end]
}

// authorizeViaChi runs GET /oauth/authorize on a chi mux and returns the
// server-side state token embedded in the 302-to-Telegram redirect.
func authorizeViaChi(t *testing.T, mux *chi.Mux, challenge string) string {
	t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"claude.ai"},
		"redirect_uri":          {"https://claude.ai/cb"},
		"state":                 {"client-state-xyz"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d body=%s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize redirect parse: %v", err)
	}
	st := loc.Query().Get("state")
	if st == "" {
		t.Fatalf("authorize redirect carried no state: %s", loc)
	}
	return st
}

// callbackViaChi runs the Telegram OIDC callback GET (?code=&state=) on a chi mux.
func callbackViaChi(t *testing.T, mux *chi.Mux, state string) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{"state": {state}, "code": {"tg-auth-code"}}
	req := httptest.NewRequest("GET", "/oauth/telegram/callback?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// driveToPhone runs /oauth/authorize then the Telegram OIDC callback for an
// admin with no session, and returns the "es" token from the rendered phone
// screen. The fake authenticator resolves the admin (210408407) by default.
func driveToPhone(t *testing.T, mux *chi.Mux) string {
	t.Helper()
	_, challenge := pkceVerifierAndChallenge()
	state := authorizeViaChi(t, mux, challenge)
	rec := callbackViaChi(t, mux, state)
	if rec.Code != http.StatusOK {
		t.Fatalf("callback = %d (want 200 phone screen); body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/oauth/telegram/enable_access/start") {
		t.Fatalf("phone screen not rendered; body=%s", body)
	}
	return extractInputValue(t, body, "es")
}

func TestEnableAccess_HappyPath_NoTwoFA(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	es := driveToPhone(t, mux)

	// Phone → code screen.
	rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not render code screen: %d %s", rec.Code, rec.Body.String())
	}

	// Code → success interstitial back to the client with an authorization code.
	rec = postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}})
	loc := authCodeRedirect(t, rec)
	if loc.Host != "claude.ai" || loc.Query().Get("code") == "" {
		t.Fatalf("bad redirect: %s", loc)
	}
	if loc.Query().Get("state") != "client-state-xyz" {
		t.Errorf("state echo = %q", loc.Query().Get("state"))
	}

	// The session must now be valid, bound to the widget-resolved user.
	ctx := context.Background()
	uid, _ := srv.store.EnsureUserByTelegramID(ctx, 210408407, "MashkovD", "Dmitry")
	if _, err := srv.store.CheckSessionValid(ctx, uid); err != nil {
		t.Errorf("session not valid after enable_access: %v", err)
	}
	if on, _ := srv.store.IsSendEnabled(ctx, uid); on {
		t.Errorf("send_enabled should be false without opt-in")
	}
}

func TestEnableAccess_TwoFA(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(true, nil))
	es := driveToPhone(t, mux)

	rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}

	// Code → 2FA screen (stub asks for a password).
	rec = postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "enable_access/password") {
		t.Fatalf("code did not render 2FA screen: %d %s", rec.Code, rec.Body.String())
	}

	// Password → success interstitial.
	rec = postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {es}, "password": {"hunter2"}})
	authCodeRedirect(t, rec)
	_ = srv
}

func TestEnableAccess_BadCode_RestartsAtPhone(t *testing.T) {
	_, mux := newEnableTestServer(t, stubLogin(false, errors.New("PHONE_CODE_INVALID")))
	es := driveToPhone(t, mux)

	rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("start: %d", rec.Code)
	}

	rec = postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"00000"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("bad code = %d (want 200 phone screen)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/oauth/telegram/enable_access/start") {
		t.Fatalf("did not fall back to the phone screen: %s", body)
	}
	if !strings.Contains(body, "not accepted") {
		t.Errorf("phone screen missing the rejection notice: %s", body)
	}
}

func TestEnableAccess_SendOptIn_SetsFlag(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	es := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}, "send_optin": {"on"}}); rec.Code != http.StatusOK {
		t.Fatalf("start: %d", rec.Code)
	}
	authCodeRedirect(t, postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}}))
	ctx := context.Background()
	uid, _ := srv.store.EnsureUserByTelegramID(ctx, 210408407, "MashkovD", "Dmitry")
	on, err := srv.store.IsSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("IsSendEnabled: %v", err)
	}
	if !on {
		t.Error("send_enabled was not set despite the opt-in checkbox")
	}
}

func TestEnableAccess_InvalidPhone_ReRendersPhone(t *testing.T) {
	_, mux := newEnableTestServer(t, stubLogin(false, nil))
	es := driveToPhone(t, mux)
	rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"not-a-phone"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("invalid phone = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "international format") {
		t.Errorf("expected phone-format error, got %s", rec.Body.String())
	}
}

func TestEnableAccess_ExpiredToken(t *testing.T) {
	_, mux := newEnableTestServer(t, stubLogin(false, nil))
	rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {"bogus-token"}, "phone": {"+14155551234"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown es token = %d (want 400)", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "expired") {
		t.Errorf("expected an expiry message, got %s", rec.Body.String())
	}
}

// getEnableSession fetches the live *enableSession for an es token (same-package
// access) so a test can hold its lock and simulate a slow concurrent step.
func getEnableSession(t *testing.T, srv *Server, esTok string) *enableSession {
	t.Helper()
	srv.mu.Lock()
	defer srv.mu.Unlock()
	es := srv.enables[esTok]
	if es == nil {
		t.Fatalf("no enable session for token %q", esTok)
	}
	return es
}

// TestEnableAccess_ConcurrentStep_RecoversInsteadOfDeadEnd reproduces the
// regression where a duplicate/concurrent step submit (common from in-app
// browsers and MCP clients re-issuing a POST) lost the per-session lock race and
// dead-ended the user on the "Sign-in interrupted" page. A submit that briefly
// loses the race must now wait, acquire, and continue the flow.
func TestEnableAccess_ConcurrentStep_RecoversInsteadOfDeadEnd(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	es := driveToPhone(t, mux)

	// Hold the session lock, release it shortly (well within enableLockWait):
	// the /start submit must wait, then render the code screen — not the
	// terminal wait page.
	sess := getEnableSession(t, srv, es)
	sess.lock.Lock()
	go func() {
		time.Sleep(100 * time.Millisecond)
		sess.lock.Unlock()
	}()

	rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("contended start = %d (want 200 code screen); body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Errorf("contended start did not render the code screen: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "still finishing") {
		t.Errorf("duplicate submit dead-ended instead of recovering: %s", rec.Body.String())
	}
}

// TestEnableAccess_LockHeldThroughout_ShowsNonTerminalWait confirms that when a
// step genuinely holds the lock for the whole window (e.g. /start mid-SendCode),
// the loser gets the non-terminal "still finishing" page rather than crashing.
func TestEnableAccess_LockHeldThroughout_ShowsNonTerminalWait(t *testing.T) {
	prev := enableLockWait
	enableLockWait = 50 * time.Millisecond
	t.Cleanup(func() { enableLockWait = prev })

	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	es := driveToPhone(t, mux)

	sess := getEnableSession(t, srv, es)
	sess.lock.Lock()
	defer sess.lock.Unlock()

	rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("lock-held start = %d (want 400 wait page); body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "still finishing") {
		t.Errorf("expected the non-terminal wait page, got: %s", rec.Body.String())
	}
}

// TestEnableAccess_DuplicateCodeAfterAdvance_KeepsPasswordStep covers the P2
// fix: a duplicate /code submit arriving after the original advanced to the
// password step must re-render the password screen WITHOUT resetting es.step to
// stepPhone — otherwise the real user's password submission would be bounced
// back to the phone screen.
func TestEnableAccess_DuplicateCodeAfterAdvance_KeepsPasswordStep(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(true, nil)) // 2FA path
	es := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}}); rec.Code != http.StatusOK {
		t.Fatalf("start: %d", rec.Code)
	}
	// First /code advances to the password screen.
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "enable_access/password") {
		t.Fatalf("first code did not reach the password screen: %d", rec.Code)
	}

	sess := getEnableSession(t, srv, es)

	// Duplicate /code now (es.step is already stepPassword): must re-render the
	// password screen, not bounce to phone, and must not reset es.step.
	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "enable_access/password") {
		t.Fatalf("duplicate code did not re-render the password screen: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "enable_access/start") {
		t.Errorf("duplicate code bounced back to the phone screen")
	}
	if sess.step != stepPassword {
		t.Errorf("es.step = %v, want stepPassword (duplicate must not reset it)", sess.step)
	}

	// The real user's password submission must still succeed.
	authCodeRedirect(t, postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {es}, "password": {"hunter2"}}))
}

// TestEnableAccess_DuplicateStartAfterAdvance_DoesNotRelaunch covers the P1
// fix: a duplicate /start arriving after the original advanced to the code
// screen must re-render the code screen and NOT cancel/relaunch the live login
// flow (which would invalidate the user's SMS code and send a second one).
func TestEnableAccess_DuplicateStartAfterAdvance_DoesNotRelaunch(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	es := driveToPhone(t, mux)

	// First /start advances to the code screen.
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}}); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("first start did not reach the code screen: %d", rec.Code)
	}
	sess := getEnableSession(t, srv, es)
	flowBefore := sess.flow

	// Duplicate /start at stepCode: re-render the code screen, leave the live
	// flow untouched.
	rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("duplicate start did not re-render the code screen: %d %s", rec.Code, rec.Body.String())
	}
	if sess.flow != flowBefore {
		t.Errorf("duplicate start relaunched the login flow (flow pointer changed)")
	}
	if sess.step != stepCode {
		t.Errorf("es.step = %v, want stepCode", sess.step)
	}

	// The original code submission still succeeds against the un-cancelled flow.
	authCodeRedirect(t, postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}}))
}

// telegramCallbackFor drives /oauth/authorize then the Telegram OIDC callback
// for tgID and returns the callback response recorder. It points the fake
// authenticator at tgID so Exchange resolves that identity.
func telegramCallbackFor(t *testing.T, srv *Server, mux *chi.Mux, tgID int64) *httptest.ResponseRecorder {
	t.Helper()
	authFake(srv).identity = &telegramoidc.Identity{TelegramID: tgID, Username: "user", FirstName: "User"}
	_, challenge := pkceVerifierAndChallenge()
	state := authorizeViaChi(t, mux, challenge)
	return callbackViaChi(t, mux, state)
}

// TestEnableAccess_UnknownUserSkipsFlow confirms a user in neither allowlist
// gets the authorization code directly, never the enable_access phone screen.
func TestEnableAccess_UnknownUserSkipsFlow(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	rec := telegramCallbackFor(t, srv, mux, 999000111) // in no allowlist
	// External client → success interstitial carrying the code (not the phone screen).
	if loc := authCodeRedirect(t, rec); loc.Query().Get("code") == "" {
		t.Fatalf("unknown-user callback did not issue a code straight away: %s", loc)
	}
}

// TestEnableAccess_LookupAdminOnlySkipsFlow confirms a lookup-admin-only
// identity (in LookupAdminTelegramIDs but not AdminTelegramIDs) gets the
// authorization code directly, never the enable_access phone screen — it
// mirrors TestEnableAccess_UnknownUserSkipsFlow's "no scopes" pattern, since
// a lookup-admin's admin:users:read-only bundle has no telegram:* scope that
// would make an MTProto session useful.
func TestEnableAccess_LookupAdminOnlySkipsFlow(t *testing.T) {
	lookupID := int64(888000333)
	srv, mux := newEnableTestServer(t, stubLogin(false, nil), func(c *Config) {
		c.LookupAdminTelegramIDs = map[int64]bool{lookupID: true}
	})
	rec := telegramCallbackFor(t, srv, mux, lookupID)
	// External client → success interstitial carrying the code (not the phone screen).
	if loc := authCodeRedirect(t, rec); loc.Query().Get("code") == "" {
		t.Fatalf("lookup-admin-only callback did not issue a code straight away: %s", loc)
	}
	if strings.Contains(rec.Body.String(), "/oauth/telegram/enable_access/start") {
		t.Fatalf("lookup-admin-only identity was routed into the enable_access phone screen; body=%s", rec.Body.String())
	}
	// No pending enableSession/stepPhone state should have been created.
	srv.mu.Lock()
	numEnables := len(srv.enables)
	srv.mu.Unlock()
	if numEnables != 0 {
		t.Errorf("lookup-admin-only callback created %d pending enableSession(s), want 0", numEnables)
	}
}

// TestEnableAccess_LookupAdminAndClientSkipsFlow covers the dual-listed case
// at the CALLBACK, where TestResolveScopes_Tiers only covers the scope grant.
// An id in both LookupAdminTelegramIDs and ClientTelegramIDs resolves to
// admin:users:read alone, so an MTProto session would be as useless to it as
// to a no-scopes identity -- it must skip the phone screen, not be routed
// into enable_access on the strength of its client listing.
func TestEnableAccess_LookupAdminAndClientSkipsFlow(t *testing.T) {
	dualID := int64(888000444)
	srv, mux := newEnableTestServer(t, stubLogin(false, nil), func(c *Config) {
		c.LookupAdminTelegramIDs = map[int64]bool{dualID: true}
		c.ClientTelegramIDs = map[int64]bool{dualID: true}
	})
	rec := telegramCallbackFor(t, srv, mux, dualID)
	if loc := authCodeRedirect(t, rec); loc.Query().Get("code") == "" {
		t.Fatalf("dual-listed lookup admin did not get a code straight away: %s", loc)
	}
	if strings.Contains(rec.Body.String(), "/oauth/telegram/enable_access/start") {
		t.Fatalf("dual-listed lookup admin was routed into the enable_access phone screen; body=%s", rec.Body.String())
	}
	srv.mu.Lock()
	numEnables := len(srv.enables)
	srv.mu.Unlock()
	if numEnables != 0 {
		t.Errorf("dual-listed lookup admin created %d pending enableSession(s), want 0", numEnables)
	}
}

// TestEnableAccess_ClientRoutedToPhoneScreen confirms a client-tier user with
// no session is routed into the enable_access phone screen, not 302'd.
func TestEnableAccess_ClientRoutedToPhoneScreen(t *testing.T) {
	clientID := int64(888000111)
	srv, mux := newEnableTestServer(t, stubLogin(false, nil), func(c *Config) {
		c.ClientTelegramIDs = map[int64]bool{clientID: true}
	})
	rec := telegramCallbackFor(t, srv, mux, clientID)
	if rec.Code != http.StatusOK {
		t.Fatalf("client callback = %d (want 200 phone screen); body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "/oauth/telegram/enable_access/start") {
		t.Fatalf("client was not routed to the enable_access phone screen; body=%s", rec.Body.String())
	}
}

// TestResolveScopes_DBRevokeOverridesEnv confirms that an explicit DB tier of
// "none" revokes a client even when they are in the TG_LOGIN_CLIENTS env
// bootstrap allowlist.
func TestResolveScopes_DBRevokeOverridesEnv(t *testing.T) {
	ctx := context.Background()
	envID := int64(666000333)
	srv := newTestServer(t, func(c *Config) {
		c.ClientTelegramIDs = map[int64]bool{envID: true}
	})
	// Starts as a client via the env bootstrap allowlist.
	if _, sc, err := srv.ResolveScopes(ctx, envID); err != nil || len(sc) == 0 {
		t.Fatalf("env-listed id should start as a client: scopes=%v err=%v", sc, err)
	}
	// Explicit DB revocation must override the env.
	if _, err := srv.store.EnsureUserByTelegramID(ctx, envID, "u", "U"); err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.SetAccessTier(ctx, envID, db.TierNone); err != nil {
		t.Fatalf("set tier none: %v", err)
	}
	if _, sc, err := srv.ResolveScopes(ctx, envID); err != nil || len(sc) != 0 {
		t.Errorf("DB tier='none' must override the env allowlist: scopes=%v err=%v", sc, err)
	}
}

// TestResolveScopes_AutoApprove confirms open registration: with
// AutoApproveClients on, an un-tiered user gets the client tier, an explicit
// DB "none" still bans, and admins are unaffected.
func TestResolveScopes_AutoApprove(t *testing.T) {
	has := func(ss []string, v string) bool {
		for _, s := range ss {
			if s == v {
				return true
			}
		}
		return false
	}
	ctx := context.Background()
	srv := newTestServer(t, func(c *Config) { c.AutoApproveClients = true })

	// Unknown user, no DB tier, not in env → client by auto-approve.
	g, sc, err := srv.ResolveScopes(ctx, 444000111)
	if err != nil {
		t.Fatalf("auto-approve ResolveScopes: %v", err)
	}
	if !has(g, "clients") || has(sc, "admin:users") || !has(sc, "telegram:messages:read") {
		t.Errorf("auto-approved user wrong tier: groups=%v scopes=%v", g, sc)
	}

	// Explicit DB "none" must override auto-approve (ban survives).
	banned := int64(444000222)
	if _, err := srv.store.EnsureUserByTelegramID(ctx, banned, "x", "X"); err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.SetAccessTier(ctx, banned, db.TierNone); err != nil {
		t.Fatalf("set tier none: %v", err)
	}
	if _, sc, err := srv.ResolveScopes(ctx, banned); err != nil || len(sc) != 0 {
		t.Errorf("explicit DB 'none' must override auto-approve: scopes=%v err=%v", sc, err)
	}

	// Admin is still an admin under auto-approve.
	if _, as, err := srv.ResolveScopes(ctx, 210408407); err != nil || !has(as, "admin:users") {
		t.Errorf("admin tier broken under auto-approve: scopes=%v err=%v", as, err)
	}
}

// TestHandleTelegramCallback_AutoApproveMaterializesDBTier confirms the
// callback-time side effect added alongside AutoApproveClients: a fresh
// user's transient client grant is written to the DB on first sign-in, an
// admin-set "none" is never overwritten, and re-sign-in is idempotent.
func TestHandleTelegramCallback_AutoApproveMaterializesDBTier(t *testing.T) {
	ctx := context.Background()

	t.Run("fresh user gets tier=client written on first sign-in", func(t *testing.T) {
		fresh := int64(444000333)
		srv, mux := newEnableTestServer(t, stubLogin(false, nil), func(c *Config) {
			c.AutoApproveClients = true
		})
		telegramCallbackFor(t, srv, mux, fresh)
		tier, err := srv.store.GetAccessTier(ctx, fresh)
		if err != nil {
			t.Fatalf("get access tier: %v", err)
		}
		if tier != db.TierClient {
			t.Fatalf("tier after first sign-in = %q, want %q", tier, db.TierClient)
		}
	})

	t.Run("explicit none is never overwritten", func(t *testing.T) {
		banned := int64(444000444)
		srv, mux := newEnableTestServer(t, stubLogin(false, nil), func(c *Config) {
			c.AutoApproveClients = true
		})
		if _, err := srv.store.EnsureUserByTelegramID(ctx, banned, "banned", "Banned"); err != nil {
			t.Fatalf("ensure user: %v", err)
		}
		if err := srv.store.SetAccessTier(ctx, banned, db.TierNone); err != nil {
			t.Fatalf("set tier none: %v", err)
		}
		telegramCallbackFor(t, srv, mux, banned)
		tier, err := srv.store.GetAccessTier(ctx, banned)
		if err != nil {
			t.Fatalf("get access tier: %v", err)
		}
		if tier != db.TierNone {
			t.Fatalf("tier after sign-in = %q, want %q (must not be overwritten)", tier, db.TierNone)
		}
	})

	// A lookup admin is exempt from the materialization. The write is
	// harmless while the id stays listed -- both ResolveScopes and
	// agentSendGate check LookupAdminTelegramIDs before the client tier --
	// but it turns REMOVAL from the allowlist into a promotion to the full
	// client tier off the persisted row, when an operator rotating the bot
	// out reasonably expects removal to de-provision it. The control leg is
	// the fresh-user subtest above: without it, this would pass even if
	// auto-approve had stopped writing for everyone.
	t.Run("lookup admin is exempt from materialization", func(t *testing.T) {
		lookup := int64(444000666)
		srv, mux := newEnableTestServer(t, stubLogin(false, nil), func(c *Config) {
			c.AutoApproveClients = true
			c.LookupAdminTelegramIDs = map[int64]bool{lookup: true}
		})
		telegramCallbackFor(t, srv, mux, lookup)
		tier, err := srv.store.GetAccessTier(ctx, lookup)
		if err != nil {
			t.Fatalf("get access tier: %v", err)
		}
		if tier != "" {
			t.Fatalf("lookup admin persisted tier %q; removal from TG_LOGIN_LOOKUP_ADMINS would then promote it to the client tier instead of de-provisioning it", tier)
		}
	})

	// Full-admin membership wins over a dual listing here as it does at every
	// other tier site, so a full admin also listed as a lookup admin keeps the
	// normal materialization. Paired with the exemption subtest above: one of
	// the two must fail if the !AdminTelegramIDs guard is added or removed.
	t.Run("full admin also listed as lookup admin still materializes", func(t *testing.T) {
		dual := int64(444000777)
		srv, mux := newEnableTestServer(t, stubLogin(false, nil), func(c *Config) {
			c.AutoApproveClients = true
			c.LookupAdminTelegramIDs = map[int64]bool{dual: true}
			c.AdminTelegramIDs[dual] = true
		})
		telegramCallbackFor(t, srv, mux, dual)
		tier, err := srv.store.GetAccessTier(ctx, dual)
		if err != nil {
			t.Fatalf("get access tier: %v", err)
		}
		if tier != db.TierClient {
			t.Fatalf("dual-listed full admin tier = %q, want %q; full-admin must win over the lookup listing here as it does everywhere else", tier, db.TierClient)
		}
	})

	t.Run("re-sign-in is idempotent", func(t *testing.T) {
		fresh := int64(444000555)
		srv, mux := newEnableTestServer(t, stubLogin(false, nil), func(c *Config) {
			c.AutoApproveClients = true
		})
		telegramCallbackFor(t, srv, mux, fresh)
		telegramCallbackFor(t, srv, mux, fresh)
		tier, err := srv.store.GetAccessTier(ctx, fresh)
		if err != nil {
			t.Fatalf("get access tier: %v", err)
		}
		if tier != db.TierClient {
			t.Fatalf("tier after second sign-in = %q, want %q", tier, db.TierClient)
		}
	})
}

// TestEnableAccess_DBClientRoutedToPhoneScreen confirms a client granted via
// the DB access_tier column (not the env allowlist) is likewise routed into
// the enable_access phone screen, not 302'd past it.
func TestEnableAccess_DBClientRoutedToPhoneScreen(t *testing.T) {
	clientID := int64(888000222)
	srv, mux := newEnableTestServer(t, stubLogin(false, nil))
	ctx := context.Background()
	if _, err := srv.store.EnsureUserByTelegramID(ctx, clientID, "dbclient", "DB Client"); err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.SetAccessTier(ctx, clientID, db.TierClient); err != nil {
		t.Fatalf("set access tier: %v", err)
	}
	rec := telegramCallbackFor(t, srv, mux, clientID)
	if rec.Code != http.StatusOK {
		t.Fatalf("db-client callback = %d (want 200 phone screen); body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "/oauth/telegram/enable_access/start") {
		t.Fatalf("db-client was not routed to the enable_access phone screen; body=%s", rec.Body.String())
	}
}

// TestEnableAccess_TelegramIDMismatch_Rejected confirms that a phone login
// resolving to a different Telegram account than the widget identity is
// rejected, and that the wrong-account session bytes are revoked.
func TestEnableAccess_TelegramIDMismatch_Rejected(t *testing.T) {
	srv, mux := newEnableTestServer(t, stubLoginWrongAccount())
	es := driveToPhone(t, mux)

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}}); rec.Code != http.StatusOK {
		t.Fatalf("start: %d", rec.Code)
	}
	rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("mismatch code step = %d (want 200 phone screen); body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "different Telegram account") {
		t.Errorf("expected an identity-mismatch error, got: %s", rec.Body.String())
	}

	// The wrong-account session bytes must have been revoked, not left valid.
	ctx := context.Background()
	uid, _ := srv.store.EnsureUserByTelegramID(ctx, 210408407, "MashkovD", "Dmitry")
	if _, err := srv.store.CheckSessionValid(ctx, uid); err == nil {
		t.Error("wrong-account session was left valid after the mismatch")
	}
}

// TestResolveScopes_Tiers checks the three identity tiers: admins get
// admin:users, clients (via env OR the DB access_tier column) get the
// telegram:* set without it, and anyone else gets nothing.
func TestResolveScopes_Tiers(t *testing.T) {
	has := func(ss []string, v string) bool {
		for _, s := range ss {
			if s == v {
				return true
			}
		}
		return false
	}
	ctx := context.Background()
	lookupOnlyID := int64(333000111)
	bothID := int64(333000222)
	lookupAndClientID := int64(333000333)
	srv := newTestServer(t, func(c *Config) {
		c.ClientTelegramIDs = map[int64]bool{555000111: true, lookupAndClientID: true}
		c.LookupAdminTelegramIDs = map[int64]bool{
			lookupOnlyID:      true,
			bothID:            true,
			lookupAndClientID: true,
		}
		c.AdminTelegramIDs[bothID] = true
	})

	// Admin tier (210408407 is in newTestServer's AdminTelegramIDs).
	ag, as, err := srv.ResolveScopes(ctx, 210408407)
	if err != nil {
		t.Fatalf("admin ResolveScopes: %v", err)
	}
	if !has(ag, "platform-admins") || !has(as, "admin:users") {
		t.Errorf("admin tier wrong: groups=%v scopes=%v", ag, as)
	}

	// Lookup-admin-only tier: exactly admin:users:read — no telegram:* scopes,
	// and NOT the flat admin:users, which also gates every admin write tool.
	lg, ls, err := srv.ResolveScopes(ctx, lookupOnlyID)
	if err != nil {
		t.Fatalf("lookup-admin ResolveScopes: %v", err)
	}
	if !has(lg, "admin-lookup") {
		t.Errorf("lookup-admin groups = %v, want to contain admin-lookup", lg)
	}
	if len(ls) != 1 || ls[0] != "admin:users:read" {
		t.Errorf("lookup-admin scopes = %v, want exactly [admin:users:read]", ls)
	}
	for _, forbidden := range []string{
		"telegram:dialogs:read", "telegram:messages:read",
		"telegram:messages:send", "telegram:messages:pin",
		// The flat admin:users is forbidden too, not merely absent: it
		// gates set_telegram_access, set_account_send, set_account_mode,
		// provision_local_account, revoke_telegram_session,
		// revoke_worker_token and mint_worker_token. Granting it here
		// would make "lookup-only" a full admin write grant.
		"admin:users", "account:manage",
	} {
		if has(ls, forbidden) {
			t.Errorf("lookup-admin must not receive %s (got %v)", forbidden, ls)
		}
	}

	// An id in BOTH AdminTelegramIDs and LookupAdminTelegramIDs resolves
	// identically to the full-admin-only case (full-admin takes precedence).
	bg, bs, err := srv.ResolveScopes(ctx, bothID)
	if err != nil {
		t.Fatalf("both-tiers ResolveScopes: %v", err)
	}
	if !has(bg, "platform-admins") || !has(bg, "admins") {
		t.Errorf("both-tiers groups = %v, want the full-admin groups", bg)
	}
	if len(bs) != len(as) {
		t.Errorf("both-tiers scopes = %v, want the same bundle as full-admin %v", bs, as)
	}
	for _, want := range as {
		if !has(bs, want) {
			t.Errorf("both-tiers missing scope %s from full-admin bundle (got %v)", want, bs)
		}
	}

	// Client tier via the TG_LOGIN_CLIENTS env allowlist.
	cg, cs, err := srv.ResolveScopes(ctx, 555000111)
	if err != nil {
		t.Fatalf("env-client ResolveScopes: %v", err)
	}
	if !has(cg, "clients") {
		t.Errorf("env-client groups = %v, want [clients]", cg)
	}
	if has(cs, "admin:users") {
		t.Error("client must not receive admin:users")
	}
	for _, want := range []string{
		"telegram:dialogs:read", "telegram:messages:read",
		"telegram:messages:send", "telegram:messages:pin",
	} {
		if !has(cs, want) {
			t.Errorf("client missing scope %s (got %v)", want, cs)
		}
	}

	// Client tier via the DB access_tier='client' column.
	dbID := int64(777000222)
	if _, err := srv.store.EnsureUserByTelegramID(ctx, dbID, "dbclient", "DB Client"); err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.SetAccessTier(ctx, dbID, db.TierClient); err != nil {
		t.Fatalf("set access tier: %v", err)
	}
	dg, ds, err := srv.ResolveScopes(ctx, dbID)
	if err != nil {
		t.Fatalf("db-client ResolveScopes: %v", err)
	}
	if !has(dg, "clients") || has(ds, "admin:users") {
		t.Errorf("db-client tier wrong: groups=%v scopes=%v", dg, ds)
	}

	// Neither tier — no scopes at all.
	ng, ns, err := srv.ResolveScopes(ctx, 999999999)
	if err != nil {
		t.Fatalf("unknown ResolveScopes: %v", err)
	}
	if len(ng) != 0 || len(ns) != 0 {
		t.Errorf("unknown id got groups=%v scopes=%v, want empty", ng, ns)
	}
	// Lookup-admin membership wins over the client tier for an id in both.
	// Pins the precedence documented on ResolveScopes: the bundles do not
	// combine, and a dual-listed id keeps no telegram:* scope. Without this,
	// swapping the two checks would be a silent scope grant.
	lcg, lcs, err := srv.ResolveScopes(ctx, lookupAndClientID)
	if err != nil {
		t.Fatalf("lookup+client ResolveScopes: %v", err)
	}
	if !has(lcs, "admin:users:read") {
		t.Fatalf("lookup+client scopes = %v, want admin:users:read", lcs)
	}
	if has(lcs, "admin:users") {
		t.Fatalf("lookup+client scopes = %v, must not carry the flat admin:users", lcs)
	}
	for _, sc := range []string{"telegram:dialogs:read", "telegram:messages:read", "telegram:messages:send", "account:manage"} {
		if has(lcs, sc) {
			t.Fatalf("lookup+client scopes = %v, must not carry %s (client tier must not merge in)", lcs, sc)
		}
	}
	if !has(lcg, "admin-lookup") {
		t.Fatalf("lookup+client groups = %v, want admin-lookup", lcg)
	}
	if has(lcg, "clients") {
		t.Fatalf("lookup+client groups = %v, must not carry clients", lcg)
	}
}

func TestFinishEnable_WritesClientTierForNonAdmin(t *testing.T) {
	srv, _ := newEnableTestServer(t, nil, func(c *Config) {
		c.AutoApproveClients = true
	})
	ctx := context.Background()
	const tgID int64 = 424242
	uid, err := srv.store.EnsureUserByTelegramID(ctx, tgID, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	srv.finishEnable(rec, req, &enableSession{
		uid:  uid,
		tgID: tgID,
		oc: oauthCtx{
			ClientID:    "claude.ai",
			RedirectURI: "https://claude.ai/cb",
			TelegramID:  tgID,
			Username:    "bob",
		},
	}, "es-tok")
	tier, err := srv.store.GetAccessTier(ctx, tgID)
	if err != nil {
		t.Fatalf("GetAccessTier: %v", err)
	}
	if tier != db.TierClient {
		t.Fatalf("tier after finishEnable = %q, want %q", tier, db.TierClient)
	}
}

func TestFinishEnable_PreservesExplicitNone(t *testing.T) {
	srv, _ := newEnableTestServer(t, nil, func(c *Config) {
		c.AutoApproveClients = true
	})
	ctx := context.Background()
	const tgID int64 = 424243
	uid, err := srv.store.EnsureUserByTelegramID(ctx, tgID, "banned", "Banned")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.SetAccessTier(ctx, tgID, db.TierNone); err != nil {
		t.Fatalf("seed none: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	srv.finishEnable(rec, req, &enableSession{
		uid:  uid,
		tgID: tgID,
		oc: oauthCtx{
			ClientID:    "claude.ai",
			RedirectURI: "https://claude.ai/cb",
			TelegramID:  tgID,
			Username:    "banned",
		},
	}, "es-none")
	tier, err := srv.store.GetAccessTier(ctx, tgID)
	if err != nil {
		t.Fatalf("GetAccessTier: %v", err)
	}
	if tier != db.TierNone {
		t.Fatalf("tier after finishEnable = %q, want %q", tier, db.TierNone)
	}
}

func TestFinishEnable_EnvListedClientStaysRevocable(t *testing.T) {
	ctx := context.Background()
	const tgID int64 = 555000111
	srv, _ := newEnableTestServer(t, nil, func(c *Config) {
		c.AutoApproveClients = false
		c.ClientTelegramIDs = map[int64]bool{tgID: true}
	})
	uid, err := srv.store.EnsureUserByTelegramID(ctx, tgID, "envclient", "Env Client")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	srv.finishEnable(rec, req, &enableSession{
		uid:  uid,
		tgID: tgID,
		oc: oauthCtx{
			ClientID:    "claude.ai",
			RedirectURI: "https://claude.ai/cb",
			TelegramID:  tgID,
			Username:    "envclient",
		},
	}, "es-env")
	tier, err := srv.store.GetAccessTier(ctx, tgID)
	if err != nil {
		t.Fatalf("GetAccessTier: %v", err)
	}
	if tier != "" {
		t.Fatalf("tier after finishEnable = %q, want unset so TG_LOGIN_CLIENTS stays revocable", tier)
	}
	ok, err := srv.isClientTier(ctx, tgID)
	if err != nil {
		t.Fatalf("isClientTier while listed: %v", err)
	}
	if !ok {
		t.Fatal("env-listed client must still resolve as client while in TG_LOGIN_CLIENTS")
	}
	delete(srv.cfg.ClientTelegramIDs, tgID)
	ok, err = srv.isClientTier(ctx, tgID)
	if err != nil {
		t.Fatalf("isClientTier after removal: %v", err)
	}
	if ok {
		t.Fatal("removing id from TG_LOGIN_CLIENTS after connect must revoke client tier")
	}
	_, scopes, err := srv.ResolveScopes(ctx, tgID)
	if err != nil {
		t.Fatalf("ResolveScopes after removal: %v", err)
	}
	if len(scopes) != 0 {
		t.Fatalf("scopes after TG_LOGIN_CLIENTS removal = %v, want empty", scopes)
	}
}

func TestFinishEnable_SkipsAdminAndLookupAdmin(t *testing.T) {
	const lookupID int64 = 555001
	srv, _ := newEnableTestServer(t, nil, func(c *Config) {
		c.LookupAdminTelegramIDs = map[int64]bool{lookupID: true}
	})
	ctx := context.Background()

	adminID := int64(210408407)
	adminUID, err := srv.store.EnsureUserByTelegramID(ctx, adminID, "admin", "Admin")
	if err != nil {
		t.Fatalf("ensure admin: %v", err)
	}
	lookupUID, err := srv.store.EnsureUserByTelegramID(ctx, lookupID, "lookup", "Lookup")
	if err != nil {
		t.Fatalf("ensure lookup: %v", err)
	}

	for _, tc := range []struct {
		name string
		uid  int64
		tgID int64
	}{
		{"full admin", adminUID, adminID},
		{"lookup admin", lookupUID, lookupID},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		srv.finishEnable(rec, req, &enableSession{
			uid:  tc.uid,
			tgID: tc.tgID,
			oc: oauthCtx{
				ClientID:    "claude.ai",
				RedirectURI: "https://claude.ai/cb",
				TelegramID:  tc.tgID,
			},
		}, "es-"+tc.name)
		tier, err := srv.store.GetAccessTier(ctx, tc.tgID)
		if err != nil {
			t.Fatalf("%s GetAccessTier: %v", tc.name, err)
		}
		if tier != "" {
			t.Fatalf("%s tier after finishEnable = %q, want unset", tc.name, tier)
		}
	}
}

func TestFinishEnable_SetAccessTierErrorIsNonFatal(t *testing.T) {
	srv, _ := newEnableTestServer(t, nil, func(c *Config) {
		c.AutoApproveClients = true
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	// No users row: SetAccessTier fails. The auth-code redirect must still happen.
	srv.finishEnable(rec, req, &enableSession{
		uid:  1,
		tgID: 999001,
		oc: oauthCtx{
			ClientID:    "claude.ai",
			RedirectURI: "https://claude.ai/cb",
			TelegramID:  999001,
		},
	}, "es-missing")
	if rec.Code != http.StatusFound && rec.Code != http.StatusOK {
		t.Fatalf("finishEnable status = %d, want a successful handoff despite SetAccessTier failure", rec.Code)
	}
}
