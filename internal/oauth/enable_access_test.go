package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	_ "modernc.org/sqlite"
)

// newEnableTestStore returns a Store backed by a per-test temp-file SQLite DB
// (real isolation between tests) with a non-nil plaintext-mode crypto, so the
// SaveSession / LoadSession calls the login goroutine makes do not nil-panic.
func newEnableTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "enable.db") + "?_pragma=busy_timeout(5000)"
	conn, err := db.Open(ctx, dsn)
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
	if _, err := srv.store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, last_used_at, expires_at)
		 VALUES($1, $2, $3, $4)`,
		uid, []byte("seed-session"), now, now.Add(24*time.Hour),
	); err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func newEnableTestServer(t *testing.T, login LoginFunc) (*Server, *chi.Mux) {
	t.Helper()
	srv, err := New(Config{
		Issuer:              testIssuer,
		JWTSecret:           testJWTSecret,
		BotToken:            testBotToken,
		BotUsername:         testBotUsername,
		AdminTelegramIDs:    map[int64]bool{210408407: true},
		AccessTokenTTL:      time.Hour,
		CodeTTL:             time.Minute,
		AllowImplicitClient: true,
		TGAPIID:             99999,
		TGAPIHash:           "test-api-hash",
	}, newEnableTestStore(t))
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

// driveToPhone runs /oauth/authorize then the widget callback for an admin with
// no session, and returns the "es" token from the rendered phone screen.
func driveToPhone(t *testing.T, mux *chi.Mux) string {
	t.Helper()
	_, challenge := pkceVerifierAndChallenge()
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
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize = %d", rec.Code)
	}
	serverState := extractInputValue(t, rec.Body.String(), "st")

	now := time.Now()
	fields := map[string]string{
		"id":         "210408407",
		"username":   "MashkovD",
		"first_name": "Dmitry",
		"auth_date":  strconv.FormatInt(now.Unix(), 10),
	}
	fields["hash"] = signWidget(t, fields)
	form := url.Values{"st": {serverState}}
	for k, v := range fields {
		form.Set(k, v)
	}
	rec = postForm(t, mux, "/oauth/telegram/callback", form)
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

	// Code → 302 back to the client with an authorization code.
	rec = postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("code step = %d (want 302); body=%s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Host != "claude.ai" || loc.Query().Get("code") == "" {
		t.Fatalf("bad redirect: %v %v", rec.Header().Get("Location"), err)
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

	// Password → 302.
	rec = postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {es}, "password": {"hunter2"}})
	if rec.Code != http.StatusFound {
		t.Fatalf("password step = %d (want 302); body=%s", rec.Code, rec.Body.String())
	}
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
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/code",
		url.Values{"es": {es}, "code": {"12345"}}); rec.Code != http.StatusFound {
		t.Fatalf("code step = %d", rec.Code)
	}
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

// TestEnableAccess_NonAdminSkipsFlow confirms a non-admin widget login gets the
// authorization code directly, never the enable_access phone screen.
func TestEnableAccess_NonAdminSkipsFlow(t *testing.T) {
	_, mux := newEnableTestServer(t, stubLogin(false, nil))
	_, challenge := pkceVerifierAndChallenge()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"claude.ai"},
		"redirect_uri":          {"https://claude.ai/cb"},
		"state":                 {"s"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	serverState := extractInputValue(t, rec.Body.String(), "st")

	now := time.Now()
	fields := map[string]string{
		"id":         "999000111", // not in AdminTelegramIDs
		"username":   "rando",
		"first_name": "Rando",
		"auth_date":  strconv.FormatInt(now.Unix(), 10),
	}
	fields["hash"] = signWidget(t, fields)
	form := url.Values{"st": {serverState}}
	for k, v := range fields {
		form.Set(k, v)
	}
	rec = postForm(t, mux, "/oauth/telegram/callback", form)
	if rec.Code != http.StatusFound {
		t.Fatalf("non-admin callback = %d (want 302 straight to code); body=%s", rec.Code, rec.Body.String())
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
// admin:users, clients get the telegram:* set without it, and anyone else
// gets nothing.
func TestResolveScopes_Tiers(t *testing.T) {
	has := func(ss []string, v string) bool {
		for _, s := range ss {
			if s == v {
				return true
			}
		}
		return false
	}
	srv := newTestServer(t, func(c *Config) {
		c.ClientTelegramIDs = map[int64]bool{555000111: true}
	})

	// Admin tier (210408407 is in newTestServer's AdminTelegramIDs).
	ag, as := srv.ResolveScopes(210408407)
	if !has(ag, "platform-admins") || !has(as, "admin:users") {
		t.Errorf("admin tier wrong: groups=%v scopes=%v", ag, as)
	}

	// Client tier — telegram:* scopes but NOT admin:users.
	cg, cs := srv.ResolveScopes(555000111)
	if !has(cg, "clients") {
		t.Errorf("client groups = %v, want [clients]", cg)
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

	// Neither tier — no scopes at all.
	ng, ns := srv.ResolveScopes(999999999)
	if len(ng) != 0 || len(ns) != 0 {
		t.Errorf("unknown id got groups=%v scopes=%v, want empty", ng, ns)
	}
}
