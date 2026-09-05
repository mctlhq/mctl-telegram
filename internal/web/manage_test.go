package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	_ "modernc.org/sqlite"
)

type stubManageProvider struct {
	id  *auth.Identity
	err error
}

func (p stubManageProvider) Authenticate(*http.Request) (*auth.Identity, error) {
	return p.id, p.err
}

func manageThroughAuth(t *testing.T, srv *ManageServer, p auth.Provider) http.Handler {
	t.Helper()
	return auth.MiddlewareWithHTML(p, true, nil, auth.ResourceMetadata{BaseURL: "https://tg.test"}, srv.WriteUnauthorized)(
		http.HandlerFunc(srv.HandleManage),
	)
}

func newManageTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "manage.db") + "?_pragma=busy_timeout(5000)"
	conn, err := db.Open(ctx, dsn, 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	crypt, err := crypto.New(nil)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	return db.NewStore(conn, crypt)
}

// TestManagePageUnauthenticatedHTML confirms that a browser GET without an
// identity gets an HTML sign-in page (not raw JSON) pointing at the hosted
// connect wizard, with a Local Bridge alternative.
func TestManagePageUnauthenticatedHTML(t *testing.T) {
	store := newManageTestStore(t)
	srv := NewManageServer(store, nil, "https://tg.test")

	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := httptest.NewRecorder()
	srv.HandleManage(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated request, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if strings.Contains(body, `{"error"`) {
		t.Fatalf("browser navigation must not see raw JSON; body=%s", body)
	}
	if !strings.Contains(body, "Sign in to manage your session") {
		t.Errorf("missing sign-in heading; body=%s", body)
	}
	if !strings.Contains(body, "https://tg.test/telegram/connect") {
		t.Errorf("missing hosted connect CTA; body=%s", body)
	}
	if !strings.Contains(body, "https://tg.test/docs/local-bridge") {
		t.Errorf("missing Local Bridge docs link; body=%s", body)
	}
	if !strings.Contains(body, "https://tg.test/local-bridge/activate") {
		t.Errorf("missing Local Bridge activate link; body=%s", body)
	}
}

func TestManagePageUnauthenticatedJSON(t *testing.T) {
	store := newManageTestStore(t)
	srv := NewManageServer(store, nil, "https://tg.test")

	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	srv.HandleManage(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("JSON body: %v; body=%s", err, rec.Body.String())
	}
	if got["error"] != "authentication required" {
		t.Errorf("error = %q, want authentication required", got["error"])
	}
}

// TestManagePageShowsSession confirms that a connected user sees their
// session details on the manage page.
func TestManagePageShowsSession(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)

	uid, err := store.EnsureUser(ctx, "alice", "", "test")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, display_name, username, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7)`,
		uid, int64(12345), "Alice Test", "alicetest", []byte("blob"), now, now.Add(24*time.Hour),
	); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	srv := NewManageServer(store, nil, "https://tg.test")

	id := &auth.Identity{UserID: uid}
	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
	req = req.WithContext(auth.With(req.Context(), id))
	rec := httptest.NewRecorder()
	srv.HandleManage(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for authenticated request, got %d; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Alice Test") {
		t.Errorf("display_name not shown on manage page; body=%s", body)
	}
}

// TestHandleDisconnect_ClearsCookieAndRedirects confirms that a successful
// disconnect (a) clears the mctl_connect_token cookie with the matching
// Path / HttpOnly / SameSite shape and Max-Age=0, and (b) redirects to
// /telegram/connect rather than back to /telegram/connect/manage.
func TestHandleDisconnect_ClearsCookieAndRedirects(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)

	uid, err := store.EnsureUser(ctx, "bob", "", "test")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, display_name, username, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7)`,
		uid, int64(99), "Bob", "bob", []byte("x"), now, now.Add(time.Hour),
	); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	srv := NewManageServer(store, nil, "https://tg.test")
	id := &auth.Identity{UserID: uid}
	req := httptest.NewRequest(http.MethodPost, "/telegram/connect/manage/disconnect", nil)
	req = req.WithContext(auth.With(req.Context(), id))
	rec := httptest.NewRecorder()
	srv.HandleDisconnect(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://tg.test/telegram/connect" {
		t.Errorf("redirect location = %q, want https://tg.test/telegram/connect", loc)
	}
	cookie := rec.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "mctl_connect_token=") {
		t.Errorf("Set-Cookie missing mctl_connect_token: %q", cookie)
	}
	if !strings.Contains(cookie, "Max-Age=0") {
		t.Errorf("Set-Cookie not clearing cookie (Max-Age=0 absent): %q", cookie)
	}
	if !strings.Contains(cookie, "Path=/telegram/connect") {
		t.Errorf("Set-Cookie Path must match the set-cookie shape from HandleConnectDone: %q", cookie)
	}
}

func TestManageMiddleware_BrowserNoTokenGetsHTML(t *testing.T) {
	store := newManageTestStore(t)
	srv := NewManageServer(store, nil, "https://tg.test")
	h := manageThroughAuth(t, srv, stubManageProvider{})

	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, `Bearer realm="mctl-telegram"`) {
		t.Errorf("WWW-Authenticate = %q, want Bearer challenge", got)
	}
	body := rec.Body.String()
	if strings.Contains(body, `{"error"`) {
		t.Fatalf("browser 401 must be HTML, not JSON; body=%s", body)
	}
	if !strings.Contains(body, "https://tg.test/telegram/connect") {
		t.Errorf("missing connect CTA; body=%s", body)
	}
}

func TestManageMiddleware_InvalidCookieBrowserGetsHTML(t *testing.T) {
	store := newManageTestStore(t)
	srv := NewManageServer(store, nil, "https://tg.test")
	h := manageThroughAuth(t, srv, stubManageProvider{err: errors.New("JWT expired")})

	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "mctl_connect_token", Value: "expired-or-garbage"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	body := rec.Body.String()
	if strings.Contains(body, `{"error":"invalid credentials"}`) {
		t.Fatalf("browser must not see raw invalid-credentials JSON; body=%s", body)
	}
	if !strings.Contains(body, "expired, or invalid") {
		t.Errorf("invalid session copy missing; body=%s", body)
	}
	if !strings.Contains(body, "https://tg.test/docs/local-bridge") {
		t.Errorf("missing Local Bridge alternative; body=%s", body)
	}
}

func TestManageMiddleware_APIClientsKeepJSON(t *testing.T) {
	store := newManageTestStore(t)
	srv := NewManageServer(store, nil, "https://tg.test")
	h := manageThroughAuth(t, srv, stubManageProvider{err: errors.New("JWT expired")})

	cases := []struct {
		name   string
		accept string
		xhr    string
	}{
		{name: "accept json", accept: "application/json"},
		{name: "empty accept", accept: ""},
		{name: "star accept", accept: "*/*"},
		{name: "xhr", accept: "text/html", xhr: "XMLHttpRequest"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
			if c.accept != "" {
				req.Header.Set("Accept", c.accept)
			}
			if c.xhr != "" {
				req.Header.Set("X-Requested-With", c.xhr)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			var got map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
				t.Fatalf("JSON: %v; body=%s", err, rec.Body.String())
			}
			if got["error"] != "invalid credentials" {
				t.Errorf("error = %q, want invalid credentials", got["error"])
			}
		})
	}
}

func TestManageMiddleware_AuthenticatedStillRendersDashboard(t *testing.T) {
	ctx := context.Background()
	store := newManageTestStore(t)

	uid, err := store.EnsureUser(ctx, "carol", "", "test")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, display_name, username, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7)`,
		uid, int64(777), "Carol Test", "caroltest", []byte("blob"), now, now.Add(24*time.Hour),
	); err != nil {
		t.Fatalf("seed session: %v", err)
	}

	srv := NewManageServer(store, nil, "https://tg.test")
	id := &auth.Identity{UserID: uid}
	h := manageThroughAuth(t, srv, stubManageProvider{id: id})

	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for authenticated request, got %d; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Carol Test") {
		t.Errorf("display_name not shown; body=%s", body)
	}
	if !strings.Contains(body, "Disable send") && !strings.Contains(body, "Enable send") {
		t.Errorf("send toggle missing; body=%s", body)
	}
	if !strings.Contains(body, "Disconnect") {
		t.Errorf("disconnect control missing; body=%s", body)
	}
}

func TestManageDisconnectUnauthenticatedHTML(t *testing.T) {
	store := newManageTestStore(t)
	srv := NewManageServer(store, nil, "https://tg.test")

	req := httptest.NewRequest(http.MethodPost, "/telegram/connect/manage/disconnect", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	srv.HandleDisconnect(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
}

func TestManageToggleSendUnauthenticatedHTML(t *testing.T) {
	store := newManageTestStore(t)
	srv := NewManageServer(store, nil, "https://tg.test")

	req := httptest.NewRequest(http.MethodPost, "/telegram/connect/manage/toggle-send", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	srv.HandleToggleSend(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("Location = %q, want no redirect for an unauthenticated caller", loc)
	}
}

// The three manage routes negotiate their 401 body on Accept and
// X-Requested-With, so both representations must be declared to caches.
func TestManageUnauthorizedSetsNegotiationVary(t *testing.T) {
	store := newManageTestStore(t)
	srv := NewManageServer(store, nil, "https://tg.test")

	for _, accept := range []string{"text/html", "application/json"} {
		req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
		req.Header.Set("Accept", accept)
		rec := httptest.NewRecorder()
		srv.HandleManage(rec, req)

		wantExactNegotiationVary(t, rec.Header(), "Accept "+accept)
	}
}

// InvalidSession picks the "expired session" copy off the reason the auth
// package passes, so the two 401 reasons must render different pages.
func TestManageUnauthorizedReasonSelectsCopy(t *testing.T) {
	store := newManageTestStore(t)
	srv := NewManageServer(store, nil, "https://tg.test")

	render := func(msg string) string {
		req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
		req.Header.Set("Accept", "text/html")
		rec := httptest.NewRecorder()
		srv.WriteUnauthorized(rec, req, http.StatusUnauthorized, msg)
		return rec.Body.String()
	}

	if body := render(auth.MsgInvalidCredentials); !strings.Contains(body, "expired, or invalid") {
		t.Fatalf("MsgInvalidCredentials rendered the wrong copy: %s", body)
	}
	if body := render(auth.MsgAuthRequired); !strings.Contains(body, "need to connect a Telegram account") {
		t.Fatalf("MsgAuthRequired rendered the wrong copy: %s", body)
	}
}

// varyTokens flattens the Vary header into its individual field names.
// Asserting on this rather than substring-matching the raw values matters
// twice over: "Accept-Encoding" contains "Accept", and a duplicated append
// is invisible to a Contains check.
func varyTokens(h http.Header) []string {
	var out []string
	for _, v := range h.Values("Vary") {
		for _, tok := range strings.Split(v, ",") {
			if tok = strings.TrimSpace(tok); tok != "" {
				out = append(out, http.CanonicalHeaderKey(tok))
			}
		}
	}
	return out
}

func wantExactNegotiationVary(t *testing.T, h http.Header, ctx string) {
	t.Helper()
	got := varyTokens(h)
	want := []string{"Accept", "X-Requested-With"}
	if !slices.Equal(got, want) {
		t.Fatalf("%s: Vary = %v, want exactly %v", ctx, got, want)
	}
}
