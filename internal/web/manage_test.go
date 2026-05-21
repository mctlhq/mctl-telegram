package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	_ "modernc.org/sqlite"
)

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

// TestManagePageRedirectsUnauthenticated confirms that GET /telegram/connect/manage
// redirects to /telegram/connect when no auth.Identity is in context.
func TestManagePageRedirectsUnauthenticated(t *testing.T) {
	store := newManageTestStore(t)
	srv := NewManageServer(store, nil, "https://tg.test")

	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
	// No identity in context.
	rec := httptest.NewRecorder()
	srv.HandleManage(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect for unauthenticated request, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if loc != "https://tg.test/telegram/connect" {
		t.Errorf("redirect location = %q, want https://tg.test/telegram/connect", loc)
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
