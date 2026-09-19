package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func newAccountTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.NewStore(conn, nil)
}

func newAccountTestRouter(t *testing.T, store *db.Store) *chi.Mux {
	t.Helper()
	h := NewAccountHandlers(store, nil)
	mux := chi.NewRouter()
	h.Register(mux)
	return mux
}

func withIdentity(req *http.Request, uid int64) *http.Request {
	return req.WithContext(auth.With(req.Context(), &auth.Identity{UserID: uid}))
}

// TestGetNotifications_Anonymous401 matches the existing AccountHandlers
// behaviour: an anonymous request gets 401, not a default-preferences body.
func TestGetNotifications_Anonymous401(t *testing.T) {
	store := newAccountTestStore(t)
	mux := newAccountTestRouter(t, store)

	req := httptest.NewRequest(http.MethodGet, "/notifications", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

// TestGetNotifications_ReturnsDefaults asserts GET returns the resolved
// defaults for a user with no explicit preferences.
func TestGetNotifications_ReturnsDefaults(t *testing.T) {
	ctx := context.Background()
	store := newAccountTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	mux := newAccountTestRouter(t, store)

	req := withIdentity(httptest.NewRequest(http.MethodGet, "/notifications", nil), uid)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Categories []db.ResolvedPref `json:"categories"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Categories) != 3 {
		t.Fatalf("got %d categories, want 3", len(body.Categories))
	}
	for _, p := range body.Categories {
		if p.Explicit {
			t.Errorf("%s: Explicit = true, want false (no writes yet)", p.Category)
		}
	}
}

// TestPutNotifications_UnauthenticatedIs401 matches T11's anonymous case.
func TestPutNotifications_UnauthenticatedIs401(t *testing.T) {
	store := newAccountTestStore(t)
	mux := newAccountTestRouter(t, store)

	body := bytes.NewBufferString(`{"product_updates":"unsubscribed"}`)
	req := httptest.NewRequest(http.MethodPut, "/notifications", body)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", rec.Code, rec.Body.String())
	}
}

// TestPutNotifications_PartialUpdate is T10/T11: writing only
// product_updates leaves maintenance/security untouched, and the response
// reflects the resolved state.
func TestPutNotifications_PartialUpdate(t *testing.T) {
	ctx := context.Background()
	store := newAccountTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	mux := newAccountTestRouter(t, store)

	body := bytes.NewBufferString(`{"product_updates":"unsubscribed"}`)
	req := withIdentity(httptest.NewRequest(http.MethodPut, "/notifications", body), uid)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	prefs, err := store.ResolveNotificationPrefs(ctx, uid)
	if err != nil {
		t.Fatalf("ResolveNotificationPrefs: %v", err)
	}
	for _, p := range prefs {
		switch p.Category {
		case string(db.CategoryProductUpdates):
			if !p.Explicit || p.State != db.PrefUnsubscribed {
				t.Errorf("product_updates = %+v, want explicit unsubscribed", p)
			}
			if p.Source != "account_api" {
				t.Errorf("product_updates source = %q, want account_api", p.Source)
			}
		default:
			if p.Explicit {
				t.Errorf("%s became explicit after a product_updates-only PUT", p.Category)
			}
		}
	}
}

// TestPutNotifications_UnknownCategoryIs400AndWritesNothing is T11's
// validation case at the HTTP layer.
func TestPutNotifications_UnknownCategoryIs400AndWritesNothing(t *testing.T) {
	ctx := context.Background()
	store := newAccountTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	mux := newAccountTestRouter(t, store)

	body := bytes.NewBufferString(`{"bogus_category":"subscribed"}`)
	req := withIdentity(httptest.NewRequest(http.MethodPut, "/notifications", body), uid)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}

	prefs, err := store.ResolveNotificationPrefs(ctx, uid)
	if err != nil {
		t.Fatalf("ResolveNotificationPrefs: %v", err)
	}
	for _, p := range prefs {
		if p.Explicit {
			t.Errorf("%s became explicit despite the request being rejected", p.Category)
		}
	}
}

// TestPutNotifications_UnknownStateIs400 is the state-validation half.
func TestPutNotifications_UnknownStateIs400(t *testing.T) {
	ctx := context.Background()
	store := newAccountTestStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	mux := newAccountTestRouter(t, store)

	body := bytes.NewBufferString(`{"security":"maybe"}`)
	req := withIdentity(httptest.NewRequest(http.MethodPut, "/notifications", body), uid)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}
