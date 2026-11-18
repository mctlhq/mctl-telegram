package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
)

const testPASecret = "pa_webhook_secret_for_tests_only_0123456789"

// TestMountPA_InertByDefault: with PA_ENABLED unset (Load's fail-closed
// default) no PA route is registered at all, and with it on exactly the
// webhook appears.
func TestMountPA_InertByDefault(t *testing.T) {
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+t.Name()+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(conn, nil)

	paRoutes := func(mux *chi.Mux) []string {
		var found []string
		_ = chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
			if strings.HasPrefix(route, "/pa") {
				found = append(found, method+" "+route)
			}
			return nil
		})
		return found
	}
	post := func(mux http.Handler) int {
		req := httptest.NewRequest(http.MethodPost, pa.WebhookPath, strings.NewReader(`{}`))
		req.Header.Set(pa.SecretHeader, testPASecret)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PAEnabled {
		t.Fatal("PA_ENABLED unset loaded as enabled")
	}
	mux := chi.NewRouter()
	mounted, err := mountPA(mux, cfg, store)
	if err != nil || mounted {
		t.Fatalf("PA_ENABLED unset: mounted=%v err=%v, want false nil", mounted, err)
	}
	if r := paRoutes(mux); len(r) != 0 {
		t.Fatalf("PA_ENABLED unset: routes %v registered", r)
	}
	if code := post(mux); code != http.StatusNotFound {
		t.Fatalf("PA_ENABLED unset: status = %d, want 404", code)
	}

	on := &config.Config{PAEnabled: true, PAWebhookSecret: testPASecret, PABotToken: "7000000001:pa-test-token-not-real"}
	mux = chi.NewRouter()
	mounted, err = mountPA(mux, on, store)
	if err != nil || !mounted {
		t.Fatalf("PA_ENABLED on: mounted=%v err=%v", mounted, err)
	}
	if r := paRoutes(mux); len(r) != 1 || r[0] != "POST "+pa.WebhookPath {
		t.Fatalf("PA_ENABLED on: routes = %v", r)
	}
	if code := post(mux); code != http.StatusOK {
		t.Fatalf("PA_ENABLED on: status = %d, want 200 (malformed update dropped)", code)
	}
}
