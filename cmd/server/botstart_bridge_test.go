package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/bot"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

func TestMountBotStartBridge(t *testing.T) {
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
	m := metrics.New()

	post := func(mux http.Handler) int {
		req := httptest.NewRequest(http.MethodPost, bot.BotStartObservationPath, strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}

	for name, token := range map[string]string{
		"unset": "",
		"short": strings.Repeat("a", bot.MinBridgeTokenLen-1),
	} {
		mux := chi.NewRouter()
		if mountBotStartBridge(mux, store, m, token) {
			t.Errorf("%s token: bridge reported mounted", name)
		}
		if code := post(mux); code != http.StatusNotFound {
			t.Errorf("%s token: status = %d, want 404 (route absent)", name, code)
		}
	}

	mux := chi.NewRouter()
	if !mountBotStartBridge(mux, store, m, strings.Repeat("a", bot.MinBridgeTokenLen)) {
		t.Fatal("valid token: bridge not mounted")
	}
	// Mounted, and guarded by its own auth rather than open.
	if code := post(mux); code != http.StatusUnauthorized {
		t.Errorf("valid token, unauthenticated call: status = %d, want 401", code)
	}
}
