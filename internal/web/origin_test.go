package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOriginGuard(t *testing.T) {
	allowed := []string{"https://tg.mctl.ai"}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	guard := OriginGuard(next, allowed)

	cases := []struct {
		name   string
		origin string // "" means header omitted
		want   int
	}{
		{"no origin (server-to-server) allowed", "", http.StatusOK},
		{"allowed origin", "https://tg.mctl.ai", http.StatusOK},
		{"allowed origin trailing slash", "https://tg.mctl.ai/", http.StatusOK},
		{"allowed origin case-insensitive", "https://TG.MCTL.AI", http.StatusOK},
		{"disallowed origin rejected", "https://evil.example", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			guard.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("origin %q: got %d, want %d", tc.origin, rec.Code, tc.want)
			}
		})
	}
}

func TestOriginGuardEmptyAllowlistAllowsAll(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	guard := OriginGuard(next, nil)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Origin", "https://anything.example")
	rec := httptest.NewRecorder()
	guard.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty allowlist should allow all, got %d", rec.Code)
	}
}
