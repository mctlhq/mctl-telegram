package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
)

func TestHealthServer_RoutesReflectHealthState(t *testing.T) {
	health := &agentworker.Health{}
	srv := newHealthServer(":0", health)
	mux := srv.Handler

	// Before any poll: alive (nothing marked stopped) but not ready.
	assertStatus(t, mux, "/livez", http.StatusOK)
	assertStatus(t, mux, "/healthz", http.StatusOK)
	assertStatus(t, mux, "/readyz", http.StatusServiceUnavailable)

	health.SetPollResult(true)
	assertStatus(t, mux, "/readyz", http.StatusOK)

	health.SetStopped()
	assertStatus(t, mux, "/livez", http.StatusServiceUnavailable)
	assertStatus(t, mux, "/healthz", http.StatusServiceUnavailable)
}

func assertStatus(t *testing.T, h http.Handler, path string, want int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Errorf("%s: status = %d, want %d", path, rec.Code, want)
	}
}
