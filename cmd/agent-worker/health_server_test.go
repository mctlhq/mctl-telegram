package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

func TestHealthServer_RoutesReflectHealthState(t *testing.T) {
	health := &agentworker.Health{}
	srv := newHealthServer(":0", health, metrics.New(), "test-domain", "")
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

// TestHealthServer_ProbeBodiesCarryCredentialDomainID covers T11: both
// probe bodies must still start with ok/not ok (Content-Type unchanged) and
// now also contain a second line naming the credential domain.
func TestHealthServer_ProbeBodiesCarryCredentialDomainID(t *testing.T) {
	health := &agentworker.Health{}
	srv := newHealthServer(":0", health, metrics.New(), "acct-42", "")
	mux := srv.Handler

	for _, path := range []string{"/livez", "/healthz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
			t.Fatalf("%s: Content-Type = %q, unchanged contract violated", path, ct)
		}
		body := rec.Body.String()
		if !strings.HasPrefix(body, "ok\n") {
			t.Fatalf("%s: body = %q, want it to start with ok", path, body)
		}
		if !strings.Contains(body, "credential_domain_id=acct-42") {
			t.Fatalf("%s: body = %q, want credential_domain_id=acct-42", path, body)
		}
	}

	health.SetStopped()
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status after stop = %d, want 503", rec.Code)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "not ok\n") {
		t.Fatalf("body = %q, want it to start with not ok", body)
	}
	if !strings.Contains(body, "credential_domain_id=acct-42") {
		t.Fatalf("body = %q, want credential_domain_id=acct-42", body)
	}
}

// TestHealthServer_MetricsRoute_ServesExpositionFormat covers T11: /metrics
// serves the Prometheus exposition format and contains the credential
// domain info gauge.
func TestHealthServer_MetricsRoute_ServesExpositionFormat(t *testing.T) {
	m := metrics.New()
	m.AgentCredentialDomain.WithLabelValues("acct-42").Set(1)
	srv := newHealthServer(":0", &agentworker.Health{}, m, "acct-42", "")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `mctl_agent_credential_domain{domain_id="acct-42"} 1`) {
		t.Fatalf("/metrics body missing credential domain gauge: %s", rec.Body.String())
	}
	// Probe routes still answer alongside /metrics.
	assertStatus(t, srv.Handler, "/readyz", http.StatusServiceUnavailable)
}

// TestHealthServer_MetricsRoute_RefusedOutsideAllowCIDR covers T11: with
// AGENT_METRICS_ALLOW_CIDR set to a non-matching CIDR, /metrics is refused
// while the probe routes still answer.
func TestHealthServer_MetricsRoute_RefusedOutsideAllowCIDR(t *testing.T) {
	m := metrics.New()
	srv := newHealthServer(":0", &agentworker.Health{}, m, "acct-42", "10.0.0.0/8")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "203.0.113.5:12345" // outside 10.0.0.0/8, and ConnContext never ran in this unit test
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("/metrics status = %d, want 403 outside the allowed CIDR", rec.Code)
	}

	assertStatus(t, srv.Handler, "/livez", http.StatusOK)
	assertStatus(t, srv.Handler, "/readyz", http.StatusServiceUnavailable)
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
