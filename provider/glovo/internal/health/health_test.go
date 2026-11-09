package health

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func code(t *testing.T, h http.Handler, path string) int {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code
}

func TestReadinessTransitions(t *testing.T) {
	disabled, open := false, false
	s := &State{Disabled: func() bool { return disabled }, BreakerOpen: func() bool { return open }}
	h := NewServer(":0", s, prometheus.NewRegistry()).Handler

	if code(t, h, "/readyz") != 503 || code(t, h, "/livez") != 200 || code(t, h, "/healthz") != 200 {
		t.Fatal("before poller: live, not ready")
	}
	s.SetPollerRunning(true)
	if code(t, h, "/readyz") != 200 {
		t.Fatal("poller running must be ready")
	}
	disabled = true
	if code(t, h, "/readyz") != 503 || code(t, h, "/livez") != 200 {
		t.Fatal("kill switch: not ready but alive")
	}
	disabled, open = false, true
	if code(t, h, "/readyz") != 503 {
		t.Fatal("open breaker must not be ready")
	}
	open = false
	if code(t, h, "/readyz") != 200 {
		t.Fatal("recovered")
	}
	s.SetShuttingDown()
	if code(t, h, "/readyz") != 503 || code(t, h, "/livez") != 503 {
		t.Fatal("shutdown: neither ready nor alive")
	}
}

func TestMetricsEndpoint(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "mctl_glovo_provider_test_total", Help: "x"})
	reg.MustRegister(c)
	h := NewServer(":0", &State{}, reg).Handler
	if code(t, h, "/metrics") != 200 {
		t.Fatal("metrics")
	}
}
