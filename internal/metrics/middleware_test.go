package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	dto "github.com/prometheus/client_model/go"
)

// TestHTTPMiddleware_UsesRoutePattern verifies that a request to a parametric
// route is recorded with the chi pattern as the route label, not the raw path.
// For example, a GET /api/account/disconnect must appear as route=
// "/api/account/{action}", not route="/api/account/disconnect".
func TestHTTPMiddleware_UsesRoutePattern(t *testing.T) {
	reg := New()
	mux := chi.NewRouter()
	mux.Use(reg.HTTPMiddleware())
	mux.Get("/api/account/{action}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/account/disconnect", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	mfs, err := reg.Prometheus.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var httpFamily *dto.MetricFamily
	for _, mf := range mfs {
		if mf.GetName() == "mctl_http_requests_total" {
			httpFamily = mf
			break
		}
	}
	if httpFamily == nil {
		t.Fatal("mctl_http_requests_total family not found")
	}

	// Find the metric with route="/api/account/{action}" and ensure there is
	// none with route="/api/account/disconnect".
	foundPattern := false
	foundRaw := false
	for _, m := range httpFamily.GetMetric() {
		routeVal := ""
		for _, lp := range m.GetLabel() {
			if lp.GetName() == "route" {
				routeVal = lp.GetValue()
			}
		}
		if routeVal == "/api/account/{action}" {
			foundPattern = true
		}
		if routeVal == "/api/account/disconnect" {
			foundRaw = true
		}
	}
	if !foundPattern {
		t.Error("expected route label /api/account/{action} in mctl_http_requests_total")
	}
	if foundRaw {
		t.Error("raw path /api/account/disconnect must not appear as route label")
	}
}

// TestHTTPMiddleware_StatusCodeLabel verifies that the status_code label
// matches the response code written by the handler.
func TestHTTPMiddleware_StatusCodeLabel(t *testing.T) {
	reg := New()
	mux := chi.NewRouter()
	mux.Use(reg.HTTPMiddleware())
	mux.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	mfs, err := reg.Prometheus.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() != "mctl_http_requests_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			statusCode := ""
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "status_code" {
					statusCode = lp.GetValue()
				}
			}
			if statusCode == "204" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected status_code=204 label in mctl_http_requests_total")
	}
}
