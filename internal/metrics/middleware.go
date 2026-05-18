package metrics

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// HTTPMiddleware returns a chi-compatible middleware that records every HTTP
// request in mctl_http_requests_total{method, route, status_code}. The route
// label is derived from the chi route pattern (e.g. /api/account/{action}),
// NOT from the raw request URL — this prevents high-cardinality labels caused
// by path parameters.
func (r *Registry) HTTPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rw, req)

			// chi populates RouteContext after the handler runs (for middleware
			// that wraps the chain). RoutePattern() returns the matched pattern
			// (e.g. "/api/account/{action}") or "" for unmatched/404 routes.
			route := ""
			if rc := chi.RouteContext(req.Context()); rc != nil {
				route = rc.RoutePattern()
			}
			if route == "" {
				route = "unmatched"
			}

			r.HTTPRequestsTotal.WithLabelValues(
				req.Method,
				route,
				fmt.Sprintf("%d", rw.status),
			).Inc()
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture the status code written
// by the handler.
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.wroteHeader = true
		// status remains the 200 default set in initialisation.
	}
	return rw.ResponseWriter.Write(b)
}
