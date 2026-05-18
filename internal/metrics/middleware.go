package metrics

import (
	"bufio"
	"fmt"
	"net"
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

// Flush forwards to the underlying ResponseWriter when it supports
// http.Flusher. This middleware is mounted globally, so it also wraps the
// MCP endpoint, which streams responses (Streamable HTTP / SSE) and depends
// on Flush. Without this pass-through the wrapper would mask the Flusher and
// streamed responses would buffer until the handler returns.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying ResponseWriter when it supports
// http.Hijacker. The /bridge websocket endpoint shares this router, and the
// websocket upgrade hijacks the connection. Without this pass-through the
// wrapper would mask the Hijacker and the upgrade would fail.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("metrics: underlying ResponseWriter does not implement http.Hijacker")
}
