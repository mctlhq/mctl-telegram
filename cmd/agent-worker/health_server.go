package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/netctx"
)

// newHealthServer builds the HTTP server for run()'s Worker probes (see
// agentworker.Health's doc comment for what each endpoint means), plus a
// /metrics route exposing m — the worker's own metrics registry, reused
// rather than a bespoke one so every mctl_* name stays defined in exactly
// one file (internal/metrics/metrics.go), matching
// docs/runbook_test.go's TestRunbookMetricNamesRegistered assumption.
//
// /healthz is a liveness alias for /livez: mctl-gitops's
// service-templates/worker/values.yaml.tpl (the template C1's
// communication-agent-worker-preview onboards from) already points
// probes.liveness.path at /healthz, matching every other service in this
// platform's convention (see e.g. cmd/server/main.go's healthz handler) —
// aliasing avoids a per-service probe-path override for the common case.
// /livez is kept too since it's the more accurate name for what this
// specific check reports (the poll loop's own running state, not general
// process health).
func newHealthServer(addr string, health *agentworker.Health, m *metrics.Registry, credentialDomainID, allowCIDR string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", func(w http.ResponseWriter, _ *http.Request) {
		writeProbeResult(w, health.Alive(), credentialDomainID)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeProbeResult(w, health.Alive(), credentialDomainID)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeProbeResult(w, health.Ready(), credentialDomainID)
	})
	mux.HandleFunc("/metrics", metricsHandler(m, allowCIDR))
	return &http.Server{
		Addr:    addr,
		Handler: mux,
		// Matches cmd/server/main.go's convention — without this, any client
		// that can reach the pod can hold a connection open by trickling
		// headers one byte at a time (Slowloris), tying up worker resources.
		ReadHeaderTimeout: 10 * time.Second,
		// Stores the real TCP peer address in the request context before any
		// handler (including the CIDR guard below) runs — see metricsHandler's
		// doc comment for why this, not r.RemoteAddr, is the authoritative
		// source.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return netctx.WithPeer(ctx, c.RemoteAddr().String())
		},
	}
}

// metricsHandler wraps the Prometheus exposition handler with an optional
// CIDR allowlist guard, modeled on cmd/server/main.go's metricsHandler. When
// allowCIDR is empty the endpoint is open, matching that function's default
// and this binary's historical no-/metrics-at-all behavior for every other
// route. When set, requests from outside the CIDR receive HTTP 403. A
// misconfigured allowCIDR fails CLOSED — the endpoint rejects every request
// rather than silently exposing worker metrics.
func metricsHandler(m *metrics.Registry, allowCIDR string) http.HandlerFunc {
	h := promhttp.HandlerFor(m.Prometheus, promhttp.HandlerOpts{})
	if allowCIDR == "" {
		return h.ServeHTTP
	}
	_, ipNet, err := net.ParseCIDR(allowCIDR)
	if err != nil {
		slog.Error("AGENT_METRICS_ALLOW_CIDR is invalid — /metrics endpoint will reject ALL requests until fixed", "cidr", allowCIDR, "err", err)
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		rawAddr := netctx.Peer(r.Context())
		if rawAddr == "" {
			rawAddr = r.RemoteAddr // fallback for tests that bypass ConnContext
		}
		host, _, splitErr := net.SplitHostPort(rawAddr)
		if splitErr != nil {
			host = rawAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !ipNet.Contains(ip) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	}
}

// writeProbeResult keeps the first line ok/not ok and the existing status
// codes unchanged (cmd/agent-worker/health_server_test.go asserts on both),
// and appends a second line naming the credential domain this worker is
// attributed to.
func writeProbeResult(w http.ResponseWriter, ok bool, credentialDomainID string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = fmt.Fprintf(w, "not ok\ncredential_domain_id=%s\n", credentialDomainID)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "ok\ncredential_domain_id=%s\n", credentialDomainID)
}
