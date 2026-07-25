package main

import (
	"net/http"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
)

// newHealthServer builds the HTTP server for run()'s Worker probes (see
// agentworker.Health's doc comment for what each endpoint means). This
// binary otherwise has no HTTP surface — the poll loop only makes outbound
// calls — so this server exists purely for Kubernetes liveness/readiness
// probes.
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
func newHealthServer(addr string, health *agentworker.Health) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", func(w http.ResponseWriter, _ *http.Request) {
		writeProbeResult(w, health.Alive())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeProbeResult(w, health.Alive())
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeProbeResult(w, health.Ready())
	})
	return &http.Server{Addr: addr, Handler: mux}
}

func writeProbeResult(w http.ResponseWriter, ok bool) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !ok {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ok\n"))
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
