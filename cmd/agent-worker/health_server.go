package main

import (
	"net/http"

	"github.com/mctlhq/mctl-telegram/internal/agentworker"
)

// newHealthServer builds the /livez /readyz HTTP server for run()'s Worker
// probes (see agentworker.Health's doc comment for what each endpoint
// means). This binary otherwise has no HTTP surface — the poll loop only
// makes outbound calls — so this server exists purely for the Kubernetes
// liveness/readiness probes configured in the C1 deployment.
func newHealthServer(addr string, health *agentworker.Health) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", func(w http.ResponseWriter, _ *http.Request) {
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
