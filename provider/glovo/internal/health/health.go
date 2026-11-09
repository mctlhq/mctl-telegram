// Package health serves the internal probe and metrics endpoints. It is
// never exposed through an ingress.
package health

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// State tracks worker readiness. The zero value is not ready.
type State struct {
	pollerRunning atomic.Bool
	shuttingDown  atomic.Bool
	// Disabled reports the kill switch; BreakerOpen the provider breaker.
	Disabled    func() bool
	BreakerOpen func() bool
}

func (s *State) SetPollerRunning(v bool) { s.pollerRunning.Store(v) }
func (s *State) SetShuttingDown()        { s.shuttingDown.Store(true) }

// Alive is true until the process starts shutting down.
func (s *State) Alive() bool { return !s.shuttingDown.Load() }

// Ready is true only while the poller runs, the kill switch is off and the
// breaker is closed.
func (s *State) Ready() bool {
	if s.shuttingDown.Load() || !s.pollerRunning.Load() {
		return false
	}
	if s.Disabled != nil && s.Disabled() {
		return false
	}
	return s.BreakerOpen == nil || !s.BreakerOpen()
}

func probe(w http.ResponseWriter, ok bool) {
	if ok {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
		return
	}
	http.Error(w, "not ready", http.StatusServiceUnavailable)
}

// NewServer builds the probe server.
func NewServer(addr string, s *State, reg *prometheus.Registry) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", func(w http.ResponseWriter, _ *http.Request) { probe(w, s.Alive()) })
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { probe(w, s.Alive()) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) { probe(w, s.Ready()) })
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
}
