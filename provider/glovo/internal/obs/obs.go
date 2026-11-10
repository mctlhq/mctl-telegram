package obs

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

// Audit event names.
const (
	EventMutationApplied = "mutation_applied"
	EventMutationUnknown = "mutation_unknown"
	EventResultSubmitted = "result_submitted"
	EventCommandStopped  = "command_stopped"
)

// Audit emits one typed audit event. Only opaque references and a code are
// accepted, so a caller cannot attach free-form data.
func Audit(log *slog.Logger, event, executionRef, orderRef, code string) {
	if log == nil {
		return
	}
	log.Info("audit", "event", event, "execution_ref", executionRef, "order_ref", orderRef, "code", code)
}

// Metrics is the worker's local registry; every name is mctl_glovo_provider_*.
// No label carries an id.
type Metrics struct {
	Registry        *prometheus.Registry
	Commands        *prometheus.CounterVec // kind, outcome, effect
	Permits         *prometheus.CounterVec // result
	Results         *prometheus.CounterVec // status
	ResultConflicts prometheus.Counter
	AmbiguousWrites prometheus.Counter
	ClaimErrors     *prometheus.CounterVec // code
	Dropped         *prometheus.CounterVec // reason
	Unmapped        *prometheus.CounterVec // route
	KillSwitch      prometheus.Gauge
	BreakerOpn      prometheus.Gauge
}

func NewMetrics() *Metrics {
	const p = "mctl_glovo_provider_"
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		Commands: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: p + "commands_total", Help: "Commands handled by kind, outcome and provider effect."}, []string{"kind", "outcome", "effect"}),
		Permits: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: p + "permits_total", Help: "Write permit requests by result."}, []string{"result"}),
		Results: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: p + "results_total", Help: "Result submissions by status."}, []string{"status"}),
		ResultConflicts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: p + "result_conflicts_total", Help: "Results refused with result_conflict."}),
		AmbiguousWrites: prometheus.NewCounter(prometheus.CounterOpts{
			Name: p + "ambiguous_writes_total", Help: "Writes whose effect could not be confirmed."}),
		ClaimErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: p + "claim_errors_total", Help: "Claim failures by code."}, []string{"code"}),
		Dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: p + "commands_dropped_total", Help: "Claimed commands dropped without a result."}, []string{"reason"}),
		Unmapped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: p + "unmapped_responses_total", Help: "Bridge responses with no mapping, failed closed."}, []string{"route"}),
		KillSwitch: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: p + "kill_switch", Help: "1 when GLOVO_PROVIDER_DISABLED is active."}),
		BreakerOpn: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: p + "breaker_open", Help: "1 when the provider circuit breaker is open."}),
	}
	m.Registry.MustRegister(m.Commands, m.Permits, m.Results, m.ResultConflicts, m.AmbiguousWrites,
		m.ClaimErrors, m.Dropped, m.Unmapped, m.KillSwitch, m.BreakerOpn)
	return m
}
