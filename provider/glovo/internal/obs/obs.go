package obs

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/interceptor"
)

// Audit event names.
const (
	EventScopeRefused    = "scope_refused"
	EventMutationApplied = "mutation_applied"
	EventMutationDeduped = "mutation_deduped"
	EventHandoffIssued   = "handoff_issued"
	EventPurged          = "purged"
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
type Metrics struct {
	Registry   *prometheus.Registry
	Activities *prometheus.CounterVec
	Duration   *prometheus.HistogramVec
	Refusals   *prometheus.CounterVec
	Mutations  *prometheus.CounterVec
	KillSwitch prometheus.Gauge
	BreakerOpn prometheus.Gauge
}

func NewMetrics() *Metrics {
	m := &Metrics{
		Registry: prometheus.NewRegistry(),
		Activities: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_glovo_provider_activities_total", Help: "Activity executions by type and outcome."}, []string{"activity", "outcome"}),
		Duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "mctl_glovo_provider_activity_duration_seconds", Help: "Activity duration.", Buckets: prometheus.DefBuckets}, []string{"activity"}),
		Refusals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_glovo_provider_refusals_total", Help: "Typed refusals by code."}, []string{"code"}),
		Mutations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_glovo_provider_mutations_total", Help: "Basket mutations by result."}, []string{"result"}),
		KillSwitch: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mctl_glovo_provider_kill_switch", Help: "1 when GLOVO_PROVIDER_DISABLED is active."}),
		BreakerOpn: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "mctl_glovo_provider_breaker_open", Help: "1 when the provider circuit breaker is open."}),
	}
	m.Registry.MustRegister(m.Activities, m.Duration, m.Refusals, m.Mutations, m.KillSwitch, m.BreakerOpn)
	return m
}

// Interceptor returns a worker interceptor recording activity outcomes and
// duration. Labels are the activity type only; no argument or result is read.
func (m *Metrics) Interceptor() interceptor.WorkerInterceptor { return &workerInterceptor{m: m} }

type workerInterceptor struct {
	interceptor.WorkerInterceptorBase
	m *Metrics
}

func (w *workerInterceptor) InterceptActivity(_ context.Context, next interceptor.ActivityInboundInterceptor) interceptor.ActivityInboundInterceptor {
	return &activityInbound{ActivityInboundInterceptorBase: interceptor.ActivityInboundInterceptorBase{Next: next}, m: w.m}
}

type activityInbound struct {
	interceptor.ActivityInboundInterceptorBase
	m *Metrics
}

func (a *activityInbound) ExecuteActivity(ctx context.Context, in *interceptor.ExecuteActivityInput) (interface{}, error) {
	name := activity.GetInfo(ctx).ActivityType.Name
	start := time.Now()
	res, err := a.Next.ExecuteActivity(ctx, in)
	a.m.Duration.WithLabelValues(name).Observe(time.Since(start).Seconds())
	outcome := "ok"
	if err != nil {
		outcome = "error"
	}
	a.m.Activities.WithLabelValues(name, outcome).Inc()
	return res, err
}
