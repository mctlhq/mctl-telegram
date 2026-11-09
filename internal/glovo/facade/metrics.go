package facade

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// metrics uses its own registry, not internal/metrics (Telegram). Every label
// value comes from a closed set (route names, contract tool names, refusal
// codes, authn reasons, operation names, status codes).
type metrics struct {
	reg          *prometheus.Registry
	httpReqs     *prometheus.CounterVec
	toolCalls    *prometheus.CounterVec
	toolDuration *prometheus.HistogramVec
	authnFail    *prometheus.CounterVec
	upstream     *prometheus.CounterVec
	rateLimited  prometheus.Counter
}

func newMetrics() *metrics {
	m := &metrics{
		reg: prometheus.NewRegistry(),
		httpReqs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "glovo_mcp_http_requests_total", Help: "HTTP requests by route and status code."}, []string{"route", "code"}),
		toolCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "glovo_mcp_tool_calls_total", Help: "Tool calls by tool and outcome."}, []string{"tool", "outcome"}),
		toolDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "glovo_mcp_tool_duration_seconds", Help: "Tool call latency.", Buckets: prometheus.DefBuckets}, []string{"tool"}),
		authnFail: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "glovo_mcp_authn_failures_total", Help: "Refused bearer tokens by reason."}, []string{"reason"}),
		upstream: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "glovo_mcp_upstream_requests_total", Help: "mctl-api requests by operation and status code."}, []string{"op", "code"}),
		rateLimited: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "glovo_mcp_ratelimited_total", Help: "Requests refused by a rate or concurrency limit."}),
	}
	m.reg.MustRegister(m.httpReqs, m.toolCalls, m.toolDuration, m.authnFail, m.upstream, m.rateLimited)
	return m
}

func codeLabel(status int) string { return strconv.Itoa(status) }
