// Package metrics defines the Prometheus collector registry for mctl-telegram.
// All metric families carry the mctl_ prefix. Use New() to obtain a Registry
// backed by a fresh (non-global) prometheus.Registry so parallel test
// instances never collide on duplicate registration.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// Registry holds every Prometheus collector used by mctl-telegram. Inject the
// single instance constructed by New() into each subsystem; never use the
// global prometheus.DefaultRegisterer.
type Registry struct {
	// Prometheus is the underlying registry used to serve /metrics.
	Prometheus *prometheus.Registry

	// HTTP layer — labeled by method, route (chi pattern), status_code.
	HTTPRequestsTotal *prometheus.CounterVec

	// Auth layer — labeled by reason and provider.
	AuthFailuresTotal *prometheus.CounterVec

	// Rate limiter — labeled by identity_kind ("user" or "anon").
	RateLimitEventsTotal *prometheus.CounterVec

	// MCP tool layer — labeled by tool and status ("ok" or "error").
	ToolInvocationsTotal   *prometheus.CounterVec
	ToolInvocationDuration *prometheus.HistogramVec

	// Telegram client pool.
	TelegramClientPoolSize    prometheus.Gauge
	TelegramClientErrorsTotal prometheus.Counter
	// TelegramPoolCapacity is the configured TELEGRAM_MAX_SESSIONS value.
	// -1 means uncapped (TELEGRAM_MAX_SESSIONS=0 or unset). Set once at
	// startup by cmd/server/main.go after pool construction.
	TelegramPoolCapacity prometheus.Gauge
	// TelegramFloodWaitEventsTotal counts FLOOD_WAIT_X events, labeled by
	// tool name. Incremented each time borrowWithRetry observes a FloodWait
	// error (whether or not the subsequent retry succeeds).
	TelegramFloodWaitEventsTotal *prometheus.CounterVec

	// Session lifecycle.
	SessionsConnectedTotal prometheus.Counter
	// SessionsRevokedTotal is labeled by reason: "disconnect", "delete",
	// "idle_expiry", "absolute_expiry".
	SessionsRevokedTotal *prometheus.CounterVec
	// SessionsActiveGauge is refreshed by a background sampler in main().
	SessionsActiveGauge prometheus.Gauge
	// SessionsBorrowTotal counts every Pool.Borrow() call exit, labeled by
	// result: ok, expired_idle, expired_absolute, error.
	// expired_idle and expired_absolute are expected user-side TTL expirations
	// and are excluded from the session-borrow availability SLI denominator.
	SessionsBorrowTotal *prometheus.CounterVec

	// OAuth server.
	// OAuthPendingAuthSize reflects the current count of pending OAuth
	// authorization flows. Refreshed every minute by oauth.Server.
	OAuthPendingAuthSize prometheus.Gauge

	// Enable_access login flow (in-browser phone -> SMS -> 2FA).
	// LoginPhoneStepTotal counts phone-step outcomes, labeled by result:
	// "ok" (SendCode returned and the code screen was shown), "timeout"
	// (connect/SendCode exceeded enableSendCodeWait — the stall failure mode),
	// or "error" (Telegram returned an RPC error).
	LoginPhoneStepTotal *prometheus.CounterVec
	// LoginPhoneToCodeDuration measures connect + SendCode wall-clock latency
	// for successful phone steps, in seconds. The buckets reach 90s to bracket
	// enableSendCodeWait so a near-timeout p95 is readable off a bucket edge.
	LoginPhoneToCodeDuration prometheus.Histogram

	// TelegramReplicaID is an info-type gauge (constant value 1) labeled by
	// replica_id. Operators use it to verify that a given user_id consistently
	// hits the same replica by cross-referencing with pod-scoped pool metrics.
	TelegramReplicaID *prometheus.GaugeVec
	// Local Bridge.
	// BridgeActiveDaemons is the current number of connected Local Bridge
	// daemon websocket connections. Incremented on Hub.Register, decremented
	// on Hub.Unregister / Hub.UnregisterSend.
	BridgeActiveDaemons prometheus.Gauge
	// BridgeCallsTotal counts hub round-trips, labeled by tool and status
	// ("ok" or "error"). Incremented by bridgeCall() in the MCP layer.
	BridgeCallsTotal *prometheus.CounterVec
}

// toolDurationBuckets covers sub-100ms fast reads through 10-second MTProto
// round-trips. The explicit 2 and 4 boundaries align with the latency SLO
// thresholds in docs/slo.md (read p95 < 2s, destructive p95 < 4s) so the
// burn-rate quantiles read directly off a bucket edge instead of being
// linearly interpolated between 1s and 2.5s.
var toolDurationBuckets = []float64{.05, .1, .25, .5, 1, 2, 2.5, 4, 5, 10}

// loginPhaseBuckets brackets the connect + SendCode round-trip up to the
// enableSendCodeWait (90s) handler ceiling. A healthy SendCode lands in the
// low single digits; values approaching 45-90s indicate the stall this metric
// exists to surface.
var loginPhaseBuckets = []float64{.5, 1, 2, 5, 10, 20, 30, 45, 60, 90}

// SetOAuthPendingAuthSize sets the mctl_oauth_pending_auth_size gauge to n.
// This method satisfies the oauth.metricsIface interface so a *Registry can be
// passed to oauth.Server.WithMetrics without importing this package from oauth.
func (r *Registry) SetOAuthPendingAuthSize(n float64) {
	r.OAuthPendingAuthSize.Set(n)
}

// ObserveLoginPhoneStep records the outcome and latency of one enable_access
// phone step. Satisfies oauth.metricsIface. The duration histogram is observed
// only for "ok" so timeouts/errors do not skew the latency distribution; the
// counter records every outcome for rate-based alerting.
func (r *Registry) ObserveLoginPhoneStep(result string, seconds float64) {
	r.LoginPhoneStepTotal.WithLabelValues(result).Inc()
	if result == "ok" {
		r.LoginPhoneToCodeDuration.Observe(seconds)
	}
}

// New constructs a Registry with all collectors registered on a fresh
// prometheus.Registry. Panics only if duplicate names are registered within
// the same call (which cannot happen in practice).
func New() *Registry {
	reg := prometheus.NewRegistry()
	r := &Registry{Prometheus: reg}

	r.HTTPRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_http_requests_total",
		Help: "Total HTTP requests handled, labeled by method, route pattern, and status code.",
	}, []string{"method", "route", "status_code"})

	r.AuthFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_auth_failures_total",
		Help: "Total authentication failures, labeled by reason and provider.",
	}, []string{"reason", "provider"})

	r.RateLimitEventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_rate_limit_events_total",
		Help: "Total HTTP 429 responses issued by the rate limiter, labeled by identity_kind.",
	}, []string{"identity_kind"})

	r.ToolInvocationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_tool_invocations_total",
		Help: "Total MCP tool invocations, labeled by tool name and status (ok or error).",
	}, []string{"tool", "status"})

	r.ToolInvocationDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mctl_tool_invocation_duration_seconds",
		Help:    "Wall-clock duration of MCP tool invocations in seconds.",
		Buckets: toolDurationBuckets,
	}, []string{"tool"})

	r.TelegramClientPoolSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_telegram_client_pool_size",
		Help: "Number of currently live Telegram MTProto client pool entries.",
	})

	r.TelegramClientErrorsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mctl_telegram_client_errors_total",
		Help: "Total Telegram MTProto client goroutine exits with a non-context-canceled error.",
	})

	r.TelegramPoolCapacity = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_telegram_pool_capacity",
		Help: "Configured TELEGRAM_MAX_SESSIONS value. -1 when uncapped (TELEGRAM_MAX_SESSIONS=0 or unset). Allows HPA to track pool_size / pool_capacity.",
	})

	r.TelegramFloodWaitEventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_telegram_flood_wait_events_total",
		Help: "Total Telegram FLOOD_WAIT_X errors observed, labeled by MCP tool name. Incremented on each FloodWait event whether or not the retry succeeds.",
	}, []string{"tool"})

	r.OAuthPendingAuthSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_oauth_pending_auth_size",
		Help: "Current count of pending OAuth authorization flows. Refreshed every minute.",
	})

	r.LoginPhoneStepTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_login_phone_step_total",
		Help: "Total enable_access phone-step outcomes, labeled by result: ok, timeout, error.",
	}, []string{"result"})

	r.LoginPhoneToCodeDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "mctl_login_phone_to_code_duration_seconds",
		Help:    "Wall-clock seconds from phone submit to the SMS-code screen (connect + SendCode), successful steps only.",
		Buckets: loginPhaseBuckets,
	})

	r.TelegramReplicaID = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mctl_telegram_replica_id",
		Help: "Info gauge (always 1) identifying this replica. " +
			"Label replica_id is sourced from REPLICA_ID / POD_NAME env vars.",
	}, []string{"replica_id"})

	r.SessionsConnectedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mctl_sessions_connected_total",
		Help: "Total new Telegram sessions persisted via SaveSession.",
	})

	r.SessionsRevokedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_sessions_revoked_total",
		Help: "Total Telegram sessions revoked, labeled by reason.",
	}, []string{"reason"})

	r.SessionsActiveGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_sessions_active",
		Help: "Count of non-revoked sessions that were last used within the last hour, including freshly created sessions not yet used. Refreshed every minute.",
	})

	r.SessionsBorrowTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_sessions_borrow_total",
		Help: "Total Pool.Borrow() calls, labeled by outcome. " +
			"expired_idle and expired_absolute are expected user-side TTL expirations; " +
			"exclude them from the availability SLI denominator.",
	}, []string{"result"})

	r.BridgeActiveDaemons = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_bridge_active_daemons",
		Help: "Current number of Local Bridge daemon websocket connections registered with the Hub.",
	})

	r.BridgeCallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_bridge_calls_total",
		Help: "Total Local Bridge hub round-trips, labeled by tool name and status (ok or error).",
	}, []string{"tool", "status"})

	// Register all collectors. MustRegister panics on duplicate names, which
	// cannot happen when New() is called once per process/test instance.
	reg.MustRegister(
		r.HTTPRequestsTotal,
		r.AuthFailuresTotal,
		r.RateLimitEventsTotal,
		r.ToolInvocationsTotal,
		r.ToolInvocationDuration,
		r.TelegramClientPoolSize,
		r.TelegramClientErrorsTotal,
		r.TelegramPoolCapacity,
		r.TelegramFloodWaitEventsTotal,
		r.SessionsConnectedTotal,
		r.SessionsRevokedTotal,
		r.SessionsActiveGauge,
		r.OAuthPendingAuthSize,
		r.LoginPhoneStepTotal,
		r.LoginPhoneToCodeDuration,
		r.SessionsBorrowTotal,
		r.TelegramReplicaID,
		r.BridgeActiveDaemons,
		r.BridgeCallsTotal,
	)
	return r
}
