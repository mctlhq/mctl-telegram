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

// SetOAuthPendingAuthSize sets the mctl_oauth_pending_auth_size gauge to n.
// This method satisfies the oauth.metricsIface interface so a *Registry can be
// passed to oauth.Server.WithMetrics without importing this package from oauth.
func (r *Registry) SetOAuthPendingAuthSize(n float64) {
	r.OAuthPendingAuthSize.Set(n)
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
		r.SessionsBorrowTotal,
		r.BridgeActiveDaemons,
		r.BridgeCallsTotal,
	)
	return r
}
