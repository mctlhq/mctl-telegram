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
	// "error" (Telegram returned an RPC error), "mode_conflict" (the account
	// has an active Local Bridge row, so the hosted connect was refused before
	// Telegram was contacted), or "mode_check_error" (the store could not
	// answer whether it is local).
	//
	// The last two never reach Telegram, so they belong in neither the
	// numerator nor the denominator of a Telegram-health ratio — see the
	// MctlTelegramLoginSendCodeStalls section of docs/runbook.md, whose
	// queries exclude them.
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

	// BridgeConnectionsTotal counts daemon registrations, labeled by user id.
	// A counter rather than the gauge because the gauge cannot see two of the
	// three ways a daemon reconnects: a reconnect that lands while the old
	// entry is still registered replaces it with net zero gauge change, and a
	// disconnect/reconnect pair nets out to zero over any window that
	// contains both. Being per-user also makes a flap alert independent of
	// how many daemons happen to be connected, which a shared gauge is not.
	BridgeConnectionsTotal *prometheus.CounterVec
	// BridgeCallsTotal counts hub round-trips, labeled by tool and status
	// ("ok" or "error"). Incremented by bridgeCall() in the MCP layer.
	BridgeCallsTotal *prometheus.CounterVec

	// Communication agent (M6).
	// AgentEventsReceivedTotal counts incoming Telegram events persisted by
	// the agent listener (post-dedup), labeled by kind.
	AgentEventsReceivedTotal *prometheus.CounterVec
	// AgentJobsTotal counts agent job state transitions, labeled by the
	// resulting status (pending, processing, completed, failed, ignored,
	// dead_letter). Enqueue increments "pending", a claim increments
	// "processing", and so on — the rate per status is the queue's flow.
	AgentJobsTotal *prometheus.CounterVec
	// AgentDeadLetterTotal counts jobs that exhausted their attempts. Also
	// counted in AgentJobsTotal{status="dead_letter"}; kept as a dedicated
	// counter because it is the primary alerting signal.
	AgentDeadLetterTotal prometheus.Counter
	// AgentActionsExecutingStuck is the count of actions the executor's
	// crash-recovery sweep found in `executing` past its grace window on the
	// most recent tick. Should stay ~0 given send_random_id-based retry
	// (see internal/agent/executor) — any nonzero reading is a real
	// incident (a send that is failing on every retry), not expected noise.
	AgentActionsExecutingStuck prometheus.Gauge
	// AgentApprovalLatencySeconds measures owner approve -> executed
	// latency, i.e. how long a reply sits waiting for a human before it
	// actually goes out.
	AgentApprovalLatencySeconds prometheus.Histogram
	// AgentExecutorRestartsTotal counts actions observed stuck in executing
	// for the FIRST time (not every sweep that still finds them stuck) — a
	// proxy for "the executor process restarted mid-send" since that is the
	// only way an action reaches executing and stays there past the grace
	// window. Counting by first-observation (not sweep count) keeps a
	// single persistently-failing retry from inflating this past the actual
	// number of distinct restart episodes (Codex finding on #307).
	AgentExecutorRestartsTotal prometheus.Counter

	// AgentPolicyDenialsTotal counts hard policy denials, labeled by the
	// closed-set denial code (policy.DenyCode, never the free-text reason —
	// three of those interpolate a runtime value via strconv.Quote and would
	// otherwise make label cardinality unbounded) and the call site that
	// consumed the decision (one of PolicySurface*). Deliberately NOT
	// labeled by account, conversation or peer: those become cardinality
	// and, for peers, personal data. Bound: 18 codes (17 + "unknown") x 6
	// surfaces = 108 series, all compile-time fixed.
	AgentPolicyDenialsTotal *prometheus.CounterVec // {reason, surface}

	// AgentJobCostUSDTotal is monotonic total Claude spend attributed to
	// agent jobs, labeled by whether the CLI's own result reported
	// is_error. Recorded before CheckResult so a job that fails afterwards
	// still reports its spend. Bound: 2 series (success, error), both
	// pre-created at zero by New() — see issue #591: a counter whose first
	// observed sample is already non-zero yields increase() == 0, because
	// that sample becomes the baseline.
	AgentJobCostUSDTotal *prometheus.CounterVec // {result}

	// AgentClaudeResultErrorsTotal counts CheckResult errors consumed by
	// ClaudeInvoker.Run, labeled by whether the error was classified as a
	// usage-limit/quota condition or something else. Bound: 2 series
	// (usage_limit, other), both pre-created at zero by New() for the
	// increase() baseline reason recorded on AgentJobCostUSDTotal above
	// (issue #591).
	AgentClaudeResultErrorsTotal *prometheus.CounterVec // {class}

	// AgentCredentialDomain is an info-type gauge (constant value 1) set
	// once at agent-worker startup, labeled by the operator-configured
	// AGENT_CREDENTIAL_DOMAIN_ID — following the TelegramReplicaID
	// precedent. Bound: one series per running worker replica's configured
	// domain id, a small deployment-time constant, never a Telegram id,
	// username, peer, or the credential itself.
	AgentCredentialDomain *prometheus.GaugeVec // {domain_id}
}

// Policy-denial surfaces — the call site that consumed a policy.Deny
// decision. Used as the "surface" label on AgentPolicyDenialsTotal.
const (
	PolicySurfaceProposeReply = "propose_reply"
	// Owner-facing denials are split per tool: handleOwnerFacing is the
	// shared body for request_owner_approval and send_owner_summary, and a
	// single "owner_notify" value made the two indistinguishable on a
	// dashboard. Still a compile-time-fixed set, so no cardinality cost.
	PolicySurfaceOwnerApproval   = "request_owner_approval"
	PolicySurfaceOwnerSummary    = "send_owner_summary"
	PolicySurfaceExecutorSend    = "executor_send"
	PolicySurfaceExecutorRecover = "executor_recover"
	// PolicySurfaceUnknown is the bounded fallback for a surface that could
	// not be resolved — see policySurfaceForOwnerTool. Its appearance in the
	// series is the signal that a caller went unmapped.
	PolicySurfaceUnknown = "unknown"
)

// Claude result-error classes — the "class" label on
// AgentClaudeResultErrorsTotal, set by ClaudeInvoker.countResultError.
const (
	ClaudeResultClassUsageLimit = "usage_limit"
	ClaudeResultClassOther      = "other"
)

// Job-cost outcomes — the "result" label on AgentJobCostUSDTotal, set by
// ClaudeInvoker.recordCost from the CLI result's own is_error field.
const (
	JobCostResultSuccess = "success"
	JobCostResultError   = "error"
)

// claudeResultClasses and jobCostResults are the single source of truth for
// the zero baseline New() writes for those two counters. Adding a label value
// to either counter means adding it here, or the new child goes back to being
// created lazily on first use.
var (
	claudeResultClasses = []string{ClaudeResultClassUsageLimit, ClaudeResultClassOther}
	jobCostResults      = []string{JobCostResultSuccess, JobCostResultError}
)

// CountPolicyDenial increments AgentPolicyDenialsTotal for the given
// closed-set denial reason code and consuming surface, so call sites do not
// need to repeat the label order. Nil-safe: a nil *Registry is a no-op,
// matching every other optional-metrics call site in this codebase.
func (r *Registry) CountPolicyDenial(reason, surface string) {
	if r == nil {
		return
	}
	r.AgentPolicyDenialsTotal.WithLabelValues(reason, surface).Inc()
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
		Help: "Total enable_access phone-step outcomes, labeled by result: ok, timeout, error, mode_conflict, mode_check_error.",
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

	r.BridgeConnectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_bridge_connections_total",
		Help: "Total Local Bridge daemon registrations with the Hub, labeled by user id. " +
			"Cardinality is bounded by the number of local-mode accounts, each of which an operator flips deliberately. " +
			"A healthy daemon contributes one increment per server rollout; repeated increments are a reconnect loop.",
	}, []string{"user_id"})

	r.BridgeCallsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_bridge_calls_total",
		Help: "Total Local Bridge hub round-trips, labeled by tool name and status (ok or error).",
	}, []string{"tool", "status"})

	r.AgentEventsReceivedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_agent_events_received_total",
		Help: "Total incoming Telegram events persisted by the communication-agent listener (after dedup), labeled by event kind.",
	}, []string{"kind"})

	r.AgentJobsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_agent_jobs_total",
		Help: "Total communication-agent job state transitions, labeled by the resulting status.",
	}, []string{"status"})

	r.AgentDeadLetterTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mctl_agent_dead_letter_total",
		Help: "Total communication-agent jobs moved to dead_letter after exhausting their attempts.",
	})

	r.AgentActionsExecutingStuck = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_agent_actions_executing_stuck",
		Help: "Communication-agent actions found stuck in executing past the crash-recovery grace window on the most recent sweep. Should stay ~0.",
	})

	r.AgentApprovalLatencySeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "mctl_agent_approval_latency_seconds",
		Help:    "Time from owner approval to a communication-agent reply actually being sent (executed).",
		Buckets: []float64{.5, 1, 2, 5, 10, 30, 60, 120, 300},
	})

	r.AgentExecutorRestartsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mctl_agent_executor_restarts_total",
		Help: "Actions observed stuck in executing for the first time (not counted again on later sweeps while still stuck).",
	})

	r.AgentPolicyDenialsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_agent_policy_denials_total",
		Help: "Total hard policy denials, labeled by a closed-set denial reason code (bounded: 18 values, see policy.DenyCode) and the consuming surface (bounded: 6 values, see PolicySurface* constants). Never labeled by account, conversation, or peer.",
	}, []string{"reason", "surface"})

	r.AgentJobCostUSDTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_agent_job_cost_usd_total",
		Help: "Total Claude spend (total_cost_usd) attributed to communication-agent jobs, labeled by result (bounded: success, error). Recorded before the job's is_error check, so a job that fails afterwards still reports its spend.",
	}, []string{"result"})

	r.AgentClaudeResultErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_agent_claude_result_errors_total",
		Help: "Total CheckResult errors observed by ClaudeInvoker.Run, labeled by class (bounded: usage_limit, other).",
	}, []string{"class"})

	r.AgentCredentialDomain = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mctl_agent_credential_domain",
		Help: "Info gauge (always 1) identifying the credential domain an agent-worker replica is running against. Label domain_id is sourced from AGENT_CREDENTIAL_DOMAIN_ID, a non-secret operator-chosen identifier (e.g. a Vault path or account label) bounded to 128 characters of [A-Za-z0-9._:/-].",
	}, []string{"domain_id"})

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
		r.BridgeConnectionsTotal,
		r.BridgeCallsTotal,
		r.AgentEventsReceivedTotal,
		r.AgentJobsTotal,
		r.AgentDeadLetterTotal,
		r.AgentActionsExecutingStuck,
		r.AgentApprovalLatencySeconds,
		r.AgentExecutorRestartsTotal,
		r.AgentPolicyDenialsTotal,
		r.AgentJobCostUSDTotal,
		r.AgentClaudeResultErrorsTotal,
		r.AgentCredentialDomain,
	)

	// Give the two agent counters a zero baseline before any work is
	// accepted. A CounterVec creates its children lazily, on first
	// increment, so a counter whose first *observed* sample is already 1
	// makes increase() read 0 — that sample is the baseline. Both alerts
	// over these series (MctlAgentClaudeUsageLimit, MctlAgentJobCostHigh)
	// would then miss the first, and possibly only, occurrence they exist
	// for. Four series total; see issue #591.
	//
	// AgentPolicyDenialsTotal is deliberately excluded: its label space is
	// 18 x 6 = 108 series, pre-initializing all of them would materialize
	// combinations that cannot occur, and MctlAgentPolicyDenialRateHigh
	// carries a "> 4" floor a single first denial would not clear anyway.
	for _, class := range claudeResultClasses {
		r.AgentClaudeResultErrorsTotal.WithLabelValues(class).Add(0)
	}
	for _, result := range jobCostResults {
		r.AgentJobCostUSDTotal.WithLabelValues(result).Add(0)
	}

	return r
}
