// Package metrics defines the Prometheus collector registry for mctl-telegram.
// All metric families carry the mctl_ prefix. Use New() to obtain a Registry
// backed by a fresh (non-global) prometheus.Registry so parallel test
// instances never collide on duplicate registration.
package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

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

	// MCP tool layer — labeled by tool, status ("ok", "error",
	// "caller_error" or "no_session") and traffic ("user" or "canary"; see
	// traffic.go).
	ToolInvocationsTotal   *prometheus.CounterVec
	ToolInvocationDuration *prometheus.HistogramVec
	// ToolCallErrorsTotal counts MCP tools/call failures, labeled by tool and
	// a closed-set reason (mctl-telegram#696) — covers both a registered
	// tool's handler failing (scope_denied, invalid_argument, ...) and a
	// JSON-RPC-level tools/call rejection (tool_not_found,
	// unparsable_message, capability_disabled, jsonrpc_error). reason is
	// always one of internal/mcp's compile-time constants, never a
	// client-supplied string, so label cardinality stays bounded. Not
	// pre-created at zero — see requirements.md Open questions.
	ToolCallErrorsTotal *prometheus.CounterVec

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
	// TelegramFloodWaitSeconds observes the wait every FLOOD_WAIT_X asks for,
	// labeled by the TL method that drew it (e.g. "messages.getHistory").
	// Recorded by the pooled clients' middleware, so it also covers calls
	// made outside an MCP tool (background executor, agent listener).
	TelegramFloodWaitSeconds *prometheus.HistogramVec
	// TelegramSponsoredTotal counts sponsored-message events on
	// get_messages/get_unread_messages, labeled by tool and outcome:
	// "returned" (an item included in a result), "unavailable" (a channel
	// whose posts were returned but whose sponsored messages could not be
	// fetched), "viewed" and "view_failed" (messages.viewSponsoredMessage
	// per returned item), and "view_deduplicated" (a returned item whose
	// view was already reported for the user within the de-dup TTL).
	TelegramSponsoredTotal *prometheus.CounterVec

	// Session lifecycle.
	SessionsConnectedTotal prometheus.Counter
	// SessionsRevokedTotal is labeled by reason: "disconnect", "delete",
	// "idle_expiry", "absolute_expiry", "unauthorized" (Telegram rejected
	// the auth key), "login_incomplete" (a login that never finished).
	SessionsRevokedTotal *prometheus.CounterVec
	// BotUpdatesTotal counts inbound login-bot updates by kind and outcome
	// (issue-619). This is how "dropped safely and counted, not logged with
	// contents" is satisfied: an unknown chat or an unroutable callback
	// increments a counter here instead of producing a log line that would
	// have to carry the update to be useful.
	BotUpdatesTotal *prometheus.CounterVec
	// SessionsActiveGauge is refreshed by a background sampler in main().
	SessionsActiveGauge prometheus.Gauge
	// SessionsBorrowTotal counts every Pool.Borrow() call exit, labeled by
	// result: ok, expired_idle, expired_absolute, no_session, flood_wait,
	// call_error, error; and by traffic: user or canary (traffic.go).
	// expired_idle and expired_absolute are expected user-side TTL expirations.
	// no_session is a user with no connected Telegram account (never
	// connected, or disconnected): Telegram is never called.
	// flood_wait and call_error are fn errors that Telegram returned over a
	// working session (a rate limit, or a 400/403 for the caller's request).
	// All five are excluded from the session-borrow availability SLI, whose
	// denominator is ok|error.
	SessionsBorrowTotal *prometheus.CounterVec

	// OAuth server.
	// OAuthPendingAuthSize reflects the current count of pending OAuth
	// authorization flows. Refreshed every minute by oauth.Server.
	OAuthPendingAuthSize prometheus.Gauge
	// OAuthClientRegistrationsTotal counts /oauth/register outcomes, labeled
	// by outcome (accepted, rejected, rate_limited, error) and reason. Both
	// label sets are closed compile-time constants from internal/oauth — a
	// client-supplied string never reaches either label.
	OAuthClientRegistrationsTotal *prometheus.CounterVec

	// Inbound events outbox (internal/events). Published envelopes, failed
	// publish attempts (the row stays pending), and the unpublished backlog.
	EventsPublishedTotal       prometheus.Counter
	EventsPublishFailuresTotal prometheus.Counter
	EventsOutboxBacklog        prometheus.Gauge

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
	// LoginFlowTotal counts finished enable_access login flows by method
	// ("code" for phone + login code, "qr" for the web QR login, #901) and
	// result: "ok", "error", "mismatch" (another Telegram account signed in
	// and was refused), "expired" (a QR code nobody scanned in time),
	// "stalled" (Telegram confirmed a QR scan but connecting the session did
	// not finish in time), "abandoned" (the flow ran out of time waiting for
	// the user) or "superseded" (the user started over). Unlike
	// LoginPhoneStepTotal it covers the whole flow, so method=code and
	// method=qr compare end to end.
	LoginFlowTotal *prometheus.CounterVec
	// LoginFlowStartedTotal counts enable_access login flows launched, by
	// method (issue #960). Every launched flow ends in exactly one
	// LoginFlowTotal increment, so started minus finished over a window is
	// the flows a pod restart cut off before they could report.
	LoginFlowStartedTotal *prometheus.CounterVec
	// LoginCallbackRejectedTotal counts rejected browser returns from
	// Telegram's OIDC leg (issue #960), labeled by route ("oauth_callback" for
	// /oauth/telegram/callback, "connect_done" for /telegram/connect/done)
	// and reason, the same closed vocabulary the "callback request rejected"
	// and "connect: request rejected" log lines carry: missing_state,
	// missing_code, oidc_error, unknown_state, expired_state,
	// exchange_failed, prefetch_refused.
	LoginCallbackRejectedTotal *prometheus.CounterVec
	// RootMCPRequestsTotal counts requests on the bare origin "/" that are
	// served as MCP rather than as the landing page (issue #960, the
	// mctl-telegram#957 alias), labeled by method (GET, POST, DELETE, other)
	// and ua_family (claude, chatgpt, perplexity, canary, other). A client
	// still configured with the bare origin shows up here.
	RootMCPRequestsTotal *prometheus.CounterVec
	// LoginFlowDuration measures a successful flow from launch to session
	// saved, in seconds, by method.
	LoginFlowDuration *prometheus.HistogramVec
	// LoginLogOutTotal counts enable_access logouts of sessions nobody holds
	// any more, by reason -- "unsaved" (a sign-in the flow did not save,
	// #919) or "superseded" (the old key a re-login replaced, #913) -- and
	// outcome ("ok", "error"). An error leaves an orphaned device in the
	// user's Active Sessions.
	LoginLogOutTotal *prometheus.CounterVec
	// ConnectFirstCallTotal counts authorization_code grants by whether the
	// same user and client made a successful MCP call within five minutes
	// (issue #960): outcome "ok", "none_within_window" or "unknown", the last
	// with a reason saying what could not be observed (insert_error, restart,
	// close_error); reason is empty otherwise. client is the bounded label
	// claude, chatgpt or other. Incremented once per grant, when internal/
	// connectfunnel decides its outcome.
	ConnectFirstCallTotal *prometheus.CounterVec
	// ConnectFirstCallErrorsTotal counts store errors in the connect funnel
	// by op (insert, close, classify, sweep).
	ConnectFirstCallErrorsTotal *prometheus.CounterVec

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
	// AgentDeliveryUnknownTotal counts actions the executor moved to
	// delivery_unknown: sends whose outcome it could not observe and will
	// not retry (#1029). Each one is also an owner alert; any increase is
	// worth a look.
	AgentDeliveryUnknownTotal prometheus.Counter

	// AgentPolicyDenialsTotal counts hard policy denials, labeled by the
	// closed-set denial code (policy.DenyCode, never the free-text reason —
	// three of those interpolate a runtime value via strconv.Quote and would
	// otherwise make label cardinality unbounded) and the call site that
	// consumed the decision (one of PolicySurface*). Deliberately NOT
	// labeled by account, conversation or peer: those become cardinality
	// and, for peers, personal data. Bound: 23 codes (22 + "unknown") x 6
	// surfaces = 138 series, all compile-time fixed and all pre-created at
	// zero by New() — see issue #591 and the comment on the pre-init loops.
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

	// WorkContextRequestsTotal counts outbound mctl-api calls made by the
	// issue-443 work-context adapter, labeled by route (a short bounded
	// name, never a raw path containing an id) and outcome (ok, error).
	WorkContextRequestsTotal *prometheus.CounterVec // {route, outcome}
	// WorkContextBindingsTotal counts work_item_bindings writes, labeled by
	// result (created, reused, refused).
	WorkContextBindingsTotal *prometheus.CounterVec // {result}

	// HumanInputTelegramEventsTotal counts issue-571 human-input adapter
	// events, labeled by event (delivery_attempt, delivered,
	// response_received, response_submitted, response_rejected) and a short
	// bounded outcome. Never labeled by request id or any content.
	HumanInputTelegramEventsTotal *prometheus.CounterVec // {event, outcome}
	// HumanInputDeliverLatency is seconds from the delivery row being queued
	// to the Saved Messages send succeeding.
	HumanInputDeliverLatency prometheus.Histogram
	// HumanInputRespondLatency is seconds from delivery to the owner's answer
	// being accepted by mctl-api.
	HumanInputRespondLatency prometheus.Histogram

	// MediaGateRejectionsTotal counts issue #705's media admission-gate
	// refusals (MEDIA_MAX_CONCURRENT operations already in flight, no slot
	// freed within the gate's admission wait), labeled by tool
	// (get_messages/get_unread_messages/get_media).
	MediaGateRejectionsTotal *prometheus.CounterVec // {tool}
	// MediaInflight is the current number of media operations holding a
	// mediaGate slot (issue #705). Always 0 when MEDIA_MAX_CONCURRENT=0 or
	// unset (no gate configured).
	MediaInflight prometheus.Gauge
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

// policySurfaces and policyDenyReasons are the label space of
// AgentPolicyDenialsTotal, mirroring the PolicySurface* constants above and
// policy.DenyCode. The reasons are duplicated as literals rather than
// referenced, to keep this package a leaf: internal/agent/policy is a much
// heavier dependency than a list of strings, and TestDenyCodesMatchMetricsList
// over there pins the two lists together so they cannot drift.
var (
	policySurfaces = []string{
		PolicySurfaceProposeReply,
		PolicySurfaceOwnerApproval,
		PolicySurfaceOwnerSummary,
		PolicySurfaceExecutorSend,
		PolicySurfaceExecutorRecover,
		PolicySurfaceUnknown,
	}
	policyDenyReasons = []string{
		"global_kill",
		"user_mismatch",
		"mode_off",
		"mode_unrecognized",
		"autopilot_paused",
		"conversation_taken_over",
		"conversation_closed",
		"conversation_paused",
		"conversation_state_unrecognized",
		"sender_blocked",
		"action_type_unrecognized",
		"peer_mismatch",
		"no_disclosure_text",
		"empty_reply",
		"reply_too_long",
		"reply_contains_url",
		"reply_contains_credentials",
		"reply_contains_never_field",
		"source_message_superseded",
		"intent_never",
		"audience_excluded",
		"install_changed",
		"unknown",
	}
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

// jobStatuses is every terminal or transitional value of the "status" label on
// AgentJobsTotal, mirroring db.JobPending .. db.JobIgnored. Duplicated as
// literals rather than referenced, because internal/db imports this package and
// the reverse would be an import cycle; TestJobStatusesMatchMetricsSlice in
// internal/db pins the two lists together so they cannot drift. Unexported and
// reached through JobStatuses(), so an importer cannot reassign an element and
// change what a later New() pre-creates.
var jobStatuses = []string{
	"pending",
	"processing",
	"completed",
	"failed",
	"dead_letter",
	"ignored",
}

// PolicyDenyReasons returns a copy of the denial-code label values New()
// pre-creates. A copy, for the reason given on JobStatuses.
func PolicyDenyReasons() []string {
	out := make([]string, len(policyDenyReasons))
	copy(out, policyDenyReasons)
	return out
}

// JobStatuses returns a copy of the job-status label values New() pre-creates.
// A copy, so a caller cannot mutate the list the constructor reads.
func JobStatuses() []string {
	out := make([]string, len(jobStatuses))
	copy(out, jobStatuses)
	return out
}

// claudeResultClasses, jobCostResults and mediaGateTools complete the set of
// label-value lists New() writes a zero baseline for; jobStatuses,
// policySurfaces and policyDenyReasons above are the others. Adding a label
// value to any of those counters means adding it to the matching list, or the
// new child goes back to being created lazily on first use.
var (
	claudeResultClasses = []string{ClaudeResultClassUsageLimit, ClaudeResultClassOther}
	jobCostResults      = []string{JobCostResultSuccess, JobCostResultError}
	// mediaGateTools is the fixed label set of mctl_media_gate_rejections_total:
	// the tools that acquire the media admission gate (issue #705). Unexported
	// like its siblings above — nothing outside this package consumes it.
	mediaGateTools = []string{"get_messages", "get_unread_messages", "get_media"}
	// connectFirstCall* are the closed label sets of the connect funnel
	// counters (issue #960). They mirror internal/connectfunnel, which cannot
	// be imported here (it imports internal/db, which imports this package);
	// connectfunnel's tests hold the two to the same values.
	connectFirstCallClients        = []string{"claude", "chatgpt", "other"}
	connectFirstCallUnknownReasons = []string{"insert_error", "restart", "close_error"}
	connectFirstCallOps            = []string{"insert", "close", "classify", "sweep"}
	// loginFlowMethods, loginCallbackRoutes/Reasons and rootMCPMethods/
	// UAFamilies are the closed label sets of the login-path counters added
	// for issue #960 signals 2-4. They mirror internal/oauth and internal/web,
	// whose tests hold them to the same values.
	loginFlowMethods     = []string{"code", "qr"}
	loginFlowResults     = []string{"ok", "error", "mismatch", "expired", "stalled", "abandoned", "superseded"}
	loginCallbackRoutes  = []string{"oauth_callback", "connect_done"}
	loginCallbackReasons = []string{
		"missing_state", "missing_code", "oidc_error", "unknown_state",
		"expired_state", "exchange_failed", "prefetch_refused",
	}
	rootMCPMethods    = []string{"GET", "POST", "DELETE", "other"}
	rootMCPUAFamilies = []string{"claude", "chatgpt", "perplexity", "canary", "other"}
	// workContextRoutes and friends are the closed label sets for
	// WorkContextRequestsTotal/WorkContextBindingsTotal (issue-443), primed
	// below for the same reason as the two lists above — see #591.
	workContextRoutes = []string{
		"redeem_link", "create_work_item", "get_work_item", "append_intent",
		"request_execution", "get_execution_request", "list_execution_requests",
		"add_surface_ref",
		"list_human_input", "get_human_input", "respond_human_input",
	}
	workContextOutcomes       = []string{"ok", "error"}
	workContextBindingResults = []string{"created", "reused", "refused"}
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

// CountWorkContextRequest increments mctl_work_context_requests_total for one
// outbound mctl-api call made by the work-context adapter (issue-443).
// Nil-safe, matching CountPolicyDenial above.
func (r *Registry) CountWorkContextRequest(route, outcome string) {
	if r == nil {
		return
	}
	r.WorkContextRequestsTotal.WithLabelValues(route, outcome).Inc()
}

// CountWorkContextBinding increments mctl_work_context_bindings_total for one
// work_item_bindings write attempted by the work-context adapter. Nil-safe.
func (r *Registry) CountWorkContextBinding(result string) {
	if r == nil {
		return
	}
	r.WorkContextBindingsTotal.WithLabelValues(result).Inc()
}

// Human-input adapter event names (issue-571), the closed value set of the
// event label on human_input_telegram_events_total.
const (
	HumanInputEventDeliveryAttempt   = "delivery_attempt"
	HumanInputEventDelivered         = "delivered"
	HumanInputEventResponseReceived  = "response_received"
	HumanInputEventResponseSubmitted = "response_submitted"
	HumanInputEventResponseRejected  = "response_rejected"
)

// CountHumanInputEvent increments human_input_telegram_events_total. outcome
// must be a short bounded token (ok, error, stale, ...), never request data.
// Nil-safe.
func (r *Registry) CountHumanInputEvent(event, outcome string) {
	if r == nil {
		return
	}
	r.HumanInputTelegramEventsTotal.WithLabelValues(event, outcome).Inc()
}

// ObserveHumanInputDeliverLatency records one queue-to-sent latency. Nil-safe.
func (r *Registry) ObserveHumanInputDeliverLatency(d time.Duration) {
	if r == nil {
		return
	}
	r.HumanInputDeliverLatency.Observe(d.Seconds())
}

// ObserveHumanInputRespondLatency records one delivered-to-answered latency.
// Nil-safe.
func (r *Registry) ObserveHumanInputRespondLatency(d time.Duration) {
	if r == nil {
		return
	}
	r.HumanInputRespondLatency.Observe(d.Seconds())
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

// CountOAuthClientRegistration increments mctl_oauth_client_registrations_total
// for one /oauth/register outcome. Satisfies oauth.metricsIface. Both outcome
// and reason come from a closed compile-time set in internal/oauth — never
// from a client-supplied string.
func (r *Registry) CountOAuthClientRegistration(outcome, reason string) {
	r.OAuthClientRegistrationsTotal.WithLabelValues(outcome, reason).Inc()
}

// CountConnectFirstCall records the decided outcome of one authorization_code
// grant. Satisfies connectfunnel.Metrics.
func (r *Registry) CountConnectFirstCall(client, outcome, reason string) {
	r.ConnectFirstCallTotal.WithLabelValues(client, outcome, reason).Inc()
}

// CountConnectFirstCallError records one connect funnel store error.
// Satisfies connectfunnel.Metrics.
func (r *Registry) CountConnectFirstCallError(op string) {
	r.ConnectFirstCallErrorsTotal.WithLabelValues(op).Inc()
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

// ObserveLoginFlow records the outcome of one finished enable_access login
// flow. Satisfies oauth.metricsIface. Like ObserveLoginPhoneStep, only "ok"
// lands in the duration histogram. method and result come from closed sets in
// internal/oauth.
func (r *Registry) ObserveLoginFlow(method, result string, seconds float64) {
	r.LoginFlowTotal.WithLabelValues(method, result).Inc()
	if result == "ok" {
		r.LoginFlowDuration.WithLabelValues(method).Observe(seconds)
	}
}

// CountLoginFlowStarted counts one launched enable_access login flow.
// Satisfies oauth.metricsIface.
func (r *Registry) CountLoginFlowStarted(method string) {
	r.LoginFlowStartedTotal.WithLabelValues(method).Inc()
}

// CountLoginCallbackRejected counts one rejected OIDC browser return.
// Satisfies oauth.metricsIface and web.ConnectMetrics; route and reason come
// from closed sets in those packages.
func (r *Registry) CountLoginCallbackRejected(route, reason string) {
	r.LoginCallbackRejectedTotal.WithLabelValues(route, reason).Inc()
}

// CountRootMCPRequest counts one MCP request served on the bare origin. The
// arguments come from web.RootMCP, which bounds both.
func (r *Registry) CountRootMCPRequest(method, uaFamily string) {
	r.RootMCPRequestsTotal.WithLabelValues(method, uaFamily).Inc()
}

// CountLoginLogOut counts one enable_access logout of a session nobody holds
// any more. Satisfies oauth.metricsIface. reason and outcome come from closed
// sets in internal/oauth.
func (r *Registry) CountLoginLogOut(reason, outcome string) {
	r.LoginLogOutTotal.WithLabelValues(reason, outcome).Inc()
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
		Help: "Total MCP tool invocations, labeled by tool name, status (ok, error, caller_error or no_session; caller_error is a request Telegram or argument/scope validation refused as the caller's mistake, no_session a call by a user with no connected Telegram account, and both are excluded from the availability SLI) and traffic (user or canary; canary is the monitoring probe's account, excluded from the user-facing SLI).",
	}, []string{"tool", "status", "traffic"})

	r.ToolInvocationDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mctl_tool_invocation_duration_seconds",
		Help:    "Wall-clock duration of MCP tool invocations in seconds.",
		Buckets: toolDurationBuckets,
	}, []string{"tool"})

	r.ToolCallErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_tool_call_errors_total",
		Help: "MCP tool-call failures, labeled by tool and a closed-set reason.",
	}, []string{"tool", "reason"})

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

	r.TelegramFloodWaitSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mctl_telegram_flood_wait_seconds",
		Help:    "Wait requested by each Telegram FLOOD_WAIT_X error on a pooled client, labeled by TL method.",
		Buckets: []float64{1, 2, 5, 10, 15, 30, 60, 120, 300, 900, 3600},
	}, []string{"method"})

	r.TelegramSponsoredTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_telegram_sponsored_messages_total",
		Help: "Sponsored-message events on broadcast channel reads, labeled by MCP tool and outcome (returned, unavailable, viewed, view_failed, view_deduplicated).",
	}, []string{"tool", "outcome"})

	r.OAuthPendingAuthSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_oauth_pending_auth_size",
		Help: "Current count of pending OAuth authorization flows. Refreshed every minute.",
	})

	r.OAuthClientRegistrationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_oauth_client_registrations_total",
		Help: "Total /oauth/register outcomes, labeled by outcome (accepted, rejected, rate_limited, error) and reason. Both labels are closed compile-time constants from internal/oauth.",
	}, []string{"outcome", "reason"})

	r.LoginPhoneStepTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_login_phone_step_total",
		Help: "Total enable_access phone-step outcomes, labeled by result: ok, timeout, error, mode_conflict, mode_check_error.",
	}, []string{"result"})

	r.LoginPhoneToCodeDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "mctl_login_phone_to_code_duration_seconds",
		Help:    "Wall-clock seconds from phone submit to the SMS-code screen (connect + SendCode), successful steps only.",
		Buckets: loginPhaseBuckets,
	})

	r.LoginFlowTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_login_flow_total",
		Help: "Total finished enable_access login flows, labeled by method (code, qr) and result: ok, error, mismatch, expired, stalled, abandoned, superseded.",
	}, []string{"method", "result"})

	r.LoginFlowStartedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_login_flow_started_total",
		Help: "Total enable_access login flows launched, labeled by method (code, qr). Started minus mctl_login_flow_total is the flows cut off by a restart.",
	}, []string{"method"})

	r.LoginCallbackRejectedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_login_callback_rejected_total",
		Help: "Total rejected Telegram OIDC browser returns, labeled by route (oauth_callback, connect_done) and reason (missing_state, missing_code, oidc_error, unknown_state, expired_state, exchange_failed, prefetch_refused).",
	}, []string{"route", "reason"})

	r.RootMCPRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_root_mcp_requests_total",
		Help: "Total requests on the bare origin / served as MCP, labeled by method (GET, POST, DELETE, other) and ua_family (claude, chatgpt, perplexity, canary, other).",
	}, []string{"method", "ua_family"})

	r.LoginFlowDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "mctl_login_flow_seconds",
		Help:    "Wall-clock seconds from launching an enable_access login flow to its session being saved, successful flows only, by method (code, qr).",
		Buckets: []float64{5, 10, 20, 30, 45, 60, 90, 120, 180, 300, 600},
	}, []string{"method"})

	r.LoginLogOutTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_login_logout_total",
		Help: "Total enable_access logouts of sessions nobody holds any more, labeled by reason (unsaved, superseded) and outcome (ok, error).",
	}, []string{"reason", "outcome"})

	r.ConnectFirstCallTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_connect_first_call_total",
		Help: "Total authorization_code grants by whether the same user and client made a successful MCP call within five minutes: outcome ok, none_within_window or unknown (reason insert_error, restart, close_error). client is claude, chatgpt or other.",
	}, []string{"client", "outcome", "reason"})

	r.ConnectFirstCallErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_connect_first_call_errors_total",
		Help: "Total store errors in the connect first-call funnel, labeled by op: insert, close, classify, sweep.",
	}, []string{"op"})

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

	r.BotUpdatesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_bot_updates_total",
		Help: "Total inbound login-bot updates, labeled by update kind and dispatch outcome (handled, reachability_recorded, no_handler, unknown_chat, unsupported, duplicate, routing_mismatch, handler_error, dispatch_error).",
	}, []string{"kind", "outcome"})

	r.SessionsActiveGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_sessions_active",
		Help: "Count of non-revoked sessions that were last used within the last hour, including freshly created sessions not yet used. Refreshed every minute.",
	})

	r.SessionsBorrowTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_sessions_borrow_total",
		Help: "Total Pool.Borrow() calls, labeled by outcome. " +
			"expired_idle and expired_absolute are expected user-side TTL expirations; " +
			"no_session is a user with no connected Telegram account (Telegram is never called); " +
			"flood_wait and call_error are Telegram replies over a working session " +
			"(a rate limit, or a 400/403 for the caller's request). " +
			"Exclude all five from the availability SLI denominator. " +
			"traffic is user or canary; canary is the monitoring probe's account, excluded from the user-facing SLI.",
	}, []string{"result", "traffic"})

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

	r.AgentDeliveryUnknownTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mctl_agent_delivery_unknown_total",
		Help: "Communication-agent sends moved to delivery_unknown: outcome not observable, not retried, owner alerted.",
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

	r.WorkContextRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_work_context_requests_total",
		Help: "Total outbound mctl-api calls made by the work-context adapter (issue-443), labeled by route and outcome (ok, error).",
	}, []string{"route", "outcome"})

	r.WorkContextBindingsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_work_context_bindings_total",
		Help: "Total work_item_bindings writes attempted by the work-context adapter, labeled by result (created; reused: redelivery or same-issue rebind; refused: thread already bound to a different issue).",
	}, []string{"result"})

	r.HumanInputTelegramEventsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "human_input_telegram_events_total",
		Help: "Human-input (agent clarification) Telegram adapter events, labeled by event and outcome.",
	}, []string{"event", "outcome"})
	r.HumanInputDeliverLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "human_input_telegram_deliver_latency_seconds",
		Help:    "Seconds from a human-input delivery being queued to it being sent to Saved Messages.",
		Buckets: []float64{1, 5, 15, 30, 60, 120, 300, 900, 3600},
	})
	r.HumanInputRespondLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "human_input_telegram_respond_latency_seconds",
		Help:    "Seconds from a human-input question being delivered to the owner's answer being accepted.",
		Buckets: []float64{5, 15, 30, 60, 300, 900, 3600, 14400, 86400},
	})

	r.MediaGateRejectionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mctl_media_gate_rejections_total",
		Help: "Total media admission-gate refusals (MEDIA_MAX_CONCURRENT operations already in flight, no slot freed within the wait), labeled by tool.",
	}, []string{"tool"})

	r.MediaInflight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_media_inflight",
		Help: "Current number of media operations holding an admission-gate slot (see MEDIA_MAX_CONCURRENT). Always 0 when no gate is configured.",
	})

	r.EventsPublishedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mctl_events_published_total",
		Help: "Event envelopes published to Valkey Streams.",
	})
	r.EventsPublishFailuresTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mctl_events_publish_failures_total",
		Help: "Failed attempts to publish an event envelope; the row stays in the outbox.",
	})
	r.EventsOutboxBacklog = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mctl_events_outbox_backlog",
		Help: "Event envelopes committed but not yet published.",
	})

	// Register all collectors. MustRegister panics on duplicate names, which
	// cannot happen when New() is called once per process/test instance.
	reg.MustRegister(
		r.EventsPublishedTotal,
		r.EventsPublishFailuresTotal,
		r.EventsOutboxBacklog,
		r.HTTPRequestsTotal,
		r.AuthFailuresTotal,
		r.RateLimitEventsTotal,
		r.ToolInvocationsTotal,
		r.ToolInvocationDuration,
		r.ToolCallErrorsTotal,
		r.TelegramClientPoolSize,
		r.TelegramClientErrorsTotal,
		r.TelegramPoolCapacity,
		r.TelegramFloodWaitEventsTotal,
		r.TelegramFloodWaitSeconds,
		r.TelegramSponsoredTotal,
		r.SessionsConnectedTotal,
		r.SessionsRevokedTotal,
		r.BotUpdatesTotal,
		r.SessionsActiveGauge,
		r.OAuthPendingAuthSize,
		r.OAuthClientRegistrationsTotal,
		r.LoginPhoneStepTotal,
		r.LoginPhoneToCodeDuration,
		r.LoginFlowTotal,
		r.LoginFlowStartedTotal,
		r.LoginCallbackRejectedTotal,
		r.RootMCPRequestsTotal,
		r.LoginLogOutTotal,
		r.LoginFlowDuration,
		r.ConnectFirstCallTotal,
		r.ConnectFirstCallErrorsTotal,
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
		r.AgentDeliveryUnknownTotal,
		r.AgentPolicyDenialsTotal,
		r.AgentJobCostUSDTotal,
		r.AgentClaudeResultErrorsTotal,
		r.AgentCredentialDomain,
		r.WorkContextRequestsTotal,
		r.WorkContextBindingsTotal,
		r.HumanInputTelegramEventsTotal,
		r.HumanInputDeliverLatency,
		r.HumanInputRespondLatency,
		r.MediaGateRejectionsTotal,
		r.MediaInflight,
	)

	// Give every agent counter an alert reads through increase() a zero
	// baseline, before any work is accepted. A CounterVec creates its
	// children lazily, on first increment, so a counter whose first
	// *observed* sample is already non-zero makes increase() read 0 — that
	// sample becomes the baseline, and the alert misses the first, and
	// possibly only, occurrence it exists for. See issue #591.
	//
	// Four families, 4 + 6 + 138 = 148 series, every one of them a
	// compile-time-fixed label set. The per-loop comments below say what
	// each one costs and what breaks without it.
	for _, class := range claudeResultClasses {
		r.AgentClaudeResultErrorsTotal.WithLabelValues(class).Add(0)
	}
	// issue #705: the media gate's rejection counter gets the same zero
	// baseline, one series per gated tool. The runbook sizes the pod memory
	// limit from this series, so a first burst of rejections must register
	// in increase() and the family must read 0, not "no data", before it.
	for _, tool := range mediaGateTools {
		r.MediaGateRejectionsTotal.WithLabelValues(tool).Add(0)
	}
	// issue #960: the connect funnel alert reads increase() of every
	// outcome, and the first stuck connector is exactly the sample a lazily
	// created child would swallow. 3 clients x (ok, none, 3 unknown
	// reasons) = 15 series, plus 4 error ops.
	for _, client := range connectFirstCallClients {
		r.ConnectFirstCallTotal.WithLabelValues(client, "ok", "").Add(0)
		r.ConnectFirstCallTotal.WithLabelValues(client, "none_within_window", "").Add(0)
		for _, reason := range connectFirstCallUnknownReasons {
			r.ConnectFirstCallTotal.WithLabelValues(client, "unknown", reason).Add(0)
		}
	}
	for _, op := range connectFirstCallOps {
		r.ConnectFirstCallErrorsTotal.WithLabelValues(op).Add(0)
	}
	// issue #960 signals 2-4: the same reasoning for the login-path counters
	// an alert reads through increase(). 2 started + 2x7 finished + 2x7
	// rejections + 4x5 root requests = 50 series, all compile-time
	// constants. The finished side matters as much as the started side: the
	// runbook's "started minus finished" query is a vector subtraction, which
	// drops a method that has no finished series instead of reading it as 0.
	for _, method := range loginFlowMethods {
		r.LoginFlowStartedTotal.WithLabelValues(method).Add(0)
		for _, result := range loginFlowResults {
			r.LoginFlowTotal.WithLabelValues(method, result).Add(0)
		}
	}
	for _, route := range loginCallbackRoutes {
		for _, reason := range loginCallbackReasons {
			r.LoginCallbackRejectedTotal.WithLabelValues(route, reason).Add(0)
		}
	}
	for _, method := range rootMCPMethods {
		for _, family := range rootMCPUAFamilies {
			r.RootMCPRequestsTotal.WithLabelValues(method, family).Add(0)
		}
	}
	for _, result := range jobCostResults {
		r.AgentJobCostUSDTotal.WithLabelValues(result).Add(0)
	}
	// AgentJobsTotal gets the same treatment, for the same reason on the
	// other side of a division. MctlAgentJobCostHigh divides spend by
	// increase over the terminal job statuses; a lazily created denominator
	// makes the first finished job after a server restart read as zero
	// finished jobs, so the guarded ratio becomes +Inf and the rule can fire
	// on ordinary spend. Six statuses, closed set.
	for _, status := range jobStatuses {
		r.AgentJobsTotal.WithLabelValues(status).Add(0)
	}
	// AgentPolicyDenialsTotal too, all 138 combinations. This was originally
	// left lazy on the grounds that MctlAgentPolicyDenialRateHigh's "> 4"
	// floor means a single first denial could not fire it anyway. True, and
	// beside the point: if the first FIVE denials for one reason land between
	// two scrapes, Prometheus first observes the series at 5, every later
	// sample reads 5, and increase() over the window is 0 — so the rule
	// misses its own documented "at least 5 denials" case, in the burst
	// scenario ("worker hammering a paused account") it exists for. 138 zero
	// series is a cheap price for the floor meaning what it says.
	for _, reason := range policyDenyReasons {
		for _, surface := range policySurfaces {
			r.AgentPolicyDenialsTotal.WithLabelValues(reason, surface).Add(0)
		}
	}
	for _, route := range workContextRoutes {
		for _, outcome := range workContextOutcomes {
			r.WorkContextRequestsTotal.WithLabelValues(route, outcome).Add(0)
		}
	}
	for _, result := range workContextBindingResults {
		r.WorkContextBindingsTotal.WithLabelValues(result).Add(0)
	}
	for _, event := range []string{
		HumanInputEventDeliveryAttempt, HumanInputEventDelivered, HumanInputEventResponseReceived,
		HumanInputEventResponseSubmitted, HumanInputEventResponseRejected,
	} {
		for _, outcome := range []string{"ok", "error"} {
			r.HumanInputTelegramEventsTotal.WithLabelValues(event, outcome).Add(0)
		}
	}

	return r
}
