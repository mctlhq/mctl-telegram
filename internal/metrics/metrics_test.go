package metrics

import (
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// expectedMetricNames lists every metric family that New() must register.
var expectedMetricNames = []string{
	"mctl_http_requests_total",
	"mctl_auth_failures_total",
	"mctl_rate_limit_events_total",
	"mctl_tool_invocations_total",
	"mctl_tool_invocation_duration_seconds",
	"mctl_telegram_client_pool_size",
	"mctl_telegram_pool_capacity",
	"mctl_telegram_client_errors_total",
	"mctl_telegram_flood_wait_events_total",
	"mctl_oauth_pending_auth_size",
	"mctl_login_phone_step_total",
	"mctl_login_phone_to_code_duration_seconds",
	"mctl_sessions_connected_total",
	"mctl_sessions_revoked_total",
	"mctl_sessions_active",
	"mctl_sessions_borrow_total",
	"mctl_telegram_replica_id",
	"mctl_bridge_active_daemons",
	"mctl_bridge_calls_total",
}

// TestNew_RegistersAllMetrics verifies that Gather() returns a MetricFamily
// for each of the metric names defined in the design.
func TestNew_RegistersAllMetrics(t *testing.T) {
	reg := New()
	// Force each metric to be "used" so the registry includes them in Gather.
	// Prometheus lazy-registers some vec children until first use; we need the
	// family header to appear even with no observations.
	reg.HTTPRequestsTotal.WithLabelValues("GET", "/healthz", "200").Add(0)
	reg.AuthFailuresTotal.WithLabelValues("other", "local-dev").Add(0)
	reg.RateLimitEventsTotal.WithLabelValues("anon").Add(0)
	reg.ToolInvocationsTotal.WithLabelValues("list_dialogs", "ok").Add(0)
	reg.ToolInvocationDuration.WithLabelValues("list_dialogs").Observe(0)
	reg.TelegramClientPoolSize.Set(0)
	reg.TelegramPoolCapacity.Set(0)
	reg.TelegramClientErrorsTotal.Add(0)
	reg.TelegramFloodWaitEventsTotal.WithLabelValues("list_dialogs").Add(0)
	reg.OAuthPendingAuthSize.Set(0)
	reg.LoginPhoneStepTotal.WithLabelValues("ok").Add(0)
	reg.LoginPhoneToCodeDuration.Observe(0)
	reg.SessionsConnectedTotal.Add(0)
	reg.SessionsRevokedTotal.WithLabelValues("disconnect").Add(0)
	reg.SessionsActiveGauge.Set(0)
	reg.SessionsBorrowTotal.WithLabelValues("ok").Add(0)
	reg.TelegramReplicaID.WithLabelValues("pod-0").Set(1)
	reg.BridgeActiveDaemons.Set(0)
	reg.BridgeCallsTotal.WithLabelValues("list_dialogs", "ok").Add(0)

	mfs, err := reg.Prometheus.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	gathered := map[string]*dto.MetricFamily{}
	for _, mf := range mfs {
		gathered[mf.GetName()] = mf
	}
	for _, name := range expectedMetricNames {
		if _, ok := gathered[name]; !ok {
			t.Errorf("metric family %q not found in gathered output", name)
		}
	}
}

// TestSessionsBorrowTotal_AllLabelValues verifies that SessionsBorrowTotal
// accepts all four result label values without panicking and that each
// produces an independent series in the gathered output.
func TestSessionsBorrowTotal_AllLabelValues(t *testing.T) {
	reg := New()
	results := []string{"ok", "expired_idle", "expired_absolute", "error"}
	for _, r := range results {
		reg.SessionsBorrowTotal.WithLabelValues(r).Inc()
	}

	mfs, err := reg.Prometheus.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var found *dto.MetricFamily
	for _, mf := range mfs {
		if mf.GetName() == "mctl_sessions_borrow_total" {
			found = mf
			break
		}
	}
	if found == nil {
		t.Fatal("mctl_sessions_borrow_total not found in gathered output")
	}
	if got := len(found.GetMetric()); got != len(results) {
		t.Errorf("expected %d metric series, got %d", len(results), got)
	}
}

// TestObserveLoginPhoneStep verifies that the counter increments for every
// result and that the latency histogram is observed only for "ok".
func TestObserveLoginPhoneStep(t *testing.T) {
	reg := New()
	reg.ObserveLoginPhoneStep("ok", 3.2)
	reg.ObserveLoginPhoneStep("timeout", 90)
	reg.ObserveLoginPhoneStep("error", 1)

	if got := testutil.ToFloat64(reg.LoginPhoneStepTotal.WithLabelValues("ok")); got != 1 {
		t.Errorf("ok counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(reg.LoginPhoneStepTotal.WithLabelValues("timeout")); got != 1 {
		t.Errorf("timeout counter = %v, want 1", got)
	}
	if got := testutil.ToFloat64(reg.LoginPhoneStepTotal.WithLabelValues("error")); got != 1 {
		t.Errorf("error counter = %v, want 1", got)
	}

	// Only the single "ok" observation should land in the histogram.
	mfs, err := reg.Prometheus.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var found bool
	for _, mf := range mfs {
		if mf.GetName() == "mctl_login_phone_to_code_duration_seconds" {
			found = true
			if got := mf.GetMetric()[0].GetHistogram().GetSampleCount(); got != 1 {
				t.Errorf("histogram sample count = %d, want 1 (ok only)", got)
			}
		}
	}
	if !found {
		t.Error("mctl_login_phone_to_code_duration_seconds not found in gathered output")
	}
}

// TestReplicaIDGauge verifies the mctl_telegram_replica_id info gauge:
// setting the gauge for two distinct replica_id labels produces two distinct
// time-series each with value 1.
func TestReplicaIDGauge(t *testing.T) {
	reg := New()

	reg.TelegramReplicaID.WithLabelValues("pod-0").Set(1)
	reg.TelegramReplicaID.WithLabelValues("pod-1").Set(1)

	const expected = `
# HELP mctl_telegram_replica_id Info gauge (always 1) identifying this replica. Label replica_id is sourced from REPLICA_ID / POD_NAME env vars.
# TYPE mctl_telegram_replica_id gauge
mctl_telegram_replica_id{replica_id="pod-0"} 1
mctl_telegram_replica_id{replica_id="pod-1"} 1
`
	if err := testutil.CollectAndCompare(reg.TelegramReplicaID, strings.NewReader(expected)); err != nil {
		t.Errorf("CollectAndCompare: %v", err)
	}
}
