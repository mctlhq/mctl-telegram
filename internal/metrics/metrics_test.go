package metrics

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
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
	"mctl_sessions_connected_total",
	"mctl_sessions_revoked_total",
	"mctl_sessions_active",
	"mctl_sessions_borrow_total",
}

// TestNew_RegistersAllMetrics verifies that Gather() returns a MetricFamily
// for each of the 14 metric names defined in the design.
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
	reg.SessionsConnectedTotal.Add(0)
	reg.SessionsRevokedTotal.WithLabelValues("disconnect").Add(0)
	reg.SessionsActiveGauge.Set(0)
	reg.SessionsBorrowTotal.WithLabelValues("ok").Add(0)

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
