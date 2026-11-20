package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func paFamilies(t *testing.T, r *Registry) map[string]int {
	t.Helper()
	mfs, err := r.Prometheus.Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, mf := range mfs {
		out[mf.GetName()] = len(mf.GetMetric())
	}
	return out
}

// TestPAWebhookGauges_AbsentUntilStarted: with the PA off nothing exports
// a webhook state, so no "unreadable" alert can fire where there is no
// webhook.
func TestPAWebhookGauges_AbsentUntilStarted(t *testing.T) {
	r := New()
	f := paFamilies(t, r)
	for _, name := range []string{
		"mctl_pa_webhook_info_up", "mctl_pa_webhook_info_ok",
		"mctl_pa_webhook_info_last_success_timestamp_seconds", "mctl_pa_webhook_problem",
	} {
		if f[name] != 0 {
			t.Fatalf("%s exported before the monitor started", name)
		}
	}
	r.StartPAWebhookMonitor()
	f = paFamilies(t, r)
	if f["mctl_pa_webhook_info_up"] != 1 || f["mctl_pa_webhook_info_last_success_timestamp_seconds"] != 1 {
		t.Fatalf("after start: %v", f)
	}
	if v := testutil.ToFloat64(r.pa.up.WithLabelValues()); v != 0 {
		t.Fatalf("up before the first read = %v, want 0", v)
	}
}

// TestPAWebhookGauges_UnreadableIsNotHealthy: a failed read sets up and ok
// to 0 and withdraws the per-state series; it never leaves the last
// healthy values to be read as current (I9).
func TestPAWebhookGauges_UnreadableIsNotHealthy(t *testing.T) {
	r := New()
	r.StartPAWebhookMonitor()
	at := time.Unix(1_800_000_000, 0)
	r.ObservePAWebhookInfo(true, nil, 3, 0, at)
	if testutil.ToFloat64(r.pa.ok.WithLabelValues()) != 1 || testutil.ToFloat64(r.pa.up.WithLabelValues()) != 1 {
		t.Fatal("healthy read not exported")
	}
	if testutil.ToFloat64(r.pa.pending.WithLabelValues()) != 3 || testutil.ToFloat64(r.pa.lastOK.WithLabelValues()) != float64(at.Unix()) {
		t.Fatal("state not exported")
	}
	r.ObservePAWebhookInfo(false, nil, 0, 0, at.Add(time.Minute))
	if testutil.ToFloat64(r.pa.ok.WithLabelValues()) != 0 || testutil.ToFloat64(r.pa.up.WithLabelValues()) != 0 {
		t.Fatal("unreadable read left ok or up at 1")
	}
	f := paFamilies(t, r)
	for _, name := range []string{"mctl_pa_webhook_problem", "mctl_pa_webhook_pending_updates", "mctl_pa_webhook_info_last_error_timestamp_seconds"} {
		if f[name] != 0 {
			t.Fatalf("%s still exported while unreadable", name)
		}
	}
	// The last success keeps its time, so staleness is measurable.
	if testutil.ToFloat64(r.pa.lastOK.WithLabelValues()) != float64(at.Unix()) {
		t.Fatal("last success moved on an unreadable read")
	}
	if testutil.ToFloat64(r.pa.checks.WithLabelValues("unreadable")) != 1 {
		t.Fatal("unreadable check not counted")
	}
}

func TestPAWebhookGauges_Problems(t *testing.T) {
	r := New()
	r.StartPAWebhookMonitor()
	r.ObservePAWebhookInfo(true, []string{"url_changed"}, 0, 0, time.Unix(1_800_000_000, 0))
	if testutil.ToFloat64(r.pa.ok.WithLabelValues()) != 0 {
		t.Fatal("a problem left ok at 1")
	}
	for _, p := range PAWebhookProblems {
		want := 0.0
		if p == "url_changed" {
			want = 1
		}
		if got := testutil.ToFloat64(r.pa.problem.WithLabelValues(p)); got != want {
			t.Fatalf("problem %s = %v, want %v", p, got, want)
		}
	}
}

// TestPACounters_PreCreated: every outcome series exists at zero, so the
// first event after a restart is visible to increase().
func TestPACounters_PreCreated(t *testing.T) {
	f := paFamilies(t, New())
	if f["mctl_pa_outbox_total"] != len(PAOutboxOutcomes) || f["mctl_pa_updates_total"] != len(PAUpdateOutcomes) {
		t.Fatalf("families %v", f)
	}
}

// TestPAWebhookProblemChecks_CountsChecks: the counter moves once per
// readable check that found the problem, survives an unreadable check, and
// exists at zero from the monitor start, so MctlPAWebhookMisconfigured can
// count checks rather than scrapes of the problem gauge.
func TestPAWebhookProblemChecks_CountsChecks(t *testing.T) {
	r := New()
	if f := paFamilies(t, r); f["mctl_pa_webhook_problem_checks_total"] != 0 {
		t.Fatal("problem checks exported before the monitor started")
	}
	r.StartPAWebhookMonitor()
	if f := paFamilies(t, r); f["mctl_pa_webhook_problem_checks_total"] != len(PAWebhookProblems) {
		t.Fatalf("after start: %v", f)
	}
	at := time.Unix(1_800_000_000, 0)
	r.ObservePAWebhookInfo(true, []string{"url_changed", "url_changed"}, 0, 0, at)
	r.ObservePAWebhookInfo(false, nil, 0, 0, at.Add(5*time.Minute))
	r.ObservePAWebhookInfo(true, nil, 0, 0, at.Add(10*time.Minute))
	r.ObservePAWebhookInfo(true, []string{"url_changed"}, 0, 0, at.Add(15*time.Minute))
	for _, p := range PAWebhookProblems {
		want := 0.0
		if p == "url_changed" {
			want = 2
		}
		if got := testutil.ToFloat64(r.pa.problemChecks.WithLabelValues(p)); got != want {
			t.Fatalf("problem checks %s = %v, want %v", p, got, want)
		}
	}
}
