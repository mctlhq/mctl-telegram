package metrics

import (
	"testing"
)

// gatheredSnapshotAge scrapes the registry the way /metrics does and returns
// the gauge's value, failing if it is not exported.
func gatheredSnapshotAge(t *testing.T, r *Registry) float64 {
	t.Helper()
	mfs, err := r.Prometheus.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == WorkerTokenRevocationSnapshotAgeName {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatalf("%s not exported", WorkerTokenRevocationSnapshotAgeName)
	return 0
}

// The gauge is computed at scrape time: it follows its source between
// scrapes with nothing calling Set, which is what lets it rise during an
// outage that has no traffic at all.
func TestRegisterWorkerTokenRevocationSnapshotAge_ReadsAtScrape(t *testing.T) {
	r := New()
	age := 2.0
	if err := r.RegisterWorkerTokenRevocationSnapshotAge(func() float64 { return age }); err != nil {
		t.Fatalf("register: %v", err)
	}
	for _, want := range []float64{2, 47.5} {
		age = want
		if got := gatheredSnapshotAge(t, r); got != want {
			t.Fatalf("scraped age = %v, want %v", got, want)
		}
	}
	if err := r.RegisterWorkerTokenRevocationSnapshotAge(func() float64 { return 0 }); err == nil {
		t.Fatal("second registration succeeded; want a duplicate-registration error")
	}
}
