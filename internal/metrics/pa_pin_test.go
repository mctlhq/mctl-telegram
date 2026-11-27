package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// An observed listing sets drift and clears unknown; an unobserved one
// removes the drift series instead of reporting 0, and a later observation
// brings it back. Denied counts of a cleared reason drop to 0.
func TestPAPinGauges(t *testing.T) {
	r := New()
	reasons := []string{"not_pinned", "changed_description"}
	r.PAPinObserved("tg", true, map[string]int{"not_pinned": 3, "changed_description": 1}, reasons)
	if testutil.ToFloat64(r.PAPinDrift.WithLabelValues("tg")) != 1 ||
		testutil.ToFloat64(r.PAPinListingUnknown.WithLabelValues("tg")) != 0 ||
		testutil.ToFloat64(r.PAPinDeniedTools.WithLabelValues("tg", "changed_description")) != 1 {
		t.Fatal("drift observation not recorded")
	}
	r.PAPinUnknown("tg")
	if n := testutil.CollectAndCount(r.PAPinDrift); n != 0 {
		t.Fatalf("drift series kept while unknown: %d", n)
	}
	if n := testutil.CollectAndCount(r.PAPinDeniedTools); n != 0 {
		t.Fatalf("denied-tool series kept while unknown: %d", n)
	}
	if testutil.ToFloat64(r.PAPinListingUnknown.WithLabelValues("tg")) != 1 {
		t.Fatal("unknown not set")
	}
	r.PAPinObserved("tg", false, map[string]int{"not_pinned": 3}, reasons)
	if testutil.ToFloat64(r.PAPinDrift.WithLabelValues("tg")) != 0 ||
		testutil.ToFloat64(r.PAPinListingUnknown.WithLabelValues("tg")) != 0 ||
		testutil.ToFloat64(r.PAPinDeniedTools.WithLabelValues("tg", "changed_description")) != 0 {
		t.Fatal("recovery not recorded")
	}
	r.CountPAListingFailure("tg", "unauthorized")
	if testutil.ToFloat64(r.PAPinListingFailures.WithLabelValues("tg", "unauthorized")) != 1 {
		t.Fatal("listing failure not counted")
	}
	r.CountPADispatch("tg", "refused", "flag_off")
	if testutil.ToFloat64(r.PADispatchTotal.WithLabelValues("tg", "refused", "flag_off")) != 1 {
		t.Fatal("dispatch not counted")
	}
	r.PreparePAWriteListingRefusals("alice", []string{"server_unavailable", "tool_changed"})
	if n := testutil.CollectAndCount(r.PAWriteListingRefusals); n != 2 {
		t.Fatalf("%d write listing refusal series prepared, want 2", n)
	}
	r.CountPAWriteListingRefusal("alice", "tool_changed")
	if testutil.ToFloat64(r.PAWriteListingRefusals.WithLabelValues("alice", "tool_changed")) != 1 ||
		testutil.ToFloat64(r.PAWriteListingRefusals.WithLabelValues("alice", "server_unavailable")) != 0 {
		t.Fatal("write listing refusal not counted under its reason")
	}
}
