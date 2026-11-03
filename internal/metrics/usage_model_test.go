package metrics

import (
	"fmt"
	"testing"
)

// The model label is bounded: a worker that reports a new model string on
// every settle cannot grow the series count past MaxUsageModelLabels + 2.
// Mutations: return model unconditionally from UsageModel; ignore mayClaim.
func TestUsageModel_Bounded(t *testing.T) {
	r := New()
	if got := r.UsageModel("", true); got != "unknown" {
		t.Fatalf("empty model = %q, want unknown", got)
	}
	for i := 0; i < MaxUsageModelLabels; i++ {
		m := fmt.Sprintf("model-%d", i)
		if got := r.UsageModel(m, true); got != m {
			t.Fatalf("model %d = %q, want itself", i, got)
		}
	}
	if got := r.UsageModel("one-too-many", true); got != "other" {
		t.Fatalf("model past the bound = %q, want other", got)
	}
	if got := r.UsageModel("model-3", false); got != "model-3" {
		t.Fatalf("known model after the bound = %q, want itself", got)
	}
	labels := map[string]bool{}
	for i := 0; i < 1000; i++ {
		labels[r.UsageModel(fmt.Sprintf("flood-%d", i), true)] = true
	}
	if len(labels) != 1 || !labels["other"] {
		t.Fatalf("flood produced labels %v, want only other", labels)
	}
	fresh := New()
	if got := fresh.UsageModel("unclaimed", false); got != "other" {
		t.Fatalf("mayClaim=false took a slot: %q", got)
	}
	if got := fresh.UsageModel("unclaimed", true); got != "unclaimed" {
		t.Fatalf("slot after a refused claim = %q, want unclaimed", got)
	}
	var nilReg *Registry
	if got := nilReg.UsageModel("x", true); got != "other" {
		t.Fatalf("nil registry = %q, want other", got)
	}
}
