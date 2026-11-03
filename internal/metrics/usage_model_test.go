package metrics

import (
	"fmt"
	"testing"
)

// The model label is bounded: a worker that reports a new model string on
// every settle cannot grow the series count past MaxUsageModelLabels + 2.
// Mutation: return model unconditionally from UsageModel.
func TestUsageModel_Bounded(t *testing.T) {
	r := New()
	if got := r.UsageModel(""); got != "unknown" {
		t.Fatalf("empty model = %q, want unknown", got)
	}
	for i := 0; i < MaxUsageModelLabels; i++ {
		m := fmt.Sprintf("model-%d", i)
		if got := r.UsageModel(m); got != m {
			t.Fatalf("model %d = %q, want itself", i, got)
		}
	}
	if got := r.UsageModel("one-too-many"); got != "other" {
		t.Fatalf("model past the bound = %q, want other", got)
	}
	if got := r.UsageModel("model-3"); got != "model-3" {
		t.Fatalf("known model after the bound = %q, want itself", got)
	}
	labels := map[string]bool{}
	for i := 0; i < 1000; i++ {
		labels[r.UsageModel(fmt.Sprintf("flood-%d", i))] = true
	}
	if len(labels) != 1 || !labels["other"] {
		t.Fatalf("flood produced labels %v, want only other", labels)
	}
	var nilReg *Registry
	if got := nilReg.UsageModel("x"); got != "other" {
		t.Fatalf("nil registry = %q, want other", got)
	}
}
