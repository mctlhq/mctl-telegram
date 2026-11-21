package linking_test

import (
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

// TestPendingMaxAge_Bounds pins the stale-pending window (#1338). It must
// outlast every secret that bounds a pending state, with a margin for clock
// skew between replicas, or the sweep would fail a connection whose secret
// is still valid. It must stay at most 15 minutes, or a stranded connection
// keeps its wrapped key and any unrevoked tokens for longer than the flow
// can need them.
func TestPendingMaxAge_Bounds(t *testing.T) {
	longest := max(linking.LinkTokenTTL, linking.StateTTL, linking.CompletionTTL, linking.ConfirmTTL)
	if linking.PendingMaxAge <= longest {
		t.Errorf("PendingMaxAge = %s, want more than the longest secret TTL %s", linking.PendingMaxAge, longest)
	}
	if linking.PendingMaxAge > 15*time.Minute {
		t.Errorf("PendingMaxAge = %s, want at most 15m", linking.PendingMaxAge)
	}
}
