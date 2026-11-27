package main

import (
	"database/sql"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
)

// TestPAWrites_CountsListingRefusalsAndTheAuditQueue: the service as it is
// built counts a call that the listing read for its card refused, and gives
// the audit event sweeper the same registry (S2-A6, S2-A8).
func TestPAWrites_CountsListingRefusalsAndTheAuditQueue(t *testing.T) {
	forEachPAStore(t, func(t *testing.T, store *db.Store, conn *sql.DB) {
		reg := metrics.New()
		paE2EMetrics = reg
		t.Cleanup(func() { paE2EMetrics = nil })
		e := newPAEval(t, store, conn)
		if e.rt.auditEvents == nil || e.rt.auditEvents.Metrics != connector.AuditEventMetrics(reg) {
			t.Fatalf("the audit event sweeper does not count to the service's registry: %+v", e.rt.auditEvents)
		}
		refused := reg.PAWriteListingRefusals.WithLabelValues("alice", connector.ReasonToolChanged)
		// One good card first: the run path holds the listing it read.
		e.oneCard("play jazz on the kitchen speaker", paPlayTool, paPlaySent)
		if v := testutil.ToFloat64(refused); v != 0 {
			t.Fatalf("a card that was shown counted %v refusals", v)
		}
		e.alice.drifted.Store(true)
		before := len(e.approvalCards())
		e.turn("play it again", paAsk(paPlayTool, paPlaySent))
		if n := len(e.approvalCards()); n != before {
			t.Fatalf("a drifted tool got %d new cards", n-before)
		}
		if v := testutil.ToFloat64(refused); v != 1 {
			t.Fatalf("the card's listing refusal was counted %v times, want 1", v)
		}
	})
}
