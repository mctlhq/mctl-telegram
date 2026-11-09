package workflows

import (
	"strings"
	"testing"
	"time"

	"go.temporal.io/sdk/converter"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridge"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridge/fake"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fakestore"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/leakcheck"
)

func happyOpen(h *harness) {
	h.consentAt(time.Minute, "n1", nil)
	h.signalAt(2*time.Minute, SigOpened)
}

// T13: outcome never paid; handoff opened ends in OUTCOME_UNKNOWN.
func TestHandoffOpenedOutcomeUnknown(t *testing.T) {
	h := newHarness(t, lunch())
	happyOpen(h)
	r := h.run()
	want := []string{"prepared", "quoted", "awaiting_consent", "basket_mutated", "verified", "handoff_issued", "handoff_opened", OutcomeUnknown}
	if strings.Join(r.States, ",") != strings.Join(want, ",") {
		t.Fatalf("states = %v", r.States)
	}
	for _, s := range r.States {
		if s == "paid" || s == "placed" {
			t.Fatalf("forbidden state %s", s)
		}
	}
	if h.Writes() != 1 || h.Bridge.Consumed() != 1 {
		t.Fatalf("writes=%d consumed=%d", h.Writes(), h.Bridge.Consumed())
	}
}

// Handoff open is revalidated: a revoked connection at open is not honoured.
func TestHandoffOpenRevalidates(t *testing.T) {
	h := newHarness(t, lunch())
	h.consentAt(time.Minute, "n1", nil)
	h.env.RegisterDelayedCallback(func() { h.Bridge.SetState("inst-alpha", fake.ConnRevoked) }, 90*time.Second)
	h.signalAt(2*time.Minute, SigOpened)
	r := h.run()
	if r.Status != StateRevoked || has(r.States, "handoff_opened") {
		t.Fatalf("states = %v", r.States)
	}
	if h.Store.HasSession(h.conn) {
		t.Fatal("session survived")
	}
}

// T6: install revision bump mid-order -> stale_install, no provider write.
func TestStaleInstallNoWrite(t *testing.T) {
	h := newHarness(t, lunch())
	h.env.RegisterDelayedCallback(func() { h.Bridge.BumpRevision("inst-alpha") }, 30*time.Second)
	h.consentAt(time.Minute, "n1", nil)
	r := h.run()
	if r.Status != StateStale || h.Writes() != 0 {
		t.Fatalf("status=%s writes=%d", r.Status, h.Writes())
	}
}

// A revoked connection before the write is a typed terminal state.
func TestConnectionRevokedBeforeWrite(t *testing.T) {
	h := newHarness(t, lunch())
	h.env.RegisterDelayedCallback(func() { h.Bridge.SetState("inst-alpha", fake.ConnRevoked) }, 30*time.Second)
	h.consentAt(time.Minute, "n1", nil)
	r := h.run()
	if r.Status != StateRevoked || h.Writes() != 0 || h.Acts.Drafts.Len() != 2 {
		t.Fatalf("status=%s writes=%d drafts=%d", r.Status, h.Writes(), h.Acts.Drafts.Len())
	}
	if h.Store.HasSession(h.conn) {
		t.Fatal("session survived")
	}
	if !h.Store.HasSession("tenant-beta|gcn_beta1") {
		t.Fatal("another tenant's session was purged")
	}
}

// T5: a fee change between consent and verify -> basket_changed, no handoff.
func TestFeeChangeReasks(t *testing.T) {
	h := newHarness(t, lunch())
	h.Store.SetBumpFeeOnWrite(50)
	h.consentAt(time.Minute, "n1", nil)
	r := h.run()
	if r.Status != "basket_changed" || has(r.States, "handoff_issued") {
		t.Fatalf("states = %v", r.States)
	}
}

// T8: expired consent, and expired handoff.
func TestConsentAndHandoffExpiry(t *testing.T) {
	h := newHarness(t, lunch())
	if r := h.run(); r.Status != "consent_expired" || h.Writes() != 0 {
		t.Fatalf("status = %s", r.Status)
	}
	h2 := newHarness(t, lunch())
	h2.consentAt(time.Minute, "n1", nil) // never opens the handoff
	r2 := h2.run()
	if r2.Status != "consent_expired" || !has(r2.States, "handoff_issued") {
		t.Fatalf("states = %v", r2.States)
	}
}

// T9: revoke mid-wait stops the order and deletes state.
func TestRevokedMidWaitDeletesState(t *testing.T) {
	h := newHarness(t, lunch())
	h.signalAt(time.Minute, SigRevoked)
	r := h.run()
	if r.Status != StateRevoked || h.Store.HasSession(h.conn) || h.Writes() != 0 {
		t.Fatalf("status=%s", r.Status)
	}
	if _, ok := h.Acts.Drafts.Get("tenant-alpha", "ord-1"); ok {
		t.Fatal("order draft survived")
	}
}

// T9b: revocation after handoff_issued purges state.
func TestRevokedAfterHandoffIssued(t *testing.T) {
	h := newHarness(t, lunch())
	h.consentAt(time.Minute, "n1", nil)
	h.signalAt(2*time.Minute, SigRevoked)
	r := h.run()
	if r.Status != StateRevoked || !has(r.States, "handoff_issued") || h.Store.HasSession(h.conn) {
		t.Fatalf("states = %v", r.States)
	}
}

// T9c: revoke racing with the provider write: no exit bypasses cleanup and
// no handoff follows.
func TestRevokedDuringProviderWrite(t *testing.T) {
	h := newHarness(t, lunch())
	h.Acts.AfterProviderWrite = func() {
		h.Bridge.SetState("inst-alpha", fake.ConnRevoked)
		h.env.SignalWorkflow(SigRevoked, nil)
	}
	h.consentAt(time.Minute, "n1", nil)
	r := h.run()
	if r.Status != StateRevoked || has(r.States, "handoff_issued") || h.Store.HasSession(h.conn) {
		t.Fatalf("status=%s states=%v", r.Status, r.States)
	}
}

// Revoke wins over a cancel that arrives with it while the write is in flight.
func TestRevokeWinsOverCancel(t *testing.T) {
	h := newHarness(t, lunch())
	h.Acts.AfterProviderWrite = func() {
		h.env.SignalWorkflow(SigCancel, nil)
		h.env.SignalWorkflow(SigRevoked, nil)
	}
	h.consentAt(time.Minute, "n1", nil)
	r := h.run()
	if r.Status != StateRevoked || h.Store.HasSession(h.conn) {
		t.Fatalf("status = %s", r.Status)
	}
}

// Owner cancel purges the order draft but keeps the install connection.
func TestCancelKeepsConnection(t *testing.T) {
	h := newHarness(t, lunch())
	h.signalAt(time.Minute, SigCancel)
	r := h.run()
	if r.Status != StateCancelled || !h.Store.HasSession(h.conn) {
		t.Fatalf("status = %s", r.Status)
	}
	if _, ok := h.Acts.Drafts.Get("tenant-alpha", "ord-1"); ok {
		t.Fatal("order draft survived cancel")
	}
}

// Cancellation after each activity boundary reaches a terminal state.
func TestCancelAtBoundaries(t *testing.T) {
	for _, hook := range []string{"after_write"} {
		h := newHarness(t, lunch())
		h.Acts.AfterProviderWrite = func() { h.env.SignalWorkflow(SigCancel, nil) }
		h.consentAt(time.Minute, "n1", nil)
		r := h.run()
		if r.Status != StateCancelled || has(r.States, "handoff_issued") {
			t.Fatalf("%s: states = %v", hook, r.States)
		}
	}
	h := newHarness(t, lunch())
	h.consentAt(time.Minute, "n1", nil)
	h.signalAt(2*time.Minute, SigCancel) // after handoff issued
	if r := h.run(); r.Status != StateCancelled || !has(r.States, "handoff_issued") {
		t.Fatalf("states = %v", r.States)
	}
}

// T4: an existing provider basket is a collision, never silently overwritten.
func TestBasketCollision(t *testing.T) {
	h := newHarness(t, lunch())
	other := fakestore.Draft{Store: "s1", Lines: []fakestore.Line{{ItemID: "m2", Qty: 2}}}
	h.Store.SeedCart(h.conn, other)
	h.consentAt(time.Minute, "n1", nil)
	r := h.run()
	if r.Status != "consent_expired" {
		t.Fatalf("status = %s", r.Status)
	}
	if got := h.Store.CartOf(h.conn); len(got.Lines) != 1 || got.Lines[0].ItemID != "m2" {
		t.Fatalf("existing cart was overwritten: %+v", got)
	}
	h2 := newHarness(t, lunch())
	h2.Store.SeedCart(h2.conn, other)
	h2.consentAt(time.Minute, "n1", func(s *ConsentSignal) { s.ReplaceExisting = true })
	h2.signalAt(5*time.Minute, SigCancel)
	if st := h2.run(); !has(st.States, "verified") {
		t.Fatalf("states = %v", st.States)
	}
}

// T3 (workflow side): a missing required modifier asks instead of quoting.
func TestMissingModifierAsks(t *testing.T) {
	h := newHarness(t, fakestore.Draft{Store: "s1", Lines: []fakestore.Line{{ItemID: "m1", Qty: 1}}})
	r := h.run()
	if r.Status != "needs_input" || has(r.States, "quoted") {
		t.Fatalf("states = %v", r.States)
	}
}

// T11: reads retry; a write timeout is verified by read-back, never re-sent.
func TestRetryDiscipline(t *testing.T) {
	h := newHarness(t, lunch())
	h.Store.SetTransientReads(2)
	h.Store.SetWriteTimeoutOnce()
	h.consentAt(time.Minute, "n1", nil)
	h.signalAt(10*time.Minute, SigCancel)
	r := h.run()
	if !has(r.States, "verified") || h.Writes() != 1 {
		t.Fatalf("states = %v writes=%d", r.States, h.Writes())
	}
}

// A write whose outcome cannot be verified ends OUTCOME_UNKNOWN.
func TestUnverifiedWriteIsOutcomeUnknown(t *testing.T) {
	h := newHarness(t, lunch())
	h.Store.SetWriteLostOnce()
	h.consentAt(time.Minute, "n1", nil)
	r := h.run()
	if r.Status != OutcomeUnknown || has(r.States, "handoff_issued") {
		t.Fatalf("states = %v", r.States)
	}
}

// Bridge failure fails closed: no write, typed state.
func TestBridgeDownFailsClosed(t *testing.T) {
	h := newHarness(t, lunch())
	h.Bridge.SetFault(fake.FaultTransport)
	r := h.run()
	if r.Status != "bridge_unavailable" || h.Writes() != 0 {
		t.Fatalf("status = %s", r.Status)
	}
}

// T12: duplicate consent delivery is counted, not re-evaluated.
func TestDuplicateConsent(t *testing.T) {
	h := newHarness(t, lunch())
	h.consentAt(10*time.Second, "same", func(s *ConsentSignal) { s.Fingerprint = "stale" })
	h.consentAt(30*time.Second, "same", nil)
	h.consentAt(time.Minute, "n2", nil)
	h.signalAt(10*time.Minute, SigCancel)
	r := h.run()
	if st := h.status(); st.Duplicates != 1 || st.Rejected != 1 {
		t.Fatalf("duplicates = %d rejected = %d", st.Duplicates, st.Rejected)
	}
	if h.Writes() != 1 || !has(r.States, "handoff_issued") {
		t.Fatalf("writes=%d states=%v", h.Writes(), r.States)
	}
}

// T11 (leaks): canaries never reach history payloads, logs, metrics or results.
func TestNoCanaryInHistoryLogsMetrics(t *testing.T) {
	h := newHarness(t, lunch())
	happyOpen(h)
	r := h.run()
	if hits := h.rec.Hits(); len(hits) > 0 {
		t.Fatalf("canaries in payloads: %v", hits)
	}
	if h.rec.Len() == 0 {
		t.Fatal("recorder saw no payloads; converter not in use")
	}
	if hits := leakcheck.Find(h.Logs.Bytes()); len(hits) > 0 {
		t.Fatalf("canaries in logs: %v", hits)
	}
	if h.Logs.Len() == 0 {
		t.Fatal("no audit logs emitted")
	}
	fams, err := h.Metrics.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if leakcheck.Find([]byte(l.GetName()+l.GetValue())) != nil {
					t.Fatalf("canary in metric label %s", f.GetName())
				}
			}
		}
	}
	if hits := leakcheck.Find([]byte(strings.Join(r.States, ","))); len(hits) > 0 {
		t.Fatal("canary in result")
	}
}

// Positive control: the converter rejects a payload that carries a canary.
func TestConverterRejectsCanary(t *testing.T) {
	h := newHarness(t, lunch())
	dc := canaryConverter{DataConverter: converter.GetDefaultDataConverter(), rec: h.rec}
	if _, err := dc.ToPayloads("leak: " + leakcheck.Canaries[0]); err == nil {
		t.Fatal("canary in a payload must be rejected")
	}
	if _, err := dc.ToPayloads("opaque-ref-1"); err != nil {
		t.Fatal(err)
	}
}


// Matching a pre-existing fake basket must not allow a synthetic handoff
// without recorded proof that this workflow consumed the bound aar_ receipt.
func TestMatchingBasketCannotBypassApprovalBeforeHandoff(t *testing.T) {
	for _, tc := range []string{"unconsumed", "wrong", "expired", "replayed"} {
		t.Run(tc, func(t *testing.T) {
			h := newHarness(t, lunch())
			h.Store.SeedCart(h.conn, lunch())
			switch tc {
			case "wrong":
				h.snap.Req.ApprovalRef = "aar_unrelated"
			case "expired":
				h.Bridge.AddReceipt("aar_alpha1", fake.Binding{
					Execution: h.Req.ExecutionRef, Tenant: h.Req.TenantRef,
					Owner: h.Req.OwnerRef, Connection: h.Req.ConnectionRef,
					IntentHash: h.Req.IntentHash, Fingerprint: h.FP,
					InstallRevision: h.Req.InstallRevision,
				}, time.Now().Add(-time.Second))
			case "replayed":
				if err := h.Bridge.ConsumeApproval(context.Background(), h.Req, h.FP); err != nil {
					t.Fatal(err)
				}
			}
			h.consentAt(time.Minute, "approve-existing-basket", func(s *ConsentSignal) {
				s.ReplaceExisting = true
			})
			r := h.run()
			if r.Status != bridge.CodeApprovalInvalid || has(r.States, "handoff_issued") ||
				has(r.States, "handoff_opened") || h.Writes() != 0 {
				t.Fatalf("receipt=%s status=%s states=%v writes=%d", tc, r.Status, r.States, h.Writes())
			}
		})
	}
}
