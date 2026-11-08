package workflows

import (
	"strings"
	"testing"
	"time"

	"go.temporal.io/sdk/converter"

	"github.com/mctlhq/mctl-telegram/test/glovo-poc/controlplane"
	"github.com/mctlhq/mctl-telegram/test/glovo-poc/fakeglovo"
	"github.com/mctlhq/mctl-telegram/test/glovo-poc/leakcheck"
)

func happyOpen(h *harness) {
	h.consentAt(time.Minute, "n1", nil)
	h.env.RegisterDelayedCallback(func() {
		st := h.status()
		tok := h.cp.Outbox[len(h.cp.Outbox)-1]
		err := h.cp.OpenHandoff(tok, controlplane.Request{Principal: "principal-alice", Tenant: "tenant-alpha", OrderID: "ord-1"}, st.Fingerprint)
		if err != nil {
			h.t.Errorf("open handoff: %v", err)
		}
		h.env.SignalWorkflow(SigOpened, nil)
	}, 2*time.Minute)
}

// T7 + T13: single use handoff, outcome never paid.
func TestT7T13_HandoffSingleUseAndOutcomeUnknown(t *testing.T) {
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
	// second use refused
	tok := h.cp.Outbox[0]
	st := controlplane.Request{Principal: "principal-alice", Tenant: "tenant-alpha", OrderID: "ord-1"}
	if err := h.cp.OpenHandoff(tok, st, h.status().Fingerprint); err == nil {
		t.Fatal("second use must be refused")
	}
}

// T6: install revision bump mid-order -> stale_install, no provider write.
func TestT6_StaleInstallNoWrite(t *testing.T) {
	h := newHarness(t, lunch())
	h.env.RegisterDelayedCallback(func() { h.cp.BumpRevision("tenant-alpha", "principal-alice") }, 30*time.Second)
	h.consentAt(time.Minute, "n1", nil)
	r := h.run()
	if r.Status != "stale_install" {
		t.Fatalf("status = %s", r.Status)
	}
	if _, w := h.fake.Counts(); w != 0 {
		t.Fatalf("provider writes = %d", w)
	}
}

// T5: a fee change between consent and verify -> basket_changed, no handoff.
func TestT5_FeeChangeReasks(t *testing.T) {
	h := newHarness(t, lunch())
	h.fake.BumpFeeOnWrite = 50
	h.consentAt(time.Minute, "n1", nil)
	r := h.run()
	if r.Status != "basket_changed" || has(r.States, "handoff_issued") || len(h.cp.Outbox) != 0 {
		t.Fatalf("states = %v outbox = %d", r.States, len(h.cp.Outbox))
	}
}

// T8: expired consent, and expired handoff refuses the token.
func TestT8_ConsentAndHandoffExpiry(t *testing.T) {
	h := newHarness(t, lunch())
	r := h.run() // nobody consents
	if r.Status != "consent_expired" {
		t.Fatalf("status = %s", r.Status)
	}
	h2 := newHarness(t, lunch())
	h2.consentAt(time.Minute, "n1", nil) // never opens the handoff
	r2 := h2.run()
	if r2.Status != "consent_expired" || !has(r2.States, "handoff_issued") {
		t.Fatalf("states = %v", r2.States)
	}
	req := controlplane.Request{Principal: "principal-alice", Tenant: "tenant-alpha", OrderID: "ord-1"}
	if err := h2.cp.OpenHandoff(h2.cp.Outbox[0], req, h2.status().Fingerprint); err == nil {
		t.Fatal("expired handoff token must be refused")
	}
}

// T9: revoked install mid-wait stops the order and deletes encrypted state.
func TestT9_RevokedDeletesState(t *testing.T) {
	h := newHarness(t, lunch())
	h.env.RegisterDelayedCallback(func() { h.env.SignalWorkflow(SigRevoked, nil) }, time.Minute)
	r := h.run()
	if r.Status != "cancelled" {
		t.Fatalf("status = %s", r.Status)
	}
	if h.vault.Has("conn-ref-1") || len(h.vault.Drafts) != 0 {
		t.Fatal("order state or session ref survived revocation")
	}
	if _, w := h.fake.Counts(); w != 0 {
		t.Fatal("provider write after revocation")
	}
}

// T9b: revocation after handoff_issued expires the token and purges state.
func TestT9b_RevokedAfterHandoffIssued(t *testing.T) {
	h := newHarness(t, lunch())
	h.consentAt(time.Minute, "n1", nil)
	h.env.RegisterDelayedCallback(func() { h.env.SignalWorkflow(SigRevoked, nil) }, 2*time.Minute)
	r := h.run()
	if r.Status != "cancelled" || !has(r.States, "handoff_issued") {
		t.Fatalf("states = %v", r.States)
	}
	req := controlplane.Request{Principal: "principal-alice", Tenant: "tenant-alpha", OrderID: "ord-1"}
	if err := h.cp.OpenHandoff(h.cp.Outbox[0], req, h.status().Fingerprint); err == nil {
		t.Fatal("handoff token must be refused after revocation")
	}
	if h.vault.Has("conn-ref-1") || len(h.vault.Drafts) != 0 {
		t.Fatal("order state or session ref survived revocation")
	}
}

// T9c: revoke can race with the provider write Activity. Its signal may
// arrive while the workflow is awaiting the Activity result; no exit may
// bypass the revoke cleanup or produce a usable handoff.
func TestT9c_RevokedDuringProviderWrite(t *testing.T) {
	h := newHarness(t, lunch())
	h.act.AfterProviderWrite = func() {
		h.cp.Deactivate("tenant-alpha", "principal-alice")
		h.env.SignalWorkflow(SigRevoked, nil)
	}
	h.consentAt(time.Minute, "n1", nil)
	r := h.run()
	if r.Status != "cancelled" {
		t.Fatalf("revocation after provider write: status=%s states=%v", r.Status, r.States)
	}
	if h.vault.Has("conn-ref-1") || len(h.vault.Drafts) != 0 {
		t.Fatal("post-write revoke left connection or order state")
	}
	if has(r.States, "handoff_issued") || len(h.cp.Outbox) > 0 {
		t.Fatalf("handoff issued after revoke: states=%v tokens=%d", r.States, len(h.cp.Outbox))
	}
}

// Owner cancel purges the order draft but keeps the install connection.
func TestCancelKeepsConnection(t *testing.T) {
	h := newHarness(t, lunch())
	h.env.RegisterDelayedCallback(func() { h.env.SignalWorkflow(SigCancel, nil) }, time.Minute)
	r := h.run()
	if r.Status != "cancelled" {
		t.Fatalf("status = %s", r.Status)
	}
	if !h.vault.Has("conn-ref-1") {
		t.Fatal("cancel must not delete the install connection")
	}
}

// T4: an existing provider cart is a collision, never silently overwritten.
func TestT4_BasketCollision(t *testing.T) {
	h := newHarness(t, lunch())
	other := fakeglovo.Draft{Store: "s1", Lines: []fakeglovo.Line{{ItemID: "m2", Qty: 2}}}
	h.fake.SeedCart(tokA, other)
	// consent without replace is rejected; the order then expires untouched
	h.consentAt(time.Minute, "n1", nil)
	r := h.run()
	if r.Status != "consent_expired" {
		t.Fatalf("status = %s", r.Status)
	}
	if got := h.fake.CartOf(tokA); len(got.Lines) != 1 || got.Lines[0].ItemID != "m2" {
		t.Fatalf("existing cart was overwritten: %+v", got)
	}
	// with explicit replace it proceeds
	h2 := newHarness(t, lunch())
	h2.fake.SeedCart(tokA, other)
	h2.consentAt(time.Minute, "n1", func(s *ConsentSignal) { s.ReplaceExisting = true })
	h2.env.RegisterDelayedCallback(func() { h2.env.SignalWorkflow(SigCancel, nil) }, 5*time.Minute)
	if st := h2.run(); !has(st.States, "verified") {
		t.Fatalf("states = %v", st.States)
	}
}

// T3 (workflow side): a missing required modifier asks instead of quoting.
func TestT3_MissingModifierAsks(t *testing.T) {
	h := newHarness(t, fakeglovo.Draft{Store: "s1", Lines: []fakeglovo.Line{{ItemID: "m1", Qty: 1}}})
	r := h.run()
	if r.Status != "needs_input" || has(r.States, "quoted") {
		t.Fatalf("states = %v", r.States)
	}
}

// T11: reads retry; a write timeout is verified by read-back, never re-sent.
func TestT11_RetryDiscipline(t *testing.T) {
	h := newHarness(t, lunch())
	h.fake.TransientReads = 2
	h.fake.WriteTimeoutOnce = true
	h.consentAt(time.Minute, "n1", nil)
	h.env.RegisterDelayedCallback(func() { h.env.SignalWorkflow(SigCancel, nil) }, 10*time.Minute)
	r := h.run()
	if !has(r.States, "verified") {
		t.Fatalf("states = %v", r.States)
	}
	if _, w := h.fake.Counts(); w != 1 {
		t.Fatalf("writes = %d, want exactly 1", w)
	}
}

// T12: the same button pressed twice is applied once and acknowledged.
func TestT12_DuplicateConsent(t *testing.T) {
	h := newHarness(t, lunch())
	// The same nonce is delivered twice before a valid consent; the second
	// delivery must be counted as a duplicate, not re-evaluated.
	h.consentAt(10*time.Second, "same", func(s *ConsentSignal) { s.Fingerprint = "stale" })
	h.consentAt(30*time.Second, "same", nil)
	h.consentAt(time.Minute, "n2", nil)
	h.env.RegisterDelayedCallback(func() { h.env.SignalWorkflow(SigCancel, nil) }, 10*time.Minute)
	r := h.run()
	if st := h.status(); st.Duplicates != 1 || st.Rejected != 1 {
		t.Fatalf("duplicates = %d rejected = %d, want 1 and 1", st.Duplicates, st.Rejected)
	}
	if _, w := h.fake.Counts(); w != 1 {
		t.Fatalf("writes = %d", w)
	}
	if !has(r.States, "handoff_issued") {
		t.Fatalf("states = %v", r.States)
	}
}

// T17: canaries never reach history payloads, logs or results.
func TestT17_NoCanaryInHistoryOrLogs(t *testing.T) {
	h := newHarness(t, lunch())
	happyOpen(h)
	h.run()
	if hits := h.rec.Hits(); len(hits) > 0 {
		t.Fatalf("canaries in payloads: %v", hits)
	}
	if hits := leakcheck.Find(h.logs.Bytes()); len(hits) > 0 {
		t.Fatalf("canaries in logs: %v", hits)
	}
	if len(h.rec.Seen) == 0 {
		t.Fatal("recorder saw no payloads; converter not in use")
	}
	// the token itself is only in the owner outbox, not in history
	for _, b := range h.rec.Seen {
		if strings.Contains(string(b), h.cp.Outbox[0]) {
			t.Fatal("handoff token in history")
		}
	}
}

// Positive control: the converter rejects a payload that carries a canary.
func TestT17_ConverterRejectsCanary(t *testing.T) {
	h := newHarness(t, lunch())
	dc := canaryConverter{DataConverter: converter.GetDefaultDataConverter(), rec: h.rec}
	if _, err := dc.ToPayloads("leak: " + tokA); err == nil {
		t.Fatal("canary in a payload must be rejected")
	}
	if _, err := dc.ToPayloads("opaque-ref-1"); err != nil {
		t.Fatal(err)
	}
}
