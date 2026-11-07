package workflows

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/testsuite"

	"github.com/mctlhq/mctl-telegram/test/glovo-poc/controlplane"
	"github.com/mctlhq/mctl-telegram/test/glovo-poc/fairness"
	"github.com/mctlhq/mctl-telegram/test/glovo-poc/fakeglovo"
	"github.com/mctlhq/mctl-telegram/test/glovo-poc/leakcheck"
)

// Synthetic personas: Alice (tenant-alpha), Bob (tenant-beta), Carol (gamma, no install).
const (
	tgAlice int64 = 600184001
	tgBob   int64 = 600184002
	tgCarol int64 = 600184003
	tokA          = "canary-session-token-7f3a"
	addrA         = "canary-address-9 Fake Street"
)

// canaryConverter rejects any payload that contains a canary secret and
// records every payload it sees for the leak check.
type canaryConverter struct {
	converter.DataConverter
	rec *leakcheck.Recorder
}

func (c canaryConverter) check(p *commonpb.Payloads) error {
	for _, pl := range p.GetPayloads() {
		c.rec.Add(pl.GetData())
		if hits := leakcheck.Find(pl.GetData()); len(hits) > 0 {
			return fmt.Errorf("payload contains canary %v", hits)
		}
	}
	return nil
}

func (c canaryConverter) ToPayloads(v ...interface{}) (*commonpb.Payloads, error) {
	p, err := c.DataConverter.ToPayloads(v...)
	if err != nil {
		return nil, err
	}
	if err := c.check(p); err != nil {
		return nil, err
	}
	return p, nil
}

func (c canaryConverter) ToPayload(v interface{}) (*commonpb.Payload, error) {
	p, err := c.DataConverter.ToPayload(v)
	if err != nil {
		return nil, err
	}
	if hits := leakcheck.Find(p.GetData()); len(hits) > 0 {
		return nil, fmt.Errorf("payload contains canary %v", hits)
	}
	c.rec.Add(p.GetData())
	return p, nil
}

type harness struct {
	t     *testing.T
	env   *testsuite.TestWorkflowEnvironment
	fake  *fakeglovo.Server
	cp    *controlplane.CP
	vault *Vault
	rec   *leakcheck.Recorder
	logs  *bytes.Buffer
	snap  Snapshot
}

func newHarness(t *testing.T, draft fakeglovo.Draft) *harness {
	t.Helper()
	h := &harness{t: t, fake: fakeglovo.New(), rec: &leakcheck.Recorder{}, logs: &bytes.Buffer{}, vault: NewVault()}
	t.Cleanup(h.fake.Close)
	h.fake.AddSession(tokA, "addr-ref-alpha")
	h.cp = controlplane.New(time.Now)
	h.cp.Link(tgAlice, "principal-alice")
	h.cp.AddMember("principal-alice", "tenant-alpha")
	h.cp.Install("tenant-alpha", "principal-alice", "inst-alpha", "conn-ref-1")
	h.vault.Sessions["conn-ref-1"] = Session{Token: tokA, Address: addrA, BaseURL: h.fake.URL}
	h.vault.Drafts["req-ref-1"] = draft
	h.snap = Snapshot{OrderID: "ord-1", TenantID: "tenant-alpha", OwnerPrincipal: "principal-alice", InstallID: "inst-alpha",
		InstallRevision: 1, ConnectionRef: "conn-ref-1", RequestRef: "req-ref-1", ConsentTTL: time.Hour, HandoffTTL: 15 * time.Minute}
	h.cp.RegisterOrder(controlplane.Order{ID: "ord-1", Tenant: "tenant-alpha", Owner: "principal-alice"})

	var s testsuite.WorkflowTestSuite
	h.env = s.NewTestWorkflowEnvironment()
	h.env.SetDataConverter(canaryConverter{DataConverter: converter.GetDefaultDataConverter(), rec: h.rec})
	h.env.RegisterWorkflow(GlovoOrderWorkflow)
	h.env.RegisterActivity(&Activities{CP: h.cp, Vault: h.vault, Breaker: fairness.NewBreaker(3),
		Log: slog.New(slog.NewTextHandler(h.logs, nil))})
	return h
}

func lunch() fakeglovo.Draft {
	return fakeglovo.Draft{Store: "s1", Lines: []fakeglovo.Line{{ItemID: "m1", Qty: 1, Modifiers: map[string]string{"size": "large"}}}}
}

func (h *harness) status() Status {
	h.t.Helper()
	v, err := h.env.QueryWorkflow(QueryStatus)
	if err != nil {
		h.t.Fatalf("query: %v", err)
	}
	var st Status
	if err := v.Get(&st); err != nil {
		h.t.Fatal(err)
	}
	return st
}

// consentAt sends a consent signal bound to the fingerprint the workflow reports.
func (h *harness) consentAt(d time.Duration, nonce string, mutate func(*ConsentSignal)) {
	h.env.RegisterDelayedCallback(func() {
		st := h.status()
		sig := ConsentSignal{Nonce: nonce, Fingerprint: st.Fingerprint, InstallRevision: h.snap.InstallRevision}
		if mutate != nil {
			mutate(&sig)
		}
		h.env.SignalWorkflow(SigConsent, sig)
	}, d)
}

func (h *harness) run() Result {
	h.t.Helper()
	h.env.ExecuteWorkflow(GlovoOrderWorkflow, h.snap)
	if !h.env.IsWorkflowCompleted() {
		h.t.Fatal("workflow did not complete")
	}
	if err := h.env.GetWorkflowError(); err != nil {
		h.t.Fatalf("workflow error: %v", err)
	}
	var r Result
	if err := h.env.GetWorkflowResult(&r); err != nil {
		h.t.Fatal(err)
	}
	return r
}

func has(states []string, s string) bool {
	for _, x := range states {
		if x == s {
			return true
		}
	}
	return false
}
