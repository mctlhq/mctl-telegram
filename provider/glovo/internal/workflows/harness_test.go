package workflows

import (
	"fmt"
	"testing"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/testsuite"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fakestore"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/leakcheck"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/testkit"
)

// canaryConverter rejects any payload that contains a canary secret and
// records every payload it sees for the leak check.
type canaryConverter struct {
	converter.DataConverter
	rec *leakcheck.Recorder
}

func (c canaryConverter) ToPayloads(v ...interface{}) (*commonpb.Payloads, error) {
	p, err := c.DataConverter.ToPayloads(v...)
	if err != nil {
		return nil, err
	}
	for _, pl := range p.GetPayloads() {
		c.rec.Add(pl.GetData())
		if hits := leakcheck.Find(pl.GetData()); len(hits) > 0 {
			return nil, fmt.Errorf("payload contains canary %v", hits)
		}
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
	*testkit.Env
	env  *testsuite.TestWorkflowEnvironment
	rec  *leakcheck.Recorder
	snap Snapshot
	conn string // fakestore session key of the order's connection
}

func newHarness(t *testing.T, draft fakestore.Draft) *harness {
	t.Helper()
	h := &harness{Env: testkit.New(t, draft), rec: &leakcheck.Recorder{}, conn: "tenant-alpha|gcn_alpha1"}
	h.snap = Snapshot{Req: h.Req, ConsentTTL: time.Hour, HandoffTTL: 15 * time.Minute}
	var s testsuite.WorkflowTestSuite
	h.env = s.NewTestWorkflowEnvironment()
	h.env.SetDataConverter(canaryConverter{DataConverter: converter.GetDefaultDataConverter(), rec: h.rec})
	h.env.RegisterWorkflow(GlovoOrderWorkflow)
	h.env.RegisterActivity(h.Acts)
	return h
}

func lunch() fakestore.Draft { return testkit.Lunch() }

func (h *harness) status() Status {
	h.T.Helper()
	v, err := h.env.QueryWorkflow(QueryStatus)
	if err != nil {
		h.T.Fatalf("query: %v", err)
	}
	var st Status
	if err := v.Get(&st); err != nil {
		h.T.Fatal(err)
	}
	return st
}

// consentAt sends a consent signal bound to the fingerprint the workflow reports.
func (h *harness) consentAt(d time.Duration, nonce string, mutate func(*ConsentSignal)) {
	h.env.RegisterDelayedCallback(func() {
		st := h.status()
		sig := ConsentSignal{Nonce: nonce, Fingerprint: st.Fingerprint, InstallRevision: h.snap.Req.InstallRevision}
		if mutate != nil {
			mutate(&sig)
		}
		h.env.SignalWorkflow(SigConsent, sig)
	}, d)
}

func (h *harness) signalAt(d time.Duration, name string) {
	h.env.RegisterDelayedCallback(func() { h.env.SignalWorkflow(name, nil) }, d)
}

func (h *harness) run() Result {
	h.T.Helper()
	h.env.ExecuteWorkflow(GlovoOrderWorkflow, h.snap)
	if !h.env.IsWorkflowCompleted() {
		h.T.Fatal("workflow did not complete")
	}
	if err := h.env.GetWorkflowError(); err != nil {
		h.T.Fatalf("workflow error: %v", err)
	}
	var r Result
	if err := h.env.GetWorkflowResult(&r); err != nil {
		h.T.Fatal(err)
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
