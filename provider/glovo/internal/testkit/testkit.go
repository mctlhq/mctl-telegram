// Package testkit builds the synthetic fixtures shared by activity and
// workflow tests. It is imported only from _test.go files. Personas are the
// repository's synthetic Alice, Bob and Carol.
package testkit

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/activities"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/basket"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridge"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridge/fake"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fairness"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fakestore"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/obs"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

const (
	IntentHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	// Canary values must never reach history, logs, metrics or results.
	CanaryAddress = "canary-address-9 Fake Street"
	CanaryToken   = "canary-session-token-7f3a"
)

type Env struct {
	T       *testing.T
	Store   *fakestore.Store
	Bridge  *fake.Bridge
	Acts    *activities.Activities
	Metrics *obs.Metrics
	Logs    *bytes.Buffer
	Draft   fakestore.Draft
	Req     v1alpha1.ProviderRequest // Alice, tenant-alpha, order ord-1
	FP      string                   // fingerprint of Draft as quoted at setup
}

func Lunch() fakestore.Draft {
	return fakestore.Draft{Store: "s1", Lines: []fakestore.Line{{ItemID: "m1", Qty: 1, Modifiers: map[string]string{"size": "large"}}}}
}

func New(t *testing.T, draft fakestore.Draft) *Env {
	t.Helper()
	e := &Env{T: t, Store: fakestore.New(), Bridge: fake.New(time.Now), Metrics: obs.NewMetrics(), Logs: &bytes.Buffer{}, Draft: draft}
	log := slog.New(obs.NewRedactingHandler(slog.NewTextHandler(e.Logs, nil)))
	drafts := activities.NewDraftStore()
	e.Acts = &activities.Activities{
		Bridge: bridge.FailClosed(e.Bridge, time.Second), Store: e.Store, Ledger: basket.NewLedger(), Drafts: drafts,
		Breaker: fairness.NewBreaker(3), Limiter: fairness.NewLimiter(4), Log: log, Metrics: e.Metrics,
	}
	e.Req = v1alpha1.ProviderRequest{Version: v1alpha1.Version, ExecutionRef: "we_alpha1", TenantRef: "tenant-alpha",
		OwnerRef: "principal-alice", ConnectionRef: "gcn_alpha1", InstallRef: "inst-alpha", InstallRevision: 1,
		OrderRef: "ord-1", IntentHash: IntentHash, ApprovalRef: "aar_alpha1"}
	e.addTenant("tenant-alpha", "principal-alice", "inst-alpha", "gcn_alpha1", "ord-1", CanaryAddress)
	e.addTenant("tenant-beta", "principal-bob", "inst-beta", "gcn_beta1", "ord-b1", "addr-ref-beta")
	// Same tenant, distinct principal.
	e.addTenant("tenant-alpha", "principal-carol", "inst-carol", "gcn_alpha2", "ord-c1", "addr-ref-carol")
	drafts.Put("tenant-alpha", "ord-1", draft)
	drafts.Put("tenant-beta", "ord-b1", draft)
	drafts.Put("tenant-alpha", "ord-c1", draft)
	q, err := e.Store.Client(activities.SessionKey("tenant-alpha", "gcn_alpha1")).QuoteBasket(context.Background(), draft)
	if err != nil {
		t.Fatalf("setup quote: %v", err)
	}
	e.FP = q.Fingerprint
	e.Receipt("aar_alpha1", e.Req, e.FP)
	return e
}

func (e *Env) addTenant(tenant, owner, install, conn, order, addr string) {
	e.Bridge.AddInstall(install, fake.Install{Tenant: tenant, Owner: owner, Connection: conn, Revision: 1})
	e.Bridge.AddOrder(order, fake.Order{Tenant: tenant, Owner: owner})
	e.Store.AddSession(activities.SessionKey(tenant, conn), addr)
}

// Receipt registers a valid one-hour receipt bound to req and fingerprint.
func (e *Env) Receipt(ref string, req v1alpha1.ProviderRequest, fp string) {
	e.Bridge.AddReceipt(ref, fake.Binding{Execution: req.ExecutionRef, Tenant: req.TenantRef, Owner: req.OwnerRef,
		Connection: req.ConnectionRef, IntentHash: req.IntentHash, Fingerprint: fp, InstallRevision: req.InstallRevision},
		time.Now().Add(time.Hour))
}

// ReqBeta, ReqCarol return valid requests of the other fixtures.
func (e *Env) ReqBeta() v1alpha1.ProviderRequest {
	r := e.Req
	r.ExecutionRef, r.TenantRef, r.OwnerRef, r.ConnectionRef, r.InstallRef, r.OrderRef, r.ApprovalRef =
		"we_beta1", "tenant-beta", "principal-bob", "gcn_beta1", "inst-beta", "ord-b1", "aar_beta1"
	return r
}

func (e *Env) ReqCarol() v1alpha1.ProviderRequest {
	r := e.Req
	r.ExecutionRef, r.OwnerRef, r.ConnectionRef, r.InstallRef, r.OrderRef, r.ApprovalRef =
		"we_carol1", "principal-carol", "gcn_alpha2", "inst-carol", "ord-c1", "aar_carol1"
	return r
}

// Writes reports the provider write counter.
func (e *Env) Writes() int { _, w := e.Store.Counts(); return w }
