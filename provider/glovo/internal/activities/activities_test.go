package activities_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/activities"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridge"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridge/fake"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/testkit"
)

var ctx = context.Background()

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if got := activities.ErrCode(err); got != code {
		t.Fatalf("code = %q (err=%v), want %q", got, err, code)
	}
}

func TestMutateHappyPathAppliesOnce(t *testing.T) {
	e := testkit.New(t, testkit.Lunch())
	r, err := e.Acts.MutateBasket(ctx, e.Req, e.FP)
	if err != nil || !r.Applied || r.Deduped {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	if e.Writes() != 1 || e.Bridge.Consumed() != 1 {
		t.Fatalf("writes=%d consumed=%d", e.Writes(), e.Bridge.Consumed())
	}
}

// T4: tenant B's refs against tenant A's order.
func TestCrossTenantRefused(t *testing.T) {
	e := testkit.New(t, testkit.Lunch())
	bobOnAlice := e.ReqBeta()
	bobOnAlice.OrderRef = e.Req.OrderRef
	_, err := e.Acts.MutateBasket(ctx, bobOnAlice, e.FP)
	wantCode(t, err, bridge.CodeNotFound)
	// Bob claiming Alice's install and connection.
	stolen := e.Req
	stolen.TenantRef = "tenant-beta"
	_, err = e.Acts.MutateBasket(ctx, stolen, e.FP)
	wantCode(t, err, bridge.CodeNotAuthorized)
	if e.Writes() != 0 || e.Bridge.Consumed() != 0 {
		t.Fatal("zero writes expected")
	}
}

// T5: same tenant, distinct principals.
func TestSameTenantOtherPrincipalRefused(t *testing.T) {
	e := testkit.New(t, testkit.Lunch())
	carolOnAlice := e.Req
	carolOnAlice.OwnerRef = "principal-carol"
	_, err := e.Acts.MutateBasket(ctx, carolOnAlice, e.FP)
	wantCode(t, err, bridge.CodeNotAuthorized)
	carolConn := e.Req
	carolConn.ConnectionRef = "gcn_alpha2"
	_, err = e.Acts.MutateBasket(ctx, carolConn, e.FP)
	wantCode(t, err, bridge.CodeNotAuthorized)
	carol := e.ReqCarol()
	carol.OrderRef = e.Req.OrderRef
	_, err = e.Acts.MutateBasket(ctx, carol, e.FP)
	wantCode(t, err, bridge.CodeNotAuthorized)
	if e.Writes() != 0 {
		t.Fatal("zero writes expected")
	}
}

// T6.
func TestScopeRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *testkit.Env) // mutate fixtures
		code  string
	}{
		{"foreign order", func(e *testkit.Env) { e.Req.OrderRef = "ord-b1" }, bridge.CodeNotFound},
		{"unknown order", func(e *testkit.Env) { e.Req.OrderRef = "ord-nope" }, bridge.CodeNotFound},
		{"stale install", func(e *testkit.Env) { e.Bridge.BumpRevision("inst-alpha") }, bridge.CodeStaleInstall},
		{"revoked", func(e *testkit.Env) { e.Bridge.SetState("inst-alpha", fake.ConnRevoked) }, bridge.CodeConnectionRevoked},
		{"expired", func(e *testkit.Env) { e.Bridge.SetState("inst-alpha", fake.ConnExpired) }, bridge.CodeConnectionExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := testkit.New(t, testkit.Lunch())
			tc.setup(e)
			_, err := e.Acts.MutateBasket(ctx, e.Req, e.FP)
			wantCode(t, err, tc.code)
			if e.Writes() != 0 || e.Bridge.Consumed() != 0 {
				t.Fatal("zero writes expected")
			}
		})
	}
}

// T7.
func TestApprovalRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(e *testkit.Env)
		code  string
	}{
		{"wrong aar", func(e *testkit.Env) { e.Req.ApprovalRef = "aar_other" }, bridge.CodeApprovalInvalid},
		{"wrong we", func(e *testkit.Env) { e.Req.ExecutionRef = "we_other" }, bridge.CodeApprovalInvalid},
		{"intent mismatch", func(e *testkit.Env) {
			e.Req.IntentHash = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}, bridge.CodeIntentMismatch},
		{"expired", func(e *testkit.Env) {
			e.Bridge.AddReceipt("aar_alpha1", fake.Binding{Execution: e.Req.ExecutionRef, Tenant: e.Req.TenantRef, Owner: e.Req.OwnerRef,
				Connection: e.Req.ConnectionRef, IntentHash: e.Req.IntentHash, Fingerprint: e.FP, InstallRevision: 1}, time.Now().Add(-time.Second))
		}, bridge.CodeApprovalExpired},
		{"missing aar", func(e *testkit.Env) { e.Req.ApprovalRef = "" }, bridge.CodeInvalidRequest},
		{"wrong fingerprint", func(e *testkit.Env) { e.FP = "deadbeef" }, bridge.CodeApprovalInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := testkit.New(t, testkit.Lunch())
			tc.setup(e)
			_, err := e.Acts.MutateBasket(ctx, e.Req, e.FP)
			wantCode(t, err, tc.code)
			if e.Writes() != 0 || e.Bridge.Consumed() != 0 {
				t.Fatal("zero writes expected")
			}
		})
	}
}

func TestReplayedReceiptRefused(t *testing.T) {
	e := testkit.New(t, testkit.Lunch())
	if _, err := e.Acts.MutateBasket(ctx, e.Req, e.FP); err != nil {
		t.Fatal(err)
	}
	// Simulate a restarted worker (empty ledger) and a basket that changed
	// since: the matching fingerprint shortcut no longer applies, so the
	// already-consumed receipt must be refused.
	e.Acts.Ledger.Forget(e.Req.TenantRef, e.Req.OrderRef)
	e.Store.SeedCart("tenant-alpha|gcn_alpha1", testkit.Lunch()) // same lines
	e.Store.SetFee(500)
	_, err := e.Acts.MutateBasket(ctx, e.Req, e.FP)
	wantCode(t, err, bridge.CodeApprovalReplayed)
	if e.Bridge.Consumed() != 1 || e.Writes() != 1 {
		t.Fatalf("consumed=%d writes=%d", e.Bridge.Consumed(), e.Writes())
	}
}

// T8: exactly-once under retries and ambiguous timeouts.
func TestExactlyOnce(t *testing.T) {
	t.Run("retry after success", func(t *testing.T) {
		e := testkit.New(t, testkit.Lunch())
		for i := 0; i < 3; i++ {
			if _, err := e.Acts.MutateBasket(ctx, e.Req, e.FP); err != nil {
				t.Fatal(err)
			}
		}
		if e.Writes() != 1 || e.Bridge.Consumed() != 1 {
			t.Fatalf("writes=%d consumed=%d", e.Writes(), e.Bridge.Consumed())
		}
	})
	t.Run("ambiguous timeout with effect applied", func(t *testing.T) {
		e := testkit.New(t, testkit.Lunch())
		e.Store.SetWriteTimeoutOnce()
		r, err := e.Acts.MutateBasket(ctx, e.Req, e.FP)
		if err != nil || !r.Applied {
			t.Fatalf("r=%+v err=%v", r, err)
		}
		if _, err := e.Acts.MutateBasket(ctx, e.Req, e.FP); err != nil {
			t.Fatal(err)
		}
		if e.Writes() != 1 {
			t.Fatalf("writes=%d", e.Writes())
		}
	})
	t.Run("ambiguous timeout without effect", func(t *testing.T) {
		e := testkit.New(t, testkit.Lunch())
		e.Store.SetWriteLostOnce()
		_, err := e.Acts.MutateBasket(ctx, e.Req, e.FP)
		wantCode(t, err, bridge.CodeWriteUnverified)
		if len(e.Store.CartOf("tenant-alpha|gcn_alpha1").Lines) != 0 {
			t.Fatal("no effect expected")
		}
		if e.Writes() > 1 {
			t.Fatalf("writes=%d", e.Writes())
		}
	})
	t.Run("restart: fresh ledger sees matching basket", func(t *testing.T) {
		e := testkit.New(t, testkit.Lunch())
		if _, err := e.Acts.MutateBasket(ctx, e.Req, e.FP); err != nil {
			t.Fatal(err)
		}
		e.Acts.Ledger.Forget(e.Req.TenantRef, e.Req.OrderRef)
		r, err := e.Acts.MutateBasket(ctx, e.Req, e.FP)
		if err != nil || r.Applied {
			t.Fatalf("r=%+v err=%v", r, err)
		}
		if e.Writes() != 1 || e.Bridge.Consumed() != 1 {
			t.Fatalf("writes=%d consumed=%d", e.Writes(), e.Bridge.Consumed())
		}
	})
	t.Run("concurrent", func(t *testing.T) {
		e := testkit.New(t, testkit.Lunch())
		e.Acts.Limiter = nil
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); _, _ = e.Acts.MutateBasket(ctx, e.Req, e.FP) }()
		}
		wg.Wait()
		if e.Writes() != 1 || e.Bridge.Consumed() != 1 {
			t.Fatalf("writes=%d consumed=%d", e.Writes(), e.Bridge.Consumed())
		}
	})
}

// T10: bridge failures fail closed.
func TestBridgeFailureFailsClosed(t *testing.T) {
	for name, f := range map[string]fake.Fault{
		"timeout": fake.FaultTimeout, "transport": fake.FaultTransport,
		"malformed": fake.FaultMalformed, "partial": fake.FaultPartial,
	} {
		t.Run(name, func(t *testing.T) {
			e := testkit.New(t, testkit.Lunch())
			e.Bridge.SetFault(f)
			_, err := e.Acts.MutateBasket(ctx, e.Req, e.FP)
			wantCode(t, err, bridge.CodeBridgeUnavailable)
			if e.Writes() != 0 || e.Bridge.Consumed() != 0 {
				t.Fatal("zero writes expected")
			}
			if _, err := e.Acts.QuoteOrder(ctx, e.Req); activities.ErrCode(err) != bridge.CodeBridgeUnavailable {
				t.Fatalf("quote must fail closed: %v", err)
			}
		})
	}
}

func TestInvalidRequestRejectedBeforeBridge(t *testing.T) {
	e := testkit.New(t, testkit.Lunch())
	bad := e.Req
	bad.ConnectionRef = "we_notaconnection"
	_, err := e.Acts.MutateBasket(ctx, bad, e.FP)
	wantCode(t, err, bridge.CodeInvalidRequest)
	if e.Writes() != 0 {
		t.Fatal("zero writes expected")
	}
}

func TestKillSwitchAndBreakerRefuseMutation(t *testing.T) {
	e := testkit.New(t, testkit.Lunch())
	e.Acts.Disabled = func() bool { return true }
	_, err := e.Acts.MutateBasket(ctx, e.Req, e.FP)
	wantCode(t, err, bridge.CodeProviderDisabled)
	// Reads of local state proceed.
	if _, err := e.Acts.QuoteOrder(ctx, e.Req); err != nil {
		t.Fatal(err)
	}
	e.Acts.Disabled = nil
	for i := 0; i < 3; i++ {
		e.Acts.Breaker.Record(true)
	}
	_, err = e.Acts.MutateBasket(ctx, e.Req, e.FP)
	wantCode(t, err, bridge.CodeProviderUnavail)
	if e.Writes() != 0 {
		t.Fatal("zero writes expected")
	}
}

func TestTenantLimiter(t *testing.T) {
	e := testkit.New(t, testkit.Lunch())
	for i := 0; i < 4; i++ {
		if !e.Acts.Limiter.TryAcquire("tenant-alpha") {
			t.Fatal("setup")
		}
	}
	_, err := e.Acts.MutateBasket(ctx, e.Req, e.FP)
	wantCode(t, err, bridge.CodeTenantBusy)
	// Tenant beta is unaffected.
	beta := e.ReqBeta()
	e.Receipt("aar_beta1", beta, e.FP)
	if _, err := e.Acts.MutateBasket(ctx, beta, e.FP); err != nil {
		t.Fatalf("beta: %v", err)
	}
}

func TestPurgeIsTenantFenced(t *testing.T) {
	e := testkit.New(t, testkit.Lunch())
	// Bob presents Alice's connection and order refs under his own tenant.
	forged := e.Req
	forged.TenantRef = "tenant-beta"
	if err := e.Acts.PurgeConnection(ctx, forged); err != nil {
		t.Fatal(err)
	}
	if !e.Store.HasSession("tenant-alpha|gcn_alpha1") {
		t.Fatal("tenant-alpha session purged by another tenant")
	}
	if _, ok := e.Acts.Drafts.Get("tenant-alpha", "ord-1"); !ok {
		t.Fatal("tenant-alpha draft purged by another tenant")
	}
	if err := e.Acts.PurgeConnection(ctx, e.Req); err != nil {
		t.Fatal(err)
	}
	if e.Store.HasSession("tenant-alpha|gcn_alpha1") {
		t.Fatal("own purge must delete the session")
	}
}

func TestIssueHandoffRevalidates(t *testing.T) {
	e := testkit.New(t, testkit.Lunch())
	if _, err := e.Acts.IssueHandoff(ctx, e.Req, e.FP); activities.ErrCode(err) != bridge.CodeApprovalInvalid {
		t.Fatalf("unapproved handoff: %v", err)
	}
	if _, err := e.Acts.MutateBasket(ctx, e.Req, e.FP); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Acts.IssueHandoff(ctx, e.Req, e.FP); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []struct {
		name   string
		mutate func(*testkit.Env)
	}{
		{"wrong_receipt", func(e *testkit.Env) { e.Req.ApprovalRef = "aar_other" }},
		{"wrong_execution", func(e *testkit.Env) { e.Req.ExecutionRef = "we_other" }},
		{"wrong_fingerprint", func(e *testkit.Env) { e.FP = "deadbeef" }},
	} {
		t.Run(changed.name, func(t *testing.T) {
			c := testkit.New(t, testkit.Lunch())
			if _, err := c.Acts.MutateBasket(ctx, c.Req, c.FP); err != nil {
				t.Fatal(err)
			}
			changed.mutate(c)
			_, err := c.Acts.IssueHandoff(ctx, c.Req, c.FP)
			wantCode(t, err, bridge.CodeApprovalInvalid)
		})
	}
	e.Bridge.SetState("inst-alpha", fake.ConnRevoked)
	_, err := e.Acts.IssueHandoff(ctx, e.Req, e.FP)
	wantCode(t, err, bridge.CodeConnectionRevoked)
}

// A basket pre-populated outside this execution must never authorize a handoff
// merely because its fingerprint happens to match. The synthetic ledger entry
// from read-back has no evidence that this execution consumed an aar_ receipt.
func TestMatchingBasketWithoutApprovalCannotIssueHandoff(t *testing.T) {
	for _, tc := range []string{"unconsumed", "wrong", "expired", "replayed"} {
		t.Run(tc, func(t *testing.T) {
			e := testkit.New(t, testkit.Lunch())
			e.Store.SeedCart("tenant-alpha|gcn_alpha1", testkit.Lunch())
			q, err := e.Store.Client("tenant-alpha|gcn_alpha1").ReadBasket(ctx)
			if err != nil || q.Fingerprint != e.FP {
				t.Fatalf("test setup does not have matching basket: quote=%+v err=%v", q, err)
			}
			switch tc {
			case "wrong":
				e.Req.ApprovalRef = "aar_other"
			case "expired":
				e.Bridge.AddReceipt("aar_alpha1", fake.Binding{
					Execution: e.Req.ExecutionRef, Tenant: e.Req.TenantRef, Owner: e.Req.OwnerRef,
					Connection: e.Req.ConnectionRef, IntentHash: e.Req.IntentHash, Fingerprint: e.FP,
					InstallRevision: e.Req.InstallRevision,
				}, time.Now().Add(-time.Second))
			case "replayed":
				if err := e.Bridge.ConsumeApproval(ctx, e.Req, e.FP); err != nil {
					t.Fatal(err)
				}
			}
			got, err := e.Acts.MutateBasket(ctx, e.Req, e.FP)
			if err != nil || got.Applied || !got.Deduped {
				t.Fatalf("matching-basket readback=%+v err=%v", got, err)
			}
			_, err = e.Acts.IssueHandoff(ctx, e.Req, e.FP)
			wantCode(t, err, bridge.CodeApprovalInvalid)
			if e.Writes() != 0 {
				t.Fatal("pre-existing basket caused a provider write")
			}
		})
	}
}
