package controlplane

import (
	"errors"
	"testing"
	"time"
)

const (
	tgAlice int64 = 600184001
	tgBob   int64 = 600184002
	tgCarol int64 = 600184003
	tgNone  int64 = 600184099
)

func fixture() *CP {
	cp := New(time.Now)
	cp.Link(tgAlice, "principal-alice")
	cp.AddMember("principal-alice", "tenant-alpha")
	cp.Install("tenant-alpha", "principal-alice", "inst-alpha", "conn-a")
	cp.Link(tgBob, "principal-bob")
	cp.AddMember("principal-bob", "tenant-beta")
	cp.Install("tenant-beta", "principal-bob", "inst-beta", "conn-b")
	cp.Link(tgCarol, "principal-carol")
	cp.AddMember("principal-carol", "tenant-gamma") // member, but no install
	cp.RegisterOrder(Order{ID: "ord-alpha", Tenant: "tenant-alpha", Owner: "principal-alice"})
	return cp
}

// T14: Bob cannot reach Alice's order; foreign and unknown look identical.
func TestT14_CrossTenant(t *testing.T) {
	cp := fixture()
	foreign := Request{Principal: "principal-bob", Tenant: "tenant-beta", OrderID: "ord-alpha"}
	unknown := Request{Principal: "principal-bob", Tenant: "tenant-beta", OrderID: "ord-nope"}
	_, e1 := cp.Authorize(foreign)
	_, e2 := cp.Authorize(unknown)
	if !errors.Is(e1, ErrNotFound) || e1 != e2 {
		t.Fatalf("e1=%v e2=%v", e1, e2)
	}
	// naming Alice's tenant with Bob's principal also fails
	if _, err := cp.Authorize(Request{Principal: "principal-bob", Tenant: "tenant-alpha", OrderID: "ord-alpha"}); !errors.Is(err, ErrNotFound) {
		t.Fatal("tenant spoof accepted")
	}
	if got := cp.List("principal-bob", "tenant-beta"); len(got) != 0 {
		t.Fatalf("list leaked %v", got)
	}
	// handoff and consent paths use the same Authorize; token bound to the owner
	h := cp.IssueHandoff("ord-alpha", "principal-alice", "fp", time.Minute)
	_ = h
	if err := cp.OpenHandoff(cp.Outbox[0], foreign, "fp"); !errors.Is(err, ErrRefused) {
		t.Fatal("Bob opened Alice's handoff")
	}
	if _, err := cp.Authorize(Request{Principal: "principal-alice", Tenant: "tenant-alpha", OrderID: "ord-alpha"}); err != nil {
		t.Fatal(err)
	}
}

// T15: every broken link fails closed, never to the default tenant.
func TestT15_FailClosed(t *testing.T) {
	cp := fixture()
	cp.RevokeLink(tgBob)
	cp.Link(700184010, "principal-two")
	cp.AddMember("principal-two", "tenant-alpha")
	cp.AddMember("principal-two", "tenant-beta")
	cases := []struct {
		name string
		tg   int64
		ten  string
		want error
	}{
		{"unlinked", tgNone, "", ErrNoLink},
		{"revoked", tgBob, "", ErrLinkRevoked},
		{"no install", tgCarol, "", ErrNoInstall},
		{"ambiguous", 700184010, "", ErrAmbiguousTenant},
		{"not a member", tgAlice, "tenant-beta", ErrNoTenant},
		{"default tenant is not a grant", tgAlice, cp.DefaultTenant, ErrNoTenant},
	}
	for _, c := range cases {
		s, err := cp.Resolve(c.tg, c.ten)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v", c.name, err)
		}
		if s.TenantID == cp.DefaultTenant {
			t.Errorf("%s: assigned default tenant", c.name)
		}
	}
	// explicit choice resolves the ambiguous principal only where an install exists
	if _, err := cp.Resolve(700184010, "tenant-alpha"); !errors.Is(err, ErrNoInstall) {
		t.Fatalf("err = %v", err)
	}
	if s, err := cp.Resolve(tgAlice, ""); err != nil || s.InstallRevision != 1 {
		t.Fatalf("happy path: %+v %v", s, err)
	}
}

// T16: no surface parameter names a namespace, workflow, run or queue.
func TestT16_NoDirectTemporalRoute(t *testing.T) {
	for _, f := range []string{"namespace", "workflow_id", "run_id", "task_queue"} {
		raw := []byte(`{"principal":"p","tenant":"t","order_id":"o","` + f + `":"x"}`)
		if _, err := DecodeRequest(raw); !errors.Is(err, ErrBadParam) {
			t.Errorf("%s accepted: %v", f, err)
		}
	}
	if _, err := DecodeRequest([]byte(`{"principal":"p","tenant":"t","order_id":"o"}`)); err != nil {
		t.Fatal(err)
	}
}

// T10: the same occurrence starts exactly one run, including after a restart.
func TestT10_DuplicateFire(t *testing.T) {
	cp := fixture()
	s, err := cp.Resolve(tgAlice, "")
	if err != nil {
		t.Fatal(err)
	}
	occ := time.Date(2026, 11, 11, 12, 30, 0, 0, time.UTC)
	starts := 0
	start := func(id string) error { starts++; return nil }
	id1, started, err := cp.Fire(s, "sched-lunch", occ, start)
	if err != nil || !started {
		t.Fatal("first fire must start")
	}
	// overlapping and post-crash fires of the same occurrence
	for i := 0; i < 3; i++ {
		id, started, err := cp.Fire(s, "sched-lunch", occ, start)
		if err != nil || started || id != id1 {
			t.Fatalf("duplicate fire started a run: %v %v", started, err)
		}
	}
	if starts != 1 {
		t.Fatalf("starts = %d", starts)
	}
	if _, started, _ := cp.Fire(s, "sched-lunch", occ.Add(7*24*time.Hour), start); !started {
		t.Fatal("next occurrence must start")
	}
	// a fire revalidates the install
	cp.BumpRevision("tenant-alpha", "principal-alice")
	if _, _, err := cp.Fire(s, "sched-lunch", occ.Add(14*24*time.Hour), start); !errors.Is(err, ErrStaleInstall) {
		t.Fatalf("stale fire err = %v", err)
	}
}

func TestHandoffTokenRules(t *testing.T) {
	now := time.Now()
	cp := New(func() time.Time { return now })
	cp.AddMember("p", "t")
	cp.Install("t", "p", "inst", "conn")
	cp.RegisterOrder(Order{ID: "o", Tenant: "t", Owner: "p"})
	req := Request{Principal: "p", Tenant: "t", OrderID: "o"}
	cp.IssueHandoff("o", "p", "fp", 15*time.Minute)
	tok := cp.Outbox[0]
	if err := cp.OpenHandoff(tok, Request{Principal: "other", Tenant: "t", OrderID: "o"}, "fp"); err == nil {
		t.Fatal("other principal")
	}
	if err := cp.OpenHandoff(tok, req, "different"); err == nil {
		t.Fatal("fingerprint mismatch")
	}
	if err := cp.OpenHandoff(tok, req, "fp"); err != nil {
		t.Fatal(err)
	}
	if err := cp.OpenHandoff(tok, req, "fp"); err == nil {
		t.Fatal("reuse")
	}
	cp.IssueHandoff("o", "p", "fp", time.Minute)
	now = now.Add(2 * time.Minute)
	if err := cp.OpenHandoff(cp.Outbox[1], req, "fp"); err == nil {
		t.Fatal("expired")
	}
}

// A previously valid handoff is immediately unusable after the owner changes
// the assistant install, loses membership, or revokes the connection. Temporal
// signals may still be queued when the user clicks.
func TestHandoffImmediateAuthorizationFence(t *testing.T) {
	cp := fixture()
	req := Request{Principal: "principal-alice", Tenant: "tenant-alpha", OrderID: "ord-alpha"}
	cp.IssueHandoff(req.OrderID, req.Principal, "fp", 15*time.Minute)
	revisionToken := cp.Outbox[len(cp.Outbox)-1]
	cp.BumpRevision(req.Tenant, req.Principal)
	if err := cp.OpenHandoff(revisionToken, req, "fp"); !errors.Is(err, ErrRefused) {
		t.Fatalf("stale revision handoff accepted: %v", err)
	}
	cp.IssueHandoff(req.OrderID, req.Principal, "fp", 15*time.Minute)
	revokedToken := cp.Outbox[len(cp.Outbox)-1]
	cp.Deactivate(req.Tenant, req.Principal)
	if err := cp.OpenHandoff(revokedToken, req, "fp"); !errors.Is(err, ErrRefused) {
		t.Fatalf("revoked install handoff accepted: %v", err)
	}
	if err := cp.OpenHandoff(revokedToken, Request{Principal: req.Principal, Tenant: "tenant-beta", OrderID: req.OrderID}, "fp"); !errors.Is(err, ErrRefused) {
		t.Fatalf("tenant mismatch accepted: %v", err)
	}
}
