package pa

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

func verified(t *testing.T, user int64) VerifiedUpdate {
	t.Helper()
	u, outcome := Filter([]byte(privateMessage(1, user, "")))
	if outcome != OutcomeAccepted {
		t.Fatalf("fixture rejected: %s", outcome)
	}
	return u
}

func TestNewInteractive(t *testing.T) {
	alice := verified(t, aliceID)
	conns := []ConnectionRevision{{ConnectionID: "conn-a", AuthorityRevision: 3}}
	ec, err := NewInteractive(alice, "conv-a", conns, BudgetReservation{ID: "hold-a"}, ConsentDataFlowV1)
	if err != nil {
		t.Fatal(err)
	}
	if ec.Trigger() != TriggerInteractive {
		t.Fatalf("trigger = %q, want interactive", ec.Trigger())
	}
	if ec.Principal().TelegramID() != aliceID || ec.ConversationID() != "conv-a" ||
		ec.Budget().ID != "hold-a" || ec.ConsentVersion() != ConsentDataFlowV1 {
		t.Fatalf("context = %+v", ec)
	}
	// The context owns its copy of the connection list.
	conns[0].AuthorityRevision = 99
	if c, _ := ec.Policy().Connection("conn-a"); c.AuthorityRevision != 3 {
		t.Fatal("caller mutation reached the context")
	}
	got := ec.Connections()
	got[0].AuthorityRevision = 99
	if c, _ := ec.Policy().Connection("conn-a"); c.AuthorityRevision != 3 {
		t.Fatal("accessor result aliases the context")
	}
}

func TestNewInteractive_FailsClosed(t *testing.T) {
	alice := verified(t, aliceID)
	ok := []ConnectionRevision{{ConnectionID: "c", AuthorityRevision: 1}}
	budget := BudgetReservation{ID: "hold"}
	cases := []struct {
		name    string
		u       VerifiedUpdate
		conv    string
		conns   []ConnectionRevision
		budget  BudgetReservation
		consent string
		want    error
	}{
		{"zero update has no principal", VerifiedUpdate{}, "conv", ok, budget, ConsentDataFlowV1, ErrNoPrincipal},
		{"no conversation", alice, "", ok, budget, ConsentDataFlowV1, ErrNoConversation},
		{"no budget reservation", alice, "conv", ok, BudgetReservation{}, ConsentDataFlowV1, ErrNoBudget},
		{"no consent", alice, "conv", ok, budget, "", ErrConsentVersion},
		{"other consent version", alice, "conv", ok, budget, "pa-data-flow/v0", ErrConsentVersion},
		{"connection without id", alice, "conv", []ConnectionRevision{{AuthorityRevision: 1}}, budget, ConsentDataFlowV1, ErrBadConnectionRev},
		{"connection without revision", alice, "conv", []ConnectionRevision{{ConnectionID: "c"}}, budget, ConsentDataFlowV1, ErrBadConnectionRev},
		{"duplicate connection", alice, "conv", []ConnectionRevision{{ConnectionID: "c", AuthorityRevision: 1}, {ConnectionID: "c", AuthorityRevision: 2}}, budget, ConsentDataFlowV1, ErrBadConnectionRev},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewInteractive(tc.u, tc.conv, tc.conns, tc.budget, tc.consent)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestPolicyHasNoTrigger enforces ADR 0011's rule that tiering, approval and
// limits code reads only the context, never the trigger: the Policy view
// they take has no method that yields a Trigger and no field of that type.
func TestPolicyHasNoTrigger(t *testing.T) {
	triggerType := reflect.TypeOf(Trigger(""))
	pt := reflect.TypeOf(Policy{})
	for i := range pt.NumMethod() {
		m := pt.Method(i)
		for j := range m.Type.NumOut() {
			if m.Type.Out(j) == triggerType {
				t.Errorf("Policy.%s returns the trigger", m.Name)
			}
		}
	}
	if pt.NumField() != 1 || pt.Field(0).Type != reflect.TypeOf(ExecutionContext{}) || pt.Field(0).IsExported() {
		t.Error("Policy must wrap an unexported ExecutionContext and nothing else")
	}
}

// S1-X1/X2 at the context layer: a context is bound to the principal of the
// update it was built from; Bob's context never names Alice.
func TestExecutionContext_PrincipalComesFromUpdate(t *testing.T) {
	alice, bob := verified(t, aliceID), verified(t, bobID)
	ea, err := NewInteractive(alice, "conv", nil, BudgetReservation{ID: "h1"}, ConsentDataFlowV1)
	if err != nil {
		t.Fatal(err)
	}
	eb, err := NewInteractive(bob, "conv", nil, BudgetReservation{ID: "h2"}, ConsentDataFlowV1)
	if err != nil {
		t.Fatal(err)
	}
	if ea.Policy().Principal() == eb.Policy().Principal() {
		t.Fatal("two principals produced the same context principal")
	}
	if eb.Principal().TelegramID() != bobID {
		t.Fatalf("Bob's context principal = %d", eb.Principal().TelegramID())
	}
}

func TestNoopMemoryStore(t *testing.T) {
	ec, err := NewInteractive(verified(t, aliceID), "conv", nil, BudgetReservation{ID: "h"}, ConsentDataFlowV1)
	if err != nil {
		t.Fatal(err)
	}
	var m MemoryStore = NoopMemoryStore{}
	ctx := context.Background()
	if err := m.Remember(ctx, ec, MemoryItem{Text: "x", Provenance: ProvenanceUser}); !errors.Is(err, ErrMemoryDisabled) {
		t.Fatalf("Remember error = %v, want ErrMemoryDisabled", err)
	}
	items, err := m.Recall(ctx, ec)
	if err != nil || len(items) != 0 {
		t.Fatalf("Recall = %v, %v; want nothing", items, err)
	}
	if err := m.Forget(ctx, ec); err != nil {
		t.Fatalf("Forget error = %v", err)
	}
}

// A zero or half-built context is invalid, and the memory store refuses it
// rather than acting for principal 0.
func TestExecutionContext_ZeroIsInvalid(t *testing.T) {
	if (ExecutionContext{}).Valid() {
		t.Fatal("zero ExecutionContext reports valid")
	}
	ec, err := NewInteractive(verified(t, aliceID), "conv", nil, BudgetReservation{ID: "h"}, ConsentDataFlowV1)
	if err != nil || !ec.Valid() {
		t.Fatalf("constructed context: valid=%v err=%v", ec.Valid(), err)
	}
	var m MemoryStore = NoopMemoryStore{}
	ctx := context.Background()
	if _, err := m.Recall(ctx, ExecutionContext{}); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("Recall(zero) error = %v, want ErrInvalidContext", err)
	}
	if err := m.Remember(ctx, ExecutionContext{}, MemoryItem{}); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("Remember(zero) error = %v, want ErrInvalidContext", err)
	}
	if err := m.Forget(ctx, ExecutionContext{}); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("Forget(zero) error = %v, want ErrInvalidContext", err)
	}
}

func TestProvenanceEffective(t *testing.T) {
	for p, want := range map[Provenance]Provenance{
		ProvenanceUser:     ProvenanceUser,
		ProvenanceExternal: ProvenanceExternal,
		"":                 ProvenanceExternal,
		"USER":             ProvenanceExternal,
	} {
		if got := p.Effective(); got != want {
			t.Errorf("%q.Effective() = %q, want %q", p, got, want)
		}
	}
}

// TestRestoreInteractive: the claim rebuilds a run's context from the job
// row only, through NewInteractive: the principal, conversation and consent
// version are the row's, the trigger is interactive, and a row that would
// not make a valid interactive context fails the same way.
// Mutations: take the principal from anywhere but j.Principal; skip the
// principal check; bypass NewInteractive's validation.
func TestRestoreInteractive(t *testing.T) {
	conns := []ConnectionRevision{{ConnectionID: "conn-a", AuthorityRevision: 2}}
	budget := BudgetReservation{ID: "pa_usage:7"}
	j := jobs.Job{ID: 7, Principal: aliceID, ConversationID: "conv-a", ConsentVersion: ConsentDataFlowV1}
	ec, err := restoreInteractive(j, conns, budget)
	if err != nil {
		t.Fatal(err)
	}
	if ec.Principal().TelegramID() != aliceID || ec.ConversationID() != "conv-a" || ec.Trigger() != TriggerInteractive ||
		ec.ConsentVersion() != ConsentDataFlowV1 || ec.Budget().ID != "pa_usage:7" ||
		!reflect.DeepEqual(ec.Connections(), conns) {
		t.Fatalf("restored context = %+v", ec)
	}
	for _, tc := range []struct {
		name string
		mut  func(*jobs.Job)
		b    BudgetReservation
		want error
	}{
		{"no principal", func(j *jobs.Job) { j.Principal = 0 }, budget, ErrNoPrincipal},
		{"negative principal", func(j *jobs.Job) { j.Principal = -1 }, budget, ErrNoPrincipal},
		{"no conversation", func(j *jobs.Job) { j.ConversationID = "" }, budget, ErrNoConversation},
		{"other consent version", func(j *jobs.Job) { j.ConsentVersion = "pa-data-flow/v0" }, budget, ErrConsentVersion},
		{"no reservation", func(*jobs.Job) {}, BudgetReservation{}, ErrNoBudget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := j
			tc.mut(&bad)
			if _, err := restoreInteractive(bad, conns, tc.b); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}
