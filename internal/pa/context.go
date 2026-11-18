package pa

import (
	"errors"
	"fmt"
	"slices"
)

// Trigger is what started a run. ADR 0011 names three; Phase 1 creates only
// TriggerInteractive, and only NewInteractive exists as a constructor.
type Trigger string

const (
	TriggerInteractive Trigger = "interactive"
	TriggerScheduled   Trigger = "scheduled"
	TriggerEvent       Trigger = "event"
)

// ConsentDataFlowV1 is the consent text version every Phase 1 run requires
// (threat model T13). The consent record itself lands in a later slice; the
// context only carries which version the run was admitted under.
const ConsentDataFlowV1 = "pa-data-flow/v1"

// ConnectionRevision binds a run to one connection at one authority revision
// (threat model T2, I4). A dispatch whose connection has moved past this
// revision is refused by the executor.
type ConnectionRevision struct {
	ConnectionID      string
	AuthorityRevision int64
}

// BudgetReservation identifies the ledger hold taken at claim (ADR 0008
// ledger, #1092; threat model T10). A run without one does not exist.
type BudgetReservation struct {
	ID string
}

// ExecutionContext is carried by every PA run (ADR 0011). Fields are
// unexported and set only by a constructor that validates them, so a
// half-built context cannot exist.
type ExecutionContext struct {
	principal      Principal
	trigger        Trigger
	conversationID string
	connections    []ConnectionRevision
	budget         BudgetReservation
	consentVersion string
}

// Errors from the constructor. None carries a value from the input.
var (
	ErrNoPrincipal      = errors.New("pa: execution context needs a principal")
	ErrNoConversation   = errors.New("pa: execution context needs a conversation id")
	ErrNoBudget         = errors.New("pa: execution context needs a budget reservation")
	ErrConsentVersion   = errors.New("pa: execution context needs the current consent version")
	ErrBadConnectionRev = errors.New("pa: invalid connection revision")
)

// NewInteractive builds the context of a Phase 1 run. The principal comes
// from the VerifiedUpdate and from nowhere else (I2). It fails closed on any
// missing part.
func NewInteractive(u VerifiedUpdate, conversationID string, conns []ConnectionRevision, budget BudgetReservation, consentVersion string) (ExecutionContext, error) {
	if u.principal.IsZero() {
		return ExecutionContext{}, ErrNoPrincipal
	}
	if conversationID == "" {
		return ExecutionContext{}, ErrNoConversation
	}
	if budget.ID == "" {
		return ExecutionContext{}, ErrNoBudget
	}
	if consentVersion != ConsentDataFlowV1 {
		return ExecutionContext{}, ErrConsentVersion
	}
	seen := make(map[string]struct{}, len(conns))
	for i, c := range conns {
		if c.ConnectionID == "" || c.AuthorityRevision <= 0 {
			return ExecutionContext{}, fmt.Errorf("%w: entry %d", ErrBadConnectionRev, i)
		}
		if _, dup := seen[c.ConnectionID]; dup {
			return ExecutionContext{}, fmt.Errorf("%w: entry %d repeats a connection", ErrBadConnectionRev, i)
		}
		seen[c.ConnectionID] = struct{}{}
	}
	return ExecutionContext{
		principal:      u.principal,
		trigger:        TriggerInteractive,
		conversationID: conversationID,
		connections:    slices.Clone(conns),
		budget:         budget,
		consentVersion: consentVersion,
	}, nil
}

// Trigger is for audit records and metrics labels only. Tiering, provenance,
// approval and limits code takes a Policy instead, which has no trigger.
func (c ExecutionContext) Trigger() Trigger { return c.trigger }

// Policy returns the view that tiering, approval and limits code reads.
func (c ExecutionContext) Policy() Policy { return Policy{ec: c} }

// Principal returns the run's principal.
func (c ExecutionContext) Principal() Principal { return c.principal }

// ConversationID returns the conversation the run belongs to.
func (c ExecutionContext) ConversationID() string { return c.conversationID }

// Connections returns a copy of the bound connection revisions.
func (c ExecutionContext) Connections() []ConnectionRevision {
	return slices.Clone(c.connections)
}

// Budget returns the ledger reservation.
func (c ExecutionContext) Budget() BudgetReservation { return c.budget }

// ConsentVersion returns the consent version the run was admitted under.
func (c ExecutionContext) ConsentVersion() string { return c.consentVersion }

// Policy is the part of an ExecutionContext that gate code may read
// (ADR 0011: "tiering, provenance, approvals, audit and limits read only the
// context, never the trigger"). It deliberately has no Trigger accessor, so
// a scheduled run can never be given a weaker gate by branching on how it
// started: whatever makes a run need more or less approval must be a field of
// the context itself. TestPolicyHasNoTrigger enforces the shape.
type Policy struct{ ec ExecutionContext }

func (p Policy) Principal() Principal              { return p.ec.principal }
func (p Policy) ConversationID() string            { return p.ec.conversationID }
func (p Policy) Connections() []ConnectionRevision { return slices.Clone(p.ec.connections) }
func (p Policy) Budget() BudgetReservation         { return p.ec.budget }
func (p Policy) ConsentVersion() string            { return p.ec.consentVersion }
func (p Policy) Connection(id string) (ConnectionRevision, bool) {
	for _, c := range p.ec.connections {
		if c.ConnectionID == id {
			return c, true
		}
	}
	return ConnectionRevision{}, false
}
