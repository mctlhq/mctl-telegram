// Package fake is a deterministic in-memory ControlBridge for tests. It
// mirrors the refusal semantics of ADR 0010 and is the only bridge
// implementation in this module.
package fake

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridge"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

type ConnState int

const (
	ConnActive ConnState = iota
	ConnRevoked
	ConnExpired
)

type Install struct {
	Tenant, Owner, Connection string
	Revision                  int64
	State                     ConnState
	ConnExpiresAt             time.Time // zero means no expiry
}

type Order struct{ Tenant, Owner string }

// Binding is what a receipt is bound to (ADR 0010 "Approval").
type Binding struct {
	Execution, Tenant, Owner, Connection, IntentHash, Fingerprint string
	InstallRevision                                               int64
}

type receipt struct {
	b       Binding
	expires time.Time
	used    bool
}

// Fault selects an injected bridge failure.
type Fault int

const (
	FaultNone Fault = iota
	FaultTimeout
	FaultTransport
	FaultMalformed // an "allow" that restates nothing
	FaultPartial   // an "allow" that restates only the tenant
)

var errTransport = errors.New("fake bridge: transport error")

// Bridge implements bridge.ControlBridge.
type Bridge struct {
	mu       sync.Mutex
	now      func() time.Time
	installs map[string]*Install
	orders   map[string]Order
	receipts map[string]*receipt
	fault    Fault
	consumed int
}

func New(now func() time.Time) *Bridge {
	if now == nil {
		now = time.Now
	}
	return &Bridge{now: now, installs: map[string]*Install{}, orders: map[string]Order{}, receipts: map[string]*receipt{}}
}

func (b *Bridge) AddInstall(ref string, in Install) {
	b.mu.Lock()
	b.installs[ref] = &in
	b.mu.Unlock()
}
func (b *Bridge) AddOrder(ref string, o Order) { b.mu.Lock(); b.orders[ref] = o; b.mu.Unlock() }
func (b *Bridge) SetFault(f Fault)             { b.mu.Lock(); b.fault = f; b.mu.Unlock() }

func (b *Bridge) BumpRevision(installRef string) {
	b.mu.Lock()
	b.installs[installRef].Revision++
	b.mu.Unlock()
}

func (b *Bridge) SetState(installRef string, s ConnState) {
	b.mu.Lock()
	b.installs[installRef].State = s
	b.mu.Unlock()
}

func (b *Bridge) AddReceipt(ref string, bind Binding, expires time.Time) {
	b.mu.Lock()
	b.receipts[ref] = &receipt{b: bind, expires: expires}
	b.mu.Unlock()
}

// Consumed reports how many receipts were successfully consumed.
func (b *Bridge) Consumed() int { b.mu.Lock(); defer b.mu.Unlock(); return b.consumed }

func (b *Bridge) injected() (error, bool) {
	switch b.fault {
	case FaultTimeout:
		return context.DeadlineExceeded, true
	case FaultTransport:
		return errTransport, true
	}
	return nil, false
}

func (b *Bridge) ResolveScope(_ context.Context, req v1alpha1.ProviderRequest) (bridge.Scope, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err, ok := b.injected(); ok {
		return bridge.Scope{}, err
	}
	switch b.fault {
	case FaultMalformed:
		return bridge.Scope{}, nil
	case FaultPartial:
		return bridge.Scope{TenantRef: req.TenantRef}, nil
	}
	if err := b.check(req); err != nil {
		return bridge.Scope{}, err
	}
	in := b.installs[req.InstallRef]
	return bridge.Scope{TenantRef: in.Tenant, OwnerRef: in.Owner, InstallRef: req.InstallRef,
		InstallRevision: in.Revision, ConnectionRef: in.Connection}, nil
}

// check applies the ADR 0010 refusal order; the caller holds b.mu.
func (b *Bridge) check(req v1alpha1.ProviderRequest) error {
	in, ok := b.installs[req.InstallRef]
	if !ok || in.Tenant != req.TenantRef {
		return bridge.Refuse(bridge.CodeNotAuthorized)
	}
	if in.Owner != req.OwnerRef {
		return bridge.Refuse(bridge.CodeNotAuthorized)
	}
	o, ok := b.orders[req.OrderRef]
	if !ok || o.Tenant != req.TenantRef {
		return bridge.Refuse(bridge.CodeNotFound)
	}
	if o.Owner != req.OwnerRef {
		return bridge.Refuse(bridge.CodeNotAuthorized)
	}
	if in.Revision != req.InstallRevision {
		return bridge.Refuse(bridge.CodeStaleInstall)
	}
	if in.Connection != req.ConnectionRef {
		return bridge.Refuse(bridge.CodeNotAuthorized)
	}
	switch {
	case in.State == ConnRevoked:
		return bridge.Refuse(bridge.CodeConnectionRevoked)
	case in.State == ConnExpired, !in.ConnExpiresAt.IsZero() && !b.now().Before(in.ConnExpiresAt):
		return bridge.Refuse(bridge.CodeConnectionExpired)
	}
	return nil
}

func (b *Bridge) ConsumeApproval(_ context.Context, req v1alpha1.ProviderRequest, fp string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err, ok := b.injected(); ok {
		return err
	}
	if b.fault == FaultMalformed || b.fault == FaultPartial {
		return errors.New("fake bridge: malformed answer")
	}
	if err := b.check(req); err != nil {
		return err
	}
	r, ok := b.receipts[req.ApprovalRef]
	if !ok {
		return bridge.Refuse(bridge.CodeApprovalInvalid)
	}
	bind := r.b
	switch {
	case bind.Execution != req.ExecutionRef:
		return bridge.Refuse(bridge.CodeApprovalInvalid)
	case bind.Tenant != req.TenantRef || bind.Owner != req.OwnerRef || bind.Connection != req.ConnectionRef ||
		bind.InstallRevision != req.InstallRevision:
		return bridge.Refuse(bridge.CodeNotAuthorized)
	case bind.IntentHash != req.IntentHash:
		return bridge.Refuse(bridge.CodeIntentMismatch)
	case bind.Fingerprint != fp:
		return bridge.Refuse(bridge.CodeApprovalInvalid)
	case !b.now().Before(r.expires):
		return bridge.Refuse(bridge.CodeApprovalExpired)
	case r.used:
		return bridge.Refuse(bridge.CodeApprovalReplayed)
	}
	r.used = true
	b.consumed++
	return nil
}

var _ bridge.ControlBridge = (*Bridge)(nil)
