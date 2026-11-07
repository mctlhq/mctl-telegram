// Package workflows holds GlovoOrderWorkflow and its activities. Workflow
// inputs and results carry opaque references and structured numbers only.
package workflows

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.temporal.io/sdk/temporal"

	"github.com/mctlhq/mctl-telegram/test/glovo-poc/controlplane"
	"github.com/mctlhq/mctl-telegram/test/glovo-poc/fairness"
	"github.com/mctlhq/mctl-telegram/test/glovo-poc/fakeglovo"
)

const (
	ErrTypeStale      = "stale_install"
	ErrTypeNeedsInput = "needs_input"
)

// Snapshot is the immutable OrderSnapshot.
type Snapshot struct {
	OrderID         string
	TenantID        string
	OwnerPrincipal  string
	InstallID       string
	InstallRevision int64
	ConnectionRef   string
	RequestRef      string
	ConsentTTL      time.Duration
	HandoffTTL      time.Duration
}

func (s Snapshot) scope() controlplane.Scope {
	return controlplane.Scope{TenantID: s.TenantID, OwnerPrincipal: s.OwnerPrincipal, InstallID: s.InstallID,
		InstallRevision: s.InstallRevision, ConnectionRef: s.ConnectionRef}
}

// QuoteResult is what a quote reveals to the workflow: numbers and IDs.
type QuoteResult struct {
	Fingerprint string
	Total       int
	Collision   bool
	ExistingN   int // number of lines already in the provider cart
}

// Encrypted, tenant-owned state, keyed by opaque reference.
type Vault struct {
	mu       sync.Mutex
	Drafts   map[string]fakeglovo.Draft
	Sessions map[string]Session
}

type Session struct{ Token, Address, BaseURL string }

func NewVault() *Vault {
	return &Vault{Drafts: map[string]fakeglovo.Draft{}, Sessions: map[string]Session{}}
}

func (v *Vault) Has(ref string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.Sessions[ref]
	return ok
}

type Activities struct {
	CP      *controlplane.CP
	Vault   *Vault
	Breaker *fairness.Breaker
	Log     *slog.Logger
}

func (a *Activities) client(ref string) (*fakeglovo.Client, error) {
	a.Vault.mu.Lock()
	s, ok := a.Vault.Sessions[ref]
	a.Vault.mu.Unlock()
	if !ok {
		return nil, temporal.NewNonRetryableApplicationError("no connection", ErrTypeStale, nil)
	}
	if a.Breaker != nil && !a.Breaker.Allow() {
		return nil, temporal.NewNonRetryableApplicationError("provider breaker open", "provider_unavailable", nil)
	}
	return fakeglovo.NewClient(s.BaseURL, s.Token)
}

func (a *Activities) note(err error) {
	if a.Breaker != nil {
		a.Breaker.Record(errors.Is(err, fakeglovo.ErrRateLimited))
	}
}

func (a *Activities) RevalidateScope(ctx context.Context, s Snapshot) error {
	if err := a.CP.Revalidate(s.scope()); err != nil {
		return temporal.NewNonRetryableApplicationError("scope changed", ErrTypeStale, err)
	}
	return nil
}

func (a *Activities) QuoteOrder(ctx context.Context, s Snapshot) (QuoteResult, error) {
	c, err := a.client(s.ConnectionRef)
	if err != nil {
		return QuoteResult{}, err
	}
	a.Vault.mu.Lock()
	d := a.Vault.Drafts[s.RequestRef]
	a.Vault.mu.Unlock()
	menu, err := c.GetMenu(ctx, d.Store)
	a.note(err)
	if err != nil {
		return QuoteResult{}, err
	}
	if verr := fakeglovo.Validate(menu, d); verr != nil {
		return QuoteResult{}, temporal.NewNonRetryableApplicationError(verr.Error(), ErrTypeNeedsInput, nil)
	}
	existing, err := c.ReadCart(ctx)
	a.note(err)
	if err != nil {
		return QuoteResult{}, err
	}
	q, err := c.QuoteBasket(ctx, d)
	a.note(err)
	if err != nil {
		return QuoteResult{}, err
	}
	return QuoteResult{Fingerprint: q.Fingerprint, Total: q.Total, Collision: len(existing.Lines) > 0, ExistingN: len(existing.Lines)}, nil
}

// MutateBasket is a write: one attempt only. On a timeout it reads back and
// accepts the write only if the cart already matches the consented fingerprint.
func (a *Activities) MutateBasket(ctx context.Context, s Snapshot, fingerprint string) error {
	c, err := a.client(s.ConnectionRef)
	if err != nil {
		return err
	}
	a.Vault.mu.Lock()
	d := a.Vault.Drafts[s.RequestRef]
	a.Vault.mu.Unlock()
	err = c.MutateBasket(ctx, d)
	a.note(err)
	if errors.Is(err, fakeglovo.ErrTimeout) {
		q, rerr := c.ReadBasket(ctx)
		if rerr == nil && q.Fingerprint == fingerprint {
			return nil
		}
		return temporal.NewNonRetryableApplicationError("write outcome unverified", "write_unverified", nil)
	}
	if err != nil {
		return temporal.NewNonRetryableApplicationError(err.Error(), "write_failed", nil)
	}
	return nil
}

func (a *Activities) ReadBasket(ctx context.Context, s Snapshot) (QuoteResult, error) {
	c, err := a.client(s.ConnectionRef)
	if err != nil {
		return QuoteResult{}, err
	}
	q, err := c.ReadBasket(ctx)
	a.note(err)
	if err != nil {
		return QuoteResult{}, err
	}
	return QuoteResult{Fingerprint: q.Fingerprint, Total: q.Total}, nil
}

// IssueHandoff returns only the token hash; the token goes to the owner
// channel (CP.Outbox) and never into workflow history.
func (a *Activities) IssueHandoff(ctx context.Context, s Snapshot, fingerprint string) (string, error) {
	h := a.CP.IssueHandoff(s.OrderID, s.OwnerPrincipal, fingerprint, s.HandoffTTL)
	a.Log.Info("handoff issued", "order", s.OrderID)
	return h, nil
}

func (a *Activities) ExpireHandoff(ctx context.Context, s Snapshot) error {
	a.CP.ExpireHandoffs(s.OrderID)
	return nil
}

// Purge deletes encrypted order state and the session reference.
func (a *Activities) Purge(ctx context.Context, s Snapshot) error {
	a.Vault.mu.Lock()
	defer a.Vault.mu.Unlock()
	delete(a.Vault.Drafts, s.RequestRef)
	delete(a.Vault.Sessions, s.ConnectionRef)
	a.Log.Info("order state purged", "order", s.OrderID)
	return nil
}

var _ = fmt.Sprintf
