// Package activities holds the provider-side Temporal activities. Every
// activity accepts opaque protocol references only and resolves authority
// through the ControlBridge before touching the fake provider.
package activities

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"sync"

	"go.temporal.io/sdk/temporal"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/basket"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridge"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fairness"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fakestore"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/obs"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

// QuoteResult is what a quote reveals to the workflow: numbers and IDs.
type QuoteResult struct {
	Fingerprint string
	Total       int
	Collision   bool
	ExistingN   int // number of lines already in the provider basket
}

// MutateResult reports the observable effect of MutateBasket.
type MutateResult struct {
	Applied bool // this call changed the basket
	Deduped bool // an effect for the idempotency key was already recorded
}

// DraftStore holds per-order synthetic drafts keyed by (tenant, order), so one
// tenant's order reference can never address another tenant's draft.
type DraftStore struct {
	mu sync.Mutex
	m  map[[2]string]fakestore.Draft
}

func NewDraftStore() *DraftStore { return &DraftStore{m: map[[2]string]fakestore.Draft{}} }

func (d *DraftStore) Put(tenant, order string, dr fakestore.Draft) {
	d.mu.Lock()
	d.m[[2]string{tenant, order}] = dr
	d.mu.Unlock()
}

func (d *DraftStore) Get(tenant, order string) (fakestore.Draft, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	dr, ok := d.m[[2]string{tenant, order}]
	return dr, ok
}

func (d *DraftStore) Delete(tenant, order string) {
	d.mu.Lock()
	delete(d.m, [2]string{tenant, order})
	d.mu.Unlock()
}

func (d *DraftStore) Len() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.m) }

// SessionKey is the fakestore session key for a request. It includes the
// tenant so the same gcn_ reference in another tenant addresses nothing.
func SessionKey(tenant, connection string) string { return tenant + "|" + connection }

// Activities is registered on the worker.
type Activities struct {
	Bridge  bridge.ControlBridge
	Store   *fakestore.Store
	Ledger  *basket.Ledger
	Drafts  *DraftStore
	Breaker *fairness.Breaker
	Limiter *fairness.Limiter
	// Disabled is the kill switch; nil means enabled.
	Disabled func() bool
	Log      *slog.Logger
	Metrics  *obs.Metrics
	// Test-only scheduling seam: fires after the external write, before the
	// activity returns its result to the workflow.
	AfterProviderWrite func()
}

// Refuse builds the non-retryable Temporal error for a refusal code.
func Refuse(code string, cause error) error {
	return temporal.NewNonRetryableApplicationError(code, code, cause)
}

// ErrCode returns the refusal code carried by a Temporal application error.
func ErrCode(err error) string {
	var ae *temporal.ApplicationError
	if errors.As(err, &ae) {
		return ae.Type()
	}
	return ""
}

func (a *Activities) refusal(req v1alpha1.ProviderRequest, err error) error {
	code := bridge.CodeOf(err)
	if code == "" {
		code = bridge.CodeBridgeUnavailable
	}
	if a.Metrics != nil {
		a.Metrics.Refusals.WithLabelValues(code).Inc()
	}
	obs.Audit(a.Log, obs.EventScopeRefused, req.ExecutionRef, req.OrderRef, code)
	return Refuse(code, nil)
}

func (a *Activities) invalid(err error) error {
	if a.Metrics != nil {
		a.Metrics.Refusals.WithLabelValues(bridge.CodeInvalidRequest).Inc()
	}
	return Refuse(bridge.CodeInvalidRequest, err)
}

// resolve validates the request and resolves live scope.
func (a *Activities) resolve(ctx context.Context, req v1alpha1.ProviderRequest) error {
	if err := req.Validate(); err != nil {
		return a.invalid(err)
	}
	if _, err := a.Bridge.ResolveScope(ctx, req); err != nil {
		return a.refusal(req, err)
	}
	return nil
}

// admit applies the per-tenant limiter; the returned func releases the slot.
func (a *Activities) admit(tenant string) (func(), error) {
	if a.Limiter == nil {
		return func() {}, nil
	}
	if !a.Limiter.TryAcquire(tenant) {
		return nil, Refuse(bridge.CodeTenantBusy, nil)
	}
	return func() { a.Limiter.Release(tenant) }, nil
}

func (a *Activities) breakerOpen() bool { return a.Breaker != nil && !a.Breaker.Allow() }

func (a *Activities) note(err error) {
	if a.Breaker != nil {
		a.Breaker.Record(errors.Is(err, fakestore.ErrRateLimited))
		if a.Metrics != nil {
			if a.Breaker.Allow() {
				a.Metrics.BreakerOpn.Set(0)
			} else {
				a.Metrics.BreakerOpn.Set(1)
			}
		}
	}
}

func (a *Activities) client(req v1alpha1.ProviderRequest) (*fakestore.Client, error) {
	key := SessionKey(req.TenantRef, req.ConnectionRef)
	if !a.Store.HasSession(key) {
		return nil, Refuse(bridge.CodeConnectionRevoked, nil)
	}
	if a.breakerOpen() {
		return nil, Refuse(bridge.CodeProviderUnavail, nil)
	}
	return a.Store.Client(key), nil
}

// RevalidateScope re-resolves live scope; any refusal is non-retryable.
func (a *Activities) RevalidateScope(ctx context.Context, req v1alpha1.ProviderRequest) error {
	return a.resolve(ctx, req)
}

func (a *Activities) QuoteOrder(ctx context.Context, req v1alpha1.ProviderRequest) (QuoteResult, error) {
	if err := a.resolve(ctx, req); err != nil {
		return QuoteResult{}, err
	}
	release, err := a.admit(req.TenantRef)
	if err != nil {
		return QuoteResult{}, err
	}
	defer release()
	c, err := a.client(req)
	if err != nil {
		return QuoteResult{}, err
	}
	d, ok := a.Drafts.Get(req.TenantRef, req.OrderRef)
	if !ok {
		return QuoteResult{}, Refuse(bridge.CodeNeedsInput, nil)
	}
	menu, err := c.GetMenu(ctx, d.Store)
	a.note(err)
	if err != nil {
		return QuoteResult{}, err
	}
	if verr := fakestore.Validate(menu, d); verr != nil {
		return QuoteResult{}, Refuse(bridge.CodeNeedsInput, verr)
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

// MutateBasket is a write: one Temporal attempt only, and idempotent under
// operator-driven or Temporal retries. Order of operations:
//
//  1. validate the request incl. aar_ ref;
//  2. kill switch, breaker, per-tenant limiter;
//  3. resolve live scope through the bridge;
//  4. idempotency ledger lookup (tenant, order, intent hash);
//  5. read back the basket; an already-matching fingerprint is recorded
//     without consuming a receipt;
//  6. consume the single-use aar_ receipt through the bridge;
//  7. apply; on an ambiguous timeout read back and compare;
//  8. record in the ledger and emit an audit event.
func (a *Activities) MutateBasket(ctx context.Context, req v1alpha1.ProviderRequest, fingerprint string) (MutateResult, error) {
	if err := req.RequireApproval(); err != nil {
		return MutateResult{}, a.invalid(err)
	}
	if (a.Disabled != nil && a.Disabled()) || a.breakerOpen() {
		code := bridge.CodeProviderDisabled
		if a.Disabled == nil || !a.Disabled() {
			code = bridge.CodeProviderUnavail
		}
		if a.Metrics != nil {
			a.Metrics.Refusals.WithLabelValues(code).Inc()
		}
		return MutateResult{}, Refuse(code, nil)
	}
	release, err := a.admit(req.TenantRef)
	if err != nil {
		return MutateResult{}, err
	}
	defer release()
	if err := a.resolve(ctx, req); err != nil {
		return MutateResult{}, err
	}
	d, ok := a.Drafts.Get(req.TenantRef, req.OrderRef)
	if !ok {
		return MutateResult{}, Refuse(bridge.CodeNeedsInput, nil)
	}
	c, err := a.client(req)
	if err != nil {
		return MutateResult{}, err
	}
	key := basket.Key{Tenant: req.TenantRef, Order: req.OrderRef, IntentHash: req.IntentHash}
	applied := false
	_, deduped, err := a.Ledger.Do(key, func() (basket.Entry, error) {
		cur, rerr := c.ReadBasket(ctx)
		a.note(rerr)
		if rerr != nil && !errors.Is(rerr, fakestore.ErrUnavailable) {
			return basket.Entry{}, rerr
		}
		if rerr == nil && cur.Fingerprint == fingerprint {
			return basket.Entry{Fingerprint: fingerprint}, nil
		}
		if cerr := a.Bridge.ConsumeApproval(ctx, req, fingerprint); cerr != nil {
			return basket.Entry{}, a.refusal(req, cerr)
		}
		werr := c.MutateBasket(ctx, d)
		a.note(werr)
		if errors.Is(werr, fakestore.ErrTimeout) {
			q, rerr := c.ReadBasket(ctx)
			if rerr != nil || q.Fingerprint != fingerprint {
				return basket.Entry{}, Refuse(bridge.CodeWriteUnverified, nil)
			}
		} else if werr != nil {
			return basket.Entry{}, Refuse(bridge.CodeWriteFailed, nil)
		}
		applied = true
		if a.AfterProviderWrite != nil {
			a.AfterProviderWrite()
		}
		return basket.Entry{Fingerprint: fingerprint}, nil
	})
	if err != nil {
		return MutateResult{}, err
	}
	if deduped {
		// Step 4: an effect is already recorded; verify, never re-apply.
		if q, rerr := c.ReadBasket(ctx); rerr != nil || q.Fingerprint != fingerprint {
			return MutateResult{}, Refuse(bridge.CodeWriteUnverified, nil)
		}
	}
	ev, result := obs.EventMutationApplied, "applied"
	if !applied {
		ev, result = obs.EventMutationDeduped, "deduped"
	}
	if a.Metrics != nil {
		a.Metrics.Mutations.WithLabelValues(result).Inc()
	}
	obs.Audit(a.Log, ev, req.ExecutionRef, req.OrderRef, result)
	return MutateResult{Applied: applied, Deduped: !applied}, nil
}

func (a *Activities) ReadBasket(ctx context.Context, req v1alpha1.ProviderRequest) (QuoteResult, error) {
	if err := a.resolve(ctx, req); err != nil {
		return QuoteResult{}, err
	}
	c, err := a.client(req)
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

// IssueHandoff revalidates scope and returns an opaque marker. The handoff
// token itself is minted by the control plane and never passes through here.
func (a *Activities) IssueHandoff(ctx context.Context, req v1alpha1.ProviderRequest, fingerprint string) (string, error) {
	if err := a.resolve(ctx, req); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(req.ExecutionRef + "\x00" + req.OrderRef + "\x00" + fingerprint))
	obs.Audit(a.Log, obs.EventHandoffIssued, req.ExecutionRef, req.OrderRef, "ok")
	return hex.EncodeToString(sum[:]), nil
}

// ExpireHandoff is the provider-side acknowledgement that a handoff window
// ended; it holds no state.
func (a *Activities) ExpireHandoff(_ context.Context, req v1alpha1.ProviderRequest) error {
	obs.Audit(a.Log, obs.EventPurged, req.ExecutionRef, req.OrderRef, "handoff_expired")
	return nil
}

// PurgeOrder deletes only the per-order draft and ledger entries. Purges
// are keyed by the request's own tenant, so they cannot reach another tenant.
func (a *Activities) PurgeOrder(_ context.Context, req v1alpha1.ProviderRequest) error {
	a.Drafts.Delete(req.TenantRef, req.OrderRef)
	a.Ledger.Forget(req.TenantRef, req.OrderRef)
	obs.Audit(a.Log, obs.EventPurged, req.ExecutionRef, req.OrderRef, "order")
	return nil
}

// PurgeConnection additionally deletes the session. Used only when the
// install or connection is revoked.
func (a *Activities) PurgeConnection(ctx context.Context, req v1alpha1.ProviderRequest) error {
	_ = a.PurgeOrder(ctx, req)
	a.Store.DropSession(SessionKey(req.TenantRef, req.ConnectionRef))
	obs.Audit(a.Log, obs.EventPurged, req.ExecutionRef, req.OrderRef, "connection")
	return nil
}
