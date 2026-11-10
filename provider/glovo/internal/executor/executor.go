package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fairness"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fakestore"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/obs"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

// Executor runs commands against the in-process fakestore.
type Executor struct {
	Store          *fakestore.Store
	Breaker        *fairness.Breaker
	Disabled       func() bool
	Metrics        *obs.Metrics
	WorkerIdentity string
	Now            func() time.Time
}

func (e *Executor) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

// SessionKey is the fake session of one tenant connection.
func SessionKey(c v1alpha1.Command) string { return c.TenantRef + "|" + c.ConnectionRef }

// Unavailable reports the kill switch or an open breaker.
func (e *Executor) Unavailable() bool {
	if e.Disabled != nil && e.Disabled() {
		return true
	}
	return e.Breaker != nil && !e.Breaker.Allow()
}

// HasPriorEffect reports a local effect record for the command: it came back
// after a reclaim, so the server's effect_state is already unknown.
func (e *Executor) HasPriorEffect(c v1alpha1.Command) bool {
	_, ok := e.Store.EffectOf(c.CommandID)
	return ok
}

// ResultRef is the deterministic result id of a command.
func ResultRef(commandID string) string {
	h := sha256.Sum256([]byte(commandID))
	return "res_" + hex.EncodeToString(h[:])[:20]
}

// Build turns a situation into a Result using the table row. detail, when not
// empty, overrides the row's default error_detail. result_ref is set only for
// the two success rows.
func (e *Executor) Build(s Situation, id v1alpha1.Envelope, detail string) (v1alpha1.Result, error) {
	row, ok := RowFor(s)
	if !ok || row.Outcome == "" {
		return v1alpha1.Result{}, errors.New("executor: situation sends no result")
	}
	if detail == "" {
		detail = row.Detail
	}
	r := v1alpha1.Result{
		SchemaVersion: v1alpha1.Version, CommandID: id.CommandID, ExecutionID: id.ExecutionID, LeaseToken: id.LeaseToken,
		Attempt: id.Attempt, WorkerIdentity: e.WorkerIdentity, Outcome: row.Outcome, ProviderEffect: row.Effect,
		ErrorCode: row.ErrorCode, ErrorDetail: detail, CompletedAt: e.now().Format("2006-01-02T15:04:05Z"),
	}
	if s == SitReadOK || s == SitApplied {
		r.ResultRef = ResultRef(id.CommandID)
	}
	return r, nil
}

// ID is the addressing envelope of a parsed command.
func ID(c v1alpha1.Command) v1alpha1.Envelope {
	return v1alpha1.Envelope{CommandID: c.CommandID, ExecutionID: c.ExecutionID, LeaseToken: c.LeaseToken, Attempt: c.Attempt}
}

func (e *Executor) record(err error) {
	if e.Breaker != nil {
		e.Breaker.Record(errors.Is(err, fakestore.ErrRateLimited))
	}
}

// classifyStore maps a fakestore error for a read.
func classifyStore(err error) Situation {
	switch {
	case err == nil:
		return SitReadOK
	case errors.Is(err, fakestore.ErrUnauthorized), errors.Is(err, fakestore.ErrUnavailable), errors.Is(err, fakestore.ErrNoOrder):
		return SitStoreRejected
	default: // rate limited, transient, timeout, context
		return SitStoreTransient
	}
}

// RunRead executes quote or read_status. It never needs a permit.
func (e *Executor) RunRead(ctx context.Context, c v1alpha1.Command) Situation {
	key := SessionKey(c)
	e.Store.EnsureSession(key)
	cl := e.Store.Client(key)
	switch c.Kind {
	case v1alpha1.KindQuote:
		var d fakestore.Draft
		for _, code := range c.Payload.ItemCodes {
			d.Lines = append(d.Lines, fakestore.Line{ItemID: code, Qty: 1})
		}
		_, err := cl.QuoteBasket(ctx, d)
		e.record(err)
		return classifyStore(err)
	case v1alpha1.KindReadStatus:
		_, err := cl.ReadCart(ctx) // authenticates the fake session; status itself is local
		e.record(err)
		if err == nil {
			e.Store.OrderStatus(c.OrderRef)
		}
		return classifyStore(err)
	}
	return SitUnmapped
}

func linesOf(c v1alpha1.Command) []fakestore.Line {
	var out []fakestore.Line
	if c.Basket != nil {
		for _, l := range c.Basket.Lines {
			out = append(out, fakestore.Line{ItemID: l.ItemCode, Qty: l.Quantity})
		}
		return out
	}
	for _, code := range c.Payload.ItemCodes {
		out = append(out, fakestore.Line{ItemID: code, Qty: 1})
	}
	return out
}

// RunWrite performs the one fake effect of a mutating command. The caller
// must hold a granted permit and have checked HasPriorEffect. The effect is
// confirmed by read-back before SitApplied is reported.
func (e *Executor) RunWrite(ctx context.Context, c v1alpha1.Command) Situation {
	key := SessionKey(c)
	e.Store.EnsureSession(key)
	cl := e.Store.Client(key)
	var err error
	switch c.Kind {
	case v1alpha1.KindPlaceOrder:
		lines := linesOf(c)
		if len(lines) == 0 {
			return SitStoreRejected
		}
		err = cl.PlaceOrderFake(ctx, c.CommandID, c.OrderRef, lines)
	case v1alpha1.KindCancelOrder:
		err = cl.CancelOrderFake(ctx, c.CommandID, c.OrderRef)
	default:
		return SitUnmapped
	}
	e.record(err)
	if err != nil {
		switch {
		case errors.Is(err, fakestore.ErrRateLimited):
			return SitStoreTransient
		case errors.Is(err, fakestore.ErrUnauthorized), errors.Is(err, fakestore.ErrUnavailable), errors.Is(err, fakestore.ErrNoOrder):
			return SitStoreRejected
		}
	}
	// Success or an ambiguous error: only the read-back decides.
	if _, ok := e.Store.EffectOf(c.CommandID); ok {
		return SitApplied
	}
	if e.Metrics != nil {
		e.Metrics.AmbiguousWrites.Inc()
	}
	return SitAmbiguousWrite
}
