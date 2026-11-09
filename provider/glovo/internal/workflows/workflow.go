// Package workflows holds the provider-side GlovoOrderWorkflow. Workflow
// inputs and results carry opaque references and structured numbers only.
package workflows

import (
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/activities"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridge"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

const (
	SigConsent  = "consent"
	SigOpened   = "handoff_opened"
	SigRevoked  = "install_revoked"
	SigCancel   = "cancel"
	QueryStatus = "status"
)

// Terminal and intermediate states.
const (
	StateRevoked       = "revoked"
	StateCancelled     = "cancelled"
	StateStale         = "stale_install"
	OutcomeUnknown     = "OUTCOME_UNKNOWN"
	StateProviderUnavl = "provider_unavailable"
)

// Snapshot is the immutable order snapshot: protocol refs plus timers.
type Snapshot struct {
	Req        v1alpha1.ProviderRequest
	ConsentTTL time.Duration
	HandoffTTL time.Duration
}

type ConsentSignal struct {
	Nonce           string
	Fingerprint     string
	InstallRevision int64
	ReplaceExisting bool
}

type Status struct {
	State       string
	Fingerprint string
	Collision   bool
	Duplicates  int
	Rejected    int
}

type Result struct {
	Status string
	States []string
}

// revokingCodes are refusals that mean the install or connection is gone.
var revokingCodes = map[string]bool{
	bridge.CodeConnectionRevoked: true, bridge.CodeConnectionExpired: true,
	bridge.CodeNotAuthorized: true, bridge.CodeNotFound: true,
}

func GlovoOrderWorkflow(ctx workflow.Context, snap Snapshot) (Result, error) {
	var res Result
	st := Status{}
	set := func(s string) { st.State = s; res.States = append(res.States, s); res.Status = s }
	if err := workflow.SetQueryHandler(ctx, QueryStatus, func() (Status, error) { return st, nil }); err != nil {
		return res, err
	}
	req := snap.Req
	read := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 2, MaximumAttempts: 5},
	})
	write := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	var a *activities.Activities
	consentCh := workflow.GetSignalChannel(ctx, SigConsent)
	openedCh := workflow.GetSignalChannel(ctx, SigOpened)
	revokedCh := workflow.GetSignalChannel(ctx, SigRevoked)
	cancelCh := workflow.GetSignalChannel(ctx, SigCancel)

	disconnected := func() workflow.Context {
		dctx, _ := workflow.NewDisconnectedContext(ctx)
		return workflow.WithActivityOptions(dctx, workflow.ActivityOptions{StartToCloseTimeout: time.Minute})
	}
	purge := func(connection bool) {
		dctx := disconnected()
		if connection {
			_ = workflow.ExecuteActivity(dctx, a.PurgeConnection, req).Get(dctx, nil)
			return
		}
		_ = workflow.ExecuteActivity(dctx, a.PurgeOrder, req).Get(dctx, nil)
	}
	// terminate expires any handoff and purges in a disconnected context.
	// Revoke purges the install connection; cancel only the order.
	terminate := func(revoked bool) (Result, error) {
		dctx := disconnected()
		_ = workflow.ExecuteActivity(dctx, a.ExpireHandoff, req).Get(dctx, nil)
		purge(revoked)
		if revoked {
			set(StateRevoked)
		} else {
			set(StateCancelled)
		}
		return res, nil
	}
	// pending reports a revoke or cancel received after the last wait; revoke
	// wins over cancel.
	pending := func() (revoked, cancelled bool) {
		revoked = revokedCh.ReceiveAsync(nil)
		cancelled = cancelCh.ReceiveAsync(nil)
		return
	}
	// Signals may arrive while an activity is awaiting its result. Check them
	// before interpreting any activity exit, including error paths.
	checkPending := func() (Result, bool) {
		if rv, cn := pending(); rv || cn {
			r, _ := terminate(rv)
			return r, true
		}
		return Result{}, false
	}
	// refused maps a failed revalidation or read to a terminal state.
	refused := func(err error) (Result, error) {
		code := activities.ErrCode(err)
		switch {
		case code == bridge.CodeStaleInstall:
			set(StateStale)
		case revokingCodes[code]:
			dctx := disconnected()
			_ = workflow.ExecuteActivity(dctx, a.ExpireHandoff, req).Get(dctx, nil)
			purge(true)
			set(StateRevoked)
		case code == bridge.CodeBridgeUnavailable || code == bridge.CodeInvalidRequest:
			set(code)
		default:
			set(StateProviderUnavl)
		}
		return res, nil
	}

	set("prepared")
	err := workflow.ExecuteActivity(read, a.RevalidateScope, req).Get(ctx, nil)
	if r, done := checkPending(); done {
		return r, nil
	}
	if err != nil {
		return refused(err)
	}
	var q activities.QuoteResult
	err = workflow.ExecuteActivity(read, a.QuoteOrder, req).Get(ctx, &q)
	if r, done := checkPending(); done {
		return r, nil
	}
	if err != nil {
		switch code := activities.ErrCode(err); {
		case code == bridge.CodeNeedsInput:
			set("needs_input")
			return res, nil
		case code == bridge.CodeStaleInstall || revokingCodes[code] || code == bridge.CodeBridgeUnavailable:
			return refused(err)
		}
		set(StateProviderUnavl)
		return res, nil
	}
	set("quoted")
	st.Fingerprint, st.Collision = q.Fingerprint, q.Collision
	set("awaiting_consent")

	// Wait for consent bound to (fingerprint, install revision).
	tctx, cancelTimer := workflow.WithCancel(ctx)
	timer := workflow.NewTimer(tctx, snap.ConsentTTL)
	seen := map[string]bool{}
	var consented, expired, revoked, cancelled bool
	for !consented && !expired && !revoked && !cancelled {
		sel := workflow.NewSelector(ctx)
		sel.AddReceive(consentCh, func(c workflow.ReceiveChannel, _ bool) {
			var s ConsentSignal
			c.Receive(ctx, &s)
			switch {
			case seen[s.Nonce]:
				st.Duplicates++
			case s.Fingerprint != q.Fingerprint || s.InstallRevision != req.InstallRevision:
				seen[s.Nonce] = true
				st.Rejected++
			case q.Collision && !s.ReplaceExisting:
				seen[s.Nonce] = true
				st.Rejected++ // collision needs an explicit replace decision
			default:
				seen[s.Nonce] = true
				consented = true
			}
		})
		sel.AddReceive(revokedCh, func(c workflow.ReceiveChannel, _ bool) { c.Receive(ctx, nil); revoked = true })
		sel.AddReceive(cancelCh, func(c workflow.ReceiveChannel, _ bool) { c.Receive(ctx, nil); cancelled = true })
		sel.AddFuture(timer, func(workflow.Future) { expired = true })
		sel.Select(ctx)
	}
	cancelTimer()
	// Both signals may be ready at once; revoke outranks cancel.
	if rv, cn := pending(); rv || cn {
		revoked = revoked || rv
		cancelled = cancelled || cn
	}
	switch {
	case revoked:
		return terminate(true)
	case cancelled:
		return terminate(false)
	case expired:
		set("consent_expired")
		return res, nil
	}

	if rv, cn := pending(); rv || cn {
		return terminate(rv)
	}
	// Revalidate immediately before the provider write.
	err = workflow.ExecuteActivity(read, a.RevalidateScope, req).Get(ctx, nil)
	if r, done := checkPending(); done {
		return r, nil
	}
	if err != nil {
		return refused(err)
	}
	var mr activities.MutateResult
	err = workflow.ExecuteActivity(write, a.MutateBasket, req, q.Fingerprint).Get(ctx, &mr)
	if r, done := checkPending(); done {
		return r, nil
	}
	if err != nil {
		code := activities.ErrCode(err)
		switch {
		case code == bridge.CodeWriteUnverified:
			// The write may or may not have landed: never claim either.
			set(OutcomeUnknown)
			return res, nil
		case code == bridge.CodeStaleInstall || revokingCodes[code] || code == bridge.CodeBridgeUnavailable ||
			code == bridge.CodeInvalidRequest:
			return refused(err)
		}
		set(StateProviderUnavl)
		return res, nil
	}
	set("basket_mutated")
	var back activities.QuoteResult
	err = workflow.ExecuteActivity(read, a.ReadBasket, req).Get(ctx, &back)
	if r, done := checkPending(); done {
		return r, nil
	}
	if err != nil {
		if c := activities.ErrCode(err); c == bridge.CodeStaleInstall || revokingCodes[c] {
			return refused(err)
		}
		set(StateProviderUnavl)
		return res, nil
	}
	if back.Fingerprint != q.Fingerprint {
		set("basket_changed") // consent invalidated; owner is asked again, no handoff
		return res, nil
	}
	set("verified")

	err = workflow.ExecuteActivity(read, a.RevalidateScope, req).Get(ctx, nil)
	if r, done := checkPending(); done {
		return r, nil
	}
	if err != nil {
		return refused(err)
	}
	var marker string
	err = workflow.ExecuteActivity(write, a.IssueHandoff, req, q.Fingerprint).Get(ctx, &marker)
	if r, done := checkPending(); done {
		return r, nil
	}
	if err != nil {
		return refused(err)
	}
	set("handoff_issued")
	hctx, cancelH := workflow.WithCancel(ctx)
	htimer := workflow.NewTimer(hctx, snap.HandoffTTL)
	opened, hexpired, hrevoked, hcancelled := false, false, false, false
	for !opened && !hexpired && !hrevoked && !hcancelled {
		sel := workflow.NewSelector(ctx)
		sel.AddReceive(revokedCh, func(c workflow.ReceiveChannel, _ bool) { c.Receive(ctx, nil); hrevoked = true })
		sel.AddReceive(cancelCh, func(c workflow.ReceiveChannel, _ bool) { c.Receive(ctx, nil); hcancelled = true })
		sel.AddReceive(openedCh, func(c workflow.ReceiveChannel, _ bool) { c.Receive(ctx, nil); opened = true })
		sel.AddFuture(htimer, func(workflow.Future) { hexpired = true })
		sel.Select(ctx)
	}
	cancelH()
	// Multiple signals can be ready together; do not let a simultaneous open
	// or timeout outrank an install revoke or user cancellation.
	rv, cn := pending()
	if hrevoked || hcancelled || rv || cn {
		return terminate(hrevoked || rv)
	}
	if hexpired {
		_ = workflow.ExecuteActivity(read, a.ExpireHandoff, req).Get(ctx, nil)
		set("consent_expired")
		return res, nil
	}
	// Revalidate at handoff open: a handoff is honoured only under live scope.
	err = workflow.ExecuteActivity(read, a.RevalidateScope, req).Get(ctx, nil)
	if r, done := checkPending(); done {
		return r, nil
	}
	if err != nil {
		dctx := disconnected()
		_ = workflow.ExecuteActivity(dctx, a.ExpireHandoff, req).Get(dctx, nil)
		return refused(err)
	}
	set("handoff_opened")
	// No provider-confirmed evidence exists, so the outcome stays unknown.
	set(OutcomeUnknown)
	return res, nil
}
