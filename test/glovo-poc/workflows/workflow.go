package workflows

import (
	"errors"
	"time"

	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

const (
	SigConsent  = "consent"
	SigOpened   = "handoff_opened"
	SigRevoked  = "install_revoked"
	SigCancel   = "cancel"
	QueryStatus = "status"
)

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

const OutcomeUnknown = "OUTCOME_UNKNOWN"

func GlovoOrderWorkflow(ctx workflow.Context, snap Snapshot) (Result, error) {
	var res Result
	st := Status{}
	set := func(s string) { st.State = s; res.States = append(res.States, s); res.Status = s }
	if err := workflow.SetQueryHandler(ctx, QueryStatus, func() (Status, error) { return st, nil }); err != nil {
		return res, err
	}
	read := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{InitialInterval: time.Second, BackoffCoefficient: 2, MaximumAttempts: 5},
	})
	write := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: time.Minute,
		RetryPolicy:         &temporal.RetryPolicy{MaximumAttempts: 1},
	})
	var a *Activities
	consentCh := workflow.GetSignalChannel(ctx, SigConsent)
	openedCh := workflow.GetSignalChannel(ctx, SigOpened)
	revokedCh := workflow.GetSignalChannel(ctx, SigRevoked)
	cancelCh := workflow.GetSignalChannel(ctx, SigCancel)

	stale := func() (Result, error) {
		set("stale_install")
		return res, nil
	}
	isType := func(err error, t string) bool {
		var ae *temporal.ApplicationError
		return errors.As(err, &ae) && ae.Type() == t
	}
	purge := func(connection bool) {
		dctx, _ := workflow.NewDisconnectedContext(ctx)
		dctx = workflow.WithActivityOptions(dctx, workflow.ActivityOptions{StartToCloseTimeout: time.Minute})
		if connection {
			_ = workflow.ExecuteActivity(dctx, a.PurgeConnection, snap).Get(dctx, nil)
			return
		}
		_ = workflow.ExecuteActivity(dctx, a.PurgeOrder, snap).Get(dctx, nil)
	}
	// pending reports a revoke or cancel signal received after the consent
	// loop; revoke wins over cancel.
	pending := func() (revoked, cancelled bool) {
		revoked = revokedCh.ReceiveAsync(nil)
		cancelled = cancelCh.ReceiveAsync(nil)
		return
	}
	finish := func(revoked bool) (Result, error) {
		dctx, _ := workflow.NewDisconnectedContext(ctx)
		dctx = workflow.WithActivityOptions(dctx, workflow.ActivityOptions{StartToCloseTimeout: time.Minute})
		_ = workflow.ExecuteActivity(dctx, a.ExpireHandoff, snap).Get(dctx, nil)
		purge(revoked)
		set("cancelled")
		return res, nil
	}

	// Signals may arrive while an activity is awaiting its result. Check them
	// before interpreting any activity exit (including error and stale paths).
	// A revoke wins over cancel and purges the install connection; cancellation
	// purges only the individual order draft.
	checkPending := func() (Result, error, bool) {
		if rv, cn := pending(); rv || cn {
			r, err := finish(rv)
			return r, err, true
		}
		return Result{}, nil, false
	}

	set("prepared")
	err := workflow.ExecuteActivity(read, a.RevalidateScope, snap).Get(ctx, nil)
	if r, e, done := checkPending(); done {
		return r, e
	}
	if err != nil {
		return stale()
	}
	var q QuoteResult
	err = workflow.ExecuteActivity(read, a.QuoteOrder, snap).Get(ctx, &q)
	if r, e, done := checkPending(); done {
		return r, e
	}
	if err != nil {
		if isType(err, ErrTypeNeedsInput) {
			set("needs_input")
			return res, nil
		}
		if isType(err, "provider_unavailable") {
			set("provider_unavailable")
			return res, nil
		}
		set("provider_unavailable")
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
			case s.Fingerprint != q.Fingerprint || s.InstallRevision != snap.InstallRevision:
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
	switch {
	case revoked:
		purge(true)
		set("cancelled")
		return res, nil
	case cancelled:
		purge(false)
		set("cancelled")
		return res, nil
	case expired:
		set("consent_expired")
		return res, nil
	}

	if rv, cn := pending(); rv || cn {
		return finish(rv)
	}
	// Revalidate immediately before the provider write.
	err = workflow.ExecuteActivity(read, a.RevalidateScope, snap).Get(ctx, nil)
	if r, e, done := checkPending(); done {
		return r, e
	}
	if err != nil {
		return stale()
	}
	err = workflow.ExecuteActivity(write, a.MutateBasket, snap, q.Fingerprint).Get(ctx, nil)
	if r, e, done := checkPending(); done {
		return r, e
	}
	if err != nil {
		set("provider_unavailable")
		return res, nil
	}
	set("basket_mutated")
	var back QuoteResult
	err = workflow.ExecuteActivity(read, a.ReadBasket, snap).Get(ctx, &back)
	if r, e, done := checkPending(); done {
		return r, e
	}
	if err != nil {
		set("provider_unavailable")
		return res, nil
	}
	if back.Fingerprint != q.Fingerprint {
		set("basket_changed") // consent invalidated; owner is asked again, no handoff
		return res, nil
	}
	set("verified")

	err = workflow.ExecuteActivity(read, a.RevalidateScope, snap).Get(ctx, nil)
	if r, e, done := checkPending(); done {
		return r, e
	}
	if err != nil {
		return stale()
	}
	var tokenHash string
	err = workflow.ExecuteActivity(write, a.IssueHandoff, snap, q.Fingerprint).Get(ctx, &tokenHash)
	if r, e, done := checkPending(); done {
		return r, e
	}
	if err != nil {
		return res, err
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
		return finish(hrevoked || rv)
	}
	if hexpired {
		_ = workflow.ExecuteActivity(read, a.ExpireHandoff, snap).Get(ctx, nil)
		set("consent_expired")
		return res, nil
	}
	set("handoff_opened")
	// No provider-confirmed evidence exists, so the outcome stays unknown.
	set(OutcomeUnknown)
	return res, nil
}
