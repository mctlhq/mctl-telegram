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
	purge := func() {
		dctx, _ := workflow.NewDisconnectedContext(ctx)
		dctx = workflow.WithActivityOptions(dctx, workflow.ActivityOptions{StartToCloseTimeout: time.Minute})
		_ = workflow.ExecuteActivity(dctx, a.Purge, snap).Get(dctx, nil)
	}

	set("prepared")
	if err := workflow.ExecuteActivity(read, a.RevalidateScope, snap).Get(ctx, nil); err != nil {
		return stale()
	}
	var q QuoteResult
	if err := workflow.ExecuteActivity(read, a.QuoteOrder, snap).Get(ctx, &q); err != nil {
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
	var replace, consented, expired, revoked, cancelled bool
	for !consented && !expired && !revoked && !cancelled {
		sel := workflow.NewSelector(ctx)
		sel.AddReceive(consentCh, func(c workflow.ReceiveChannel, _ bool) {
			var s ConsentSignal
			c.Receive(ctx, &s)
			switch {
			case seen[s.Nonce]:
				st.Duplicates++
			case s.Fingerprint != q.Fingerprint || s.InstallRevision != snap.InstallRevision:
				st.Rejected++
			case q.Collision && !s.ReplaceExisting:
				st.Rejected++ // collision needs an explicit replace decision
			default:
				seen[s.Nonce] = true
				replace, consented = s.ReplaceExisting, true
			}
		})
		sel.AddReceive(revokedCh, func(c workflow.ReceiveChannel, _ bool) { c.Receive(ctx, nil); revoked = true })
		sel.AddReceive(cancelCh, func(c workflow.ReceiveChannel, _ bool) { c.Receive(ctx, nil); cancelled = true })
		sel.AddFuture(timer, func(workflow.Future) { expired = true })
		sel.Select(ctx)
	}
	cancelTimer()
	_ = replace
	switch {
	case revoked:
		purge()
		set("cancelled")
		return res, nil
	case cancelled:
		purge()
		set("cancelled")
		return res, nil
	case expired:
		set("consent_expired")
		return res, nil
	}

	// Revalidate immediately before the provider write.
	if err := workflow.ExecuteActivity(read, a.RevalidateScope, snap).Get(ctx, nil); err != nil {
		return stale()
	}
	if err := workflow.ExecuteActivity(write, a.MutateBasket, snap, q.Fingerprint).Get(ctx, nil); err != nil {
		set("provider_unavailable")
		return res, nil
	}
	set("basket_mutated")
	var back QuoteResult
	if err := workflow.ExecuteActivity(read, a.ReadBasket, snap).Get(ctx, &back); err != nil {
		set("provider_unavailable")
		return res, nil
	}
	if back.Fingerprint != q.Fingerprint {
		set("basket_changed") // consent invalidated; owner is asked again, no handoff
		return res, nil
	}
	set("verified")

	if err := workflow.ExecuteActivity(read, a.RevalidateScope, snap).Get(ctx, nil); err != nil {
		return stale()
	}
	var tokenHash string
	if err := workflow.ExecuteActivity(read, a.IssueHandoff, snap, q.Fingerprint).Get(ctx, &tokenHash); err != nil {
		return res, err
	}
	set("handoff_issued")
	hctx, cancelH := workflow.WithCancel(ctx)
	htimer := workflow.NewTimer(hctx, snap.HandoffTTL)
	opened, hexpired := false, false
	for !opened && !hexpired {
		sel := workflow.NewSelector(ctx)
		sel.AddReceive(openedCh, func(c workflow.ReceiveChannel, _ bool) { c.Receive(ctx, nil); opened = true })
		sel.AddFuture(htimer, func(workflow.Future) { hexpired = true })
		sel.Select(ctx)
	}
	cancelH()
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
