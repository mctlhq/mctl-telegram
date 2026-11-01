package assistantinstall

import (
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// ManagedRuntime is the server's gate on the managed runtime (ADR 0008):
// MANAGED_RUNTIME_ENABLED and MANAGED_RUNTIME_MAX_ACCOUNTS.
type ManagedRuntime struct {
	Enabled     bool
	MaxAccounts int
}

// RuntimeChange is the profile columns a write must set for a runtime
// decision. The zero value changes nothing.
type RuntimeChange struct {
	Runtime        *string
	ConsentVersion *string
	ConsentAt      *time.Time
	// Quota is set for an own -> managed write: the store refuses it while
	// that many other accounts are already managed.
	Quota *int
	// Changed: the runtime moves. Consented: a consent is recorded.
	Changed, Consented bool
	From, To           string
}

// Apply copies the change onto u.
func (c RuntimeChange) Apply(u *db.AgentProfileUpdate) {
	u.Runtime, u.ManagedConsentVersion, u.ManagedConsentAt, u.ManagedQuota = c.Runtime, c.ConsentVersion, c.ConsentAt, c.Quota
}

// DecideRuntime returns the profile columns a write must set, or a refusal.
// requested "" means "unchanged" and yields the empty change. The checks run
// in an order that never asks an owner to consent to a runtime the server
// cannot offer: flag, then consent, then (in the store) quota.
func (m ManagedRuntime) DecideRuntime(currentRuntime, requested, consent string, now time.Time) (RuntimeChange, *Error) {
	if requested == "" {
		return RuntimeChange{}, nil
	}
	if currentRuntime == "" {
		currentRuntime = db.RuntimeOwn
	}
	to := requested
	ch := RuntimeChange{Runtime: &to, From: currentRuntime, To: requested}
	consented := consent == db.ManagedConsentCurrent
	switch {
	case requested == db.RuntimeManaged && currentRuntime != db.RuntimeManaged:
		if !m.Enabled {
			return RuntimeChange{}, fail(KindManagedDisabled, "the managed runtime is not enabled")
		}
		if !consented {
			return RuntimeChange{}, fail(KindManagedConsentRequired, "switching to the managed runtime needs your consent")
		}
		quota := m.MaxAccounts
		v := db.ManagedConsentCurrent
		at := now.UTC()
		ch.ConsentVersion, ch.ConsentAt, ch.Quota = &v, &at, &quota
		ch.Changed, ch.Consented = true, true
	case requested == db.RuntimeManaged:
		// Already managed: only a current consent refreshes the record.
		ch.Runtime = nil
		if consented {
			v := db.ManagedConsentCurrent
			at := now.UTC()
			ch.ConsentVersion, ch.ConsentAt = &v, &at
			ch.Consented = true
		}
	case currentRuntime == db.RuntimeManaged:
		// managed -> own: no checks, nothing else cleared.
		ch.Changed = true
	default:
		ch.Runtime = nil
	}
	return ch, nil
}
