// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gate decides how a proposed PA write or disclosure may proceed
// (threat model I5, I6, T5, T6, T7, T11). It is pure: callers read the
// switches, the principal's state, the taint and the standing permissions,
// and hand the results here, read errors included, so that "could not
// observe" is decided in one place and always fails closed (I9).
//
// No runtime code calls Decide yet (P2-S1). Reads never reach it: the
// catalog grants auto reads (catalog.Surface.Authorize). The principal half
// of Input comes from StorePrincipalStatus, the admin disable of #1318; the
// run loop checks the same disable at every step on its own.
package gate

import (
	"context"
	"errors"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

// Outcome is how a call may proceed.
type Outcome string

const (
	// OutcomeNever: the call does not run, and no card is offered.
	OutcomeNever Outcome = "never"
	// OutcomeCard: the call runs only after a per-call approval card.
	OutcomeCard Outcome = "card"
	// OutcomeLowered: a standing permission covers the exact call, so it
	// runs without a card.
	OutcomeLowered Outcome = "lowered"
)

// Reason names the rule that decided, one per branch of Decide.
type Reason string

const (
	ReasonWritesOff         Reason = "writes_off"
	ReasonPrincipalDisabled Reason = "principal_disabled"
	ReasonNotAWrite         Reason = "not_a_write"
	ReasonDisclosure        Reason = "disclosure"
	ReasonNeverLowerable    Reason = "never_lowerable"
	ReasonTainted           Reason = "tainted"
	ReasonConditionUnmet    Reason = "condition_unmet"
	ReasonPermission        Reason = "standing_permission"
	ReasonNoPermission      Reason = "no_permission"
)

// Decision is Decide's verdict.
type Decision struct {
	Outcome Outcome
	Reason  Reason
}

// Input is everything Decide looks at. Each observation carries the error
// of reading it; a non-nil error is decided as the unsafe value (writes
// off, principal disabled, tainted, no permission), whatever the bool says.
type Input struct {
	// Writes is Flags.Writes (PA_WRITES_ENABLED), WritesErr is
	// Flags.WritesErr, the error of reading that switch.
	Writes    bool
	WritesErr error
	// PrincipalDisabled and PrincipalErr are PrincipalStatus's answer for
	// the job's principal.
	PrincipalDisabled bool
	PrincipalErr      error
	// Tool, Class and Lowerable come from the pin entry the catalog
	// matched for the call, never from the model.
	Tool      string
	Class     catalog.Class
	Lowerable catalog.Lowerable
	// Tainted: external content entered this conversation (T5). Assistant
	// output in a clean conversation does not taint; a conversation row
	// from before taint was recorded is tainted. TaintErr is the error of
	// reading it.
	Tainted  bool
	TaintErr error
	// PermissionMatch: a standing permission of this principal, connection
	// and revision covers this exact call within its limits (T6, T7): the
	// caller has checked the device id, the device type read fresh, the
	// value ceiling and the expiry. PermissionErr is the error of reading
	// the permissions.
	PermissionMatch bool
	PermissionErr   error
	// ConditionMet: for a "conditional" tool, the call meets the pin's own
	// condition (catalog.Constraints): every playback action is in
	// playback_actions (alice_media_control), or the device type, read
	// fresh at dispatch, passes catalog.DeviceTypeAllowed for
	// allowed_type_prefixes (alice_control_device). ConditionErr is the
	// error of checking it (the device type unreadable, for one). Decide
	// ignores both for a tool that is not conditional.
	ConditionMet bool
	ConditionErr error
}

// Decide applies the gate in a fixed order; the first rule that matches
// decides:
//
//  1. writes off, or the flags unreadable -> never;
//  2. the principal disabled, or their state unreadable -> never;
//  3. not a write or disclosure -> never (a read or an unknown class has
//     no business here);
//  4. a disclosure -> card (never lowerable, whatever the taint: S2-I9);
//  5. never lowerable, by the pin or by the threat model's list -> card;
//  6. tainted, or the taint unreadable -> card (S2-I5, S2-I10);
//  7. a conditional tool whose condition is unmet, or could not be
//     checked -> card (T6);
//  8. a standing permission covers the call -> lowered;
//  9. otherwise -> card.
func Decide(in Input) Decision {
	switch {
	case in.WritesErr != nil || !in.Writes:
		return Decision{OutcomeNever, ReasonWritesOff}
	case in.PrincipalErr != nil || in.PrincipalDisabled:
		return Decision{OutcomeNever, ReasonPrincipalDisabled}
	case in.Class != catalog.ClassWrite && in.Class != catalog.ClassDisclosure:
		return Decision{OutcomeNever, ReasonNotAWrite}
	case in.Class == catalog.ClassDisclosure:
		return Decision{OutcomeCard, ReasonDisclosure}
	case (in.Lowerable != catalog.LowerableYes && in.Lowerable != catalog.LowerableConditional) ||
		catalog.IsNeverLowerable(in.Tool):
		return Decision{OutcomeCard, ReasonNeverLowerable}
	case in.TaintErr != nil || in.Tainted:
		return Decision{OutcomeCard, ReasonTainted}
	case in.Lowerable == catalog.LowerableConditional && (in.ConditionErr != nil || !in.ConditionMet):
		return Decision{OutcomeCard, ReasonConditionUnmet}
	case in.PermissionErr == nil && in.PermissionMatch:
		return Decision{OutcomeLowered, ReasonPermission}
	default:
		return Decision{OutcomeCard, ReasonNoPermission}
	}
}

// PrincipalStatus reports whether an admin disabled one principal's PA
// (threat model T11). An error means the state could not be read, and the
// principal is treated as disabled.
type PrincipalStatus interface {
	PrincipalDisabled(ctx context.Context, principal int64) (bool, error)
}

// PrincipalDisableReader reads the admin disable outside a transaction
// (*db.Store.PAPrincipalDisabledState). It returns true with any error.
type PrincipalDisableReader interface {
	PAPrincipalDisabledState(ctx context.Context, principal int64) (bool, error)
}

// ErrPrincipalStatusUnavailable: no store to read the disable from.
var ErrPrincipalStatusUnavailable = errors.New("pa gate: principal disable state is unavailable")

// StorePrincipalStatus is the PrincipalStatus backed by the admin disable
// (pa_principal_disables, #1318). A read error, or no store, is (true,
// err): a principal whose state cannot be read is treated as disabled.
type StorePrincipalStatus struct {
	Store PrincipalDisableReader
}

// PrincipalDisabled implements PrincipalStatus.
func (s StorePrincipalStatus) PrincipalDisabled(ctx context.Context, principal int64) (bool, error) {
	if s.Store == nil {
		return true, ErrPrincipalStatusUnavailable
	}
	disabled, err := s.Store.PAPrincipalDisabledState(ctx, principal)
	if err != nil {
		return true, err
	}
	return disabled, nil
}

var _ PrincipalStatus = StorePrincipalStatus{}
