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

package connector

// lower.go is lowering (#1320, #1322 slice P2-S11; threat model T5 "Taint",
// T6, T7 "Standing permissions"; S2-I5, S2-I9, S2-D1, S2-D5): a standing
// permission the principal granted with /permissions may stand in for the
// approval card of one call.
//
// It happens in two places. The second checks again what it can read
// itself, and one thing it cannot:
//
//   - Cards.Emit decides. Only a write to one device that passed every
//     check its card would need (precheckDeviceWrite, deviceWriteTarget:
//     the value is one the pin allows, the device id is one a read made
//     now lists) is looked up, and the gate lowers it only in a clean
//     conversation. A disclosure, alice_control_room,
//     alice_trigger_scenario and alice_control_device are never looked up.
//   - WriteExecutor.DispatchLowered sends. It runs the steps of an
//     approved dispatch, the fresh tools/list among them. On its own it
//     checks the class, that the tool has a rule and that the pin makes it
//     lowerable, the tool's condition (the playback action), and it reads
//     the device and the values from the bytes it will send. Inside the
//     pre-dispatch transaction it reads the taint and the permission row
//     again, by id, under the connection row's lock. Only then does it
//     write the call's ledger row, already consumed, in that same
//     transaction.
//
// The executor reads the device list itself, once, after the
// pre-dispatch transaction and right before it sends (device_recheck.go):
// the device must be listed, be what Emit read (LoweredCall.Target, sealed
// into the call's ledger row), and be of a type the tool's rule allows.
// A device that is gone or changed is a refusal with nothing sent; a
// caller that hands the executor no target gets nothing sent either.
//
// Whatever cannot be read (the permissions, the taint, the devices) is a
// card or a refusal, never a call. When the executor finds the permission
// or the clean run gone, nothing was sent and Emit goes on to a card.
//
// The audit record of a lowered call names the permission in its approver
// field ("permission:<id>"); the approval id there is the ledger row the
// call consumed.
//
// It runs only with the write path built (cmd/server buildPAWrites).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

// Reasons a lowered dispatch is refused for. The first three mean "what
// lowered it no longer holds": nothing was sent or written, and the call
// gets a card instead.
const (
	// ReasonPermissionGone: the permission is revoked, expired, granted at
	// another revision, or does not cover the call.
	ReasonPermissionGone = "permission_gone"
	// ReasonPermissionUnreadable: the permission row could not be read.
	ReasonPermissionUnreadable = "permission_unreadable"
	// ReasonRunTainted: external content entered the conversation, or its
	// taint could not be read (S2-I5).
	ReasonRunTainted = "run_tainted"
	// ReasonNotLowerable: the call is not one any permission may lower.
	ReasonNotLowerable = "not_lowerable"
)

// permissionApproverPrefix starts the approver of a lowered call's audit
// record.
const permissionApproverPrefix = "permission:"

func permissionApprover(id string) string { return permissionApproverPrefix + id }

// loweredDoneOutput and loweredFailedOutput are what the worker's model
// reads as the result of a lowered call. They are server text: the tool's
// own output is external content and is not passed on, so a lowered call
// does not taint the conversation.
const (
	loweredDoneOutput   = "Done. The action was carried out under a standing permission the user granted."
	loweredFailedOutput = "The device or its service reported an error. The action was not carried out."
)

// PermissionLookup reads the standing permissions that may cover a call
// (*db.Store.LookupPAPermissions): those of the connection at exactly
// revision, not revoked, expiring after now. A failed read is an error,
// never an empty list.
type PermissionLookup interface {
	LookupPAPermissions(ctx context.Context, principal int64, connectionID string, revision int64, server, tool string, now time.Time) ([]permissions.Permission, error)
}

// LoweredDispatcher sends a call a standing permission covers
// (*WriteExecutor).
type LoweredDispatcher interface {
	DispatchLowered(ctx context.Context, call LoweredCall) (WriteOutcome, error)
}

var _ LoweredDispatcher = (*WriteExecutor)(nil)

// LoweredCall is one call the gate lowered.
type LoweredCall struct {
	// Binding is what an approval of the call would bind; its hashes are
	// those of the tool as it was just listed.
	Binding approval.Binding
	// Args are the canonical argument bytes, the ones Binding.ArgsSHA
	// names and the checks of the card path passed.
	Args []byte
	// PermissionID is the standing permission that covered the call.
	PermissionID string
	// Target is the device the caller's read reported for the call, in
	// the form a card of the tool seals. It is sealed into the call's
	// ledger row, and the executor compares its own read with it before
	// it sends (device_recheck.go). Required.
	Target []byte
	// device, ints and strs are the target and the arguments, read by the
	// executor from Args: it does not take the caller's word for what the
	// bytes say.
	device string
	ints   map[string]int64
	strs   map[string]string
}

func (c LoweredCall) covered() permissions.Call {
	return permissions.Call{
		Principal: c.Binding.Principal, ConnectionID: c.Binding.ConnectionID,
		AuthorityRevision: c.Binding.AuthorityRevision, Server: c.Binding.Server, Tool: c.Binding.Tool,
		Device: c.device, Ints: c.ints, Strings: c.strs,
	}
}

// loweredTarget reads the device id and the arguments of a device write
// from its canonical bytes, for the comparison with a permission. It
// checks no value against the pin: the caller's checks did. ok is false
// for a tool that is not a device write, bytes that are not an object, a
// missing device, an integer that is not in its one plain spelling and a
// string argument that is not a string.
func loweredTarget(tool string, canonical []byte) (device string, ints map[string]int64, strs map[string]string, ok bool) {
	spec, known := deviceWriteTools[tool]
	if !known {
		return "", nil, nil, false
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &args); err != nil || args == nil {
		return "", nil, nil, false
	}
	if device, ok = stringArg(args, spec.deviceArg); !ok || device == "" {
		return "", nil, nil, false
	}
	ints, strs = map[string]int64{}, map[string]string{}
	for _, v := range spec.values {
		raw, present := args[v.arg]
		if !present {
			continue
		}
		if v.bound == nil {
			text, isString := stringArg(args, v.arg)
			if !isString {
				return "", nil, nil, false
			}
			strs[v.arg] = text
			continue
		}
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil || strconv.FormatInt(n, 10) != string(raw) {
			return "", nil, nil, false
		}
		ints[v.arg] = n
	}
	return device, ints, strs, true
}

// unlowered reports whether out is a lowered dispatch that sent and wrote
// nothing because what lowered it no longer holds.
func unlowered(out WriteOutcome) bool {
	if out.Status != StatusRefused || out.DispatchID != "" {
		return false
	}
	return out.Reason == ReasonPermissionGone || out.Reason == ReasonPermissionUnreadable || out.Reason == ReasonRunTainted
}

// DispatchLowered dispatches call without an approval card, once. It must
// be called outside any transaction. The error is non-nil only for a call
// that is not complete; every other outcome, refusals included, is in the
// WriteOutcome and already recorded.
//
// It refuses, before anything is read, a call that is not a write, or of a
// tool no permission may lower: a disclosure never runs from here, whatever
// the caller decided (S2-D1). After the fresh tools/list it refuses a tool
// the pin does not make lowerable and a call that does not meet the tool's
// condition, and it reads the device list (see the file comment).
func (w *WriteExecutor) DispatchLowered(ctx context.Context, call LoweredCall) (WriteOutcome, error) {
	if w == nil || call.Binding.Validate() != nil || !permissions.ValidID(call.PermissionID) {
		return WriteOutcome{}, fmt.Errorf("%w: lowered dispatch needs a binding and a permission", ErrInvalidCall)
	}
	canonical, err := catalog.CanonicalArgs(call.Args)
	if err != nil || !bytes.Equal(canonical, call.Args) || digest(call.Args) != call.Binding.ArgsSHA {
		return WriteOutcome{}, fmt.Errorf("%w: lowered dispatch arguments are not the bound ones", ErrInvalidCall)
	}
	now := w.now()
	a, err := approval.New(call.Binding, now)
	switch {
	case err != nil:
	case len(call.Target) != 0:
		a, err = w.cfg.Sealer.SealWithDetail(a, call.Args, call.Target)
	default:
		// No target: refused below, before anything is read.
		a, err = w.cfg.Sealer.Seal(a, call.Args)
	}
	if err != nil {
		return WriteOutcome{}, fmt.Errorf("%w: lowered dispatch: %v", ErrInvalidCall, err)
	}
	reason := ""
	target := false
	call.device, call.ints, call.strs, target = loweredTarget(call.Binding.Tool, call.Args)
	// The target the caller read must be readable, name the device the
	// bytes name, and be of a type the tool's rule allows.
	sealed, terr := sealedTarget(call.Binding.Tool, call.Target)
	if call.Binding.Class != catalog.ClassWrite || !permissions.HasRule(call.Binding.Tool) || !target ||
		terr != nil || sealed.ID != call.device || !permissions.TypeAllowed(call.Binding.Tool, sealed.Type) {
		reason = ReasonNotLowerable
	} else {
		reason = w.precheckLowered(ctx, a, now)
	}
	return w.run(ctx, a, reason, &call), nil
}

// precheckLowered is step 1 of a lowered dispatch: the switches, read now
// in a short transaction that changes nothing.
func (w *WriteExecutor) precheckLowered(ctx context.Context, a approval.Approval, now time.Time) string {
	tx, err := w.cfg.Store.BeginPAWrite(ctx, a.Principal, false)
	if err != nil {
		return ReasonStateUnreadable
	}
	defer func() { _ = tx.Rollback() }()
	return w.admit(ctx, tx, a, now)
}

// lower is the part of the pre-dispatch transaction only a lowered call
// has. It runs after the connection row was locked and found active at the
// call's revision, and after the switches were read. In order:
//
//  1. the conversation must have been read as clean in this transaction
//     (S2-I5): a read that happened since the decision, or a taint that
//     cannot be read, ends the lowering;
//  2. the permission row is read by id and must still cover the call at the
//     connection's revision: not revoked, not expired, same tool and
//     connection, the device listed, the value within the ceiling (S2-A9);
//  3. the call's ledger row is created and approved here, so that it exists
//     only together with the dispatch record the caller inserts next.
//
// It returns the refusal reason or "". a gets the row's approver.
func (w *WriteExecutor) lower(ctx context.Context, tx *sql.Tx, a *approval.Approval, conn connection.Connection, low LoweredCall, taint Taint, now time.Time) string {
	if taint != TaintClean {
		return ReasonRunTainted
	}
	p, err := w.cfg.Store.PAPermissionIn(ctx, tx, a.Principal, low.PermissionID)
	switch {
	case errors.Is(err, permissions.ErrNotFound):
		return ReasonPermissionGone
	case err != nil:
		return ReasonPermissionUnreadable
	}
	// The call's revision is the locked row's: the caller checked that
	// before it called.
	if p.ID != low.PermissionID || conn.AuthorityRevision != a.AuthorityRevision || !p.Covers(low.covered(), now) {
		return ReasonPermissionGone
	}
	if err := w.cfg.Store.CreatePAApproval(ctx, tx, *a); err != nil {
		if errors.Is(err, approval.ErrBinding) {
			return ReasonConnectionUnbound
		}
		return ReasonApprovalUnreadable
	}
	approved, err := w.cfg.Store.ApprovePAApproval(ctx, tx, a.Principal, a.ID, now)
	if err != nil {
		return approvalRefusal(err)
	}
	a.Approver = approved.Approver
	return ""
}

// lowerable reports whether a standing permission may be looked up for a
// call of tool at all: a write the pin makes lowerable, with a rule of its
// own, that is not on the threat model's never list.
func lowerable(tool string, pinned catalog.PinnedTool) bool {
	return pinned.Class == catalog.ClassWrite &&
		(pinned.Lowerable == catalog.LowerableYes || pinned.Lowerable == catalog.LowerableConditional) &&
		!catalog.IsNeverLowerable(tool) && permissions.HasRule(tool)
}

// errConditionUnchecked: this file has no way to check a conditional
// tool's condition.
var errConditionUnchecked = errors.New("pa connector: lowering condition cannot be checked")

// loweringCondition is the gate's ConditionMet for a conditional tool: the
// call's playback action is one the pin lets a permission cover. A
// condition on a device type has no reader here and is an error, which the
// gate decides as unmet.
func loweringCondition(pinned catalog.PinnedTool, canonical []byte) (bool, error) {
	if pinned.Lowerable != catalog.LowerableConditional {
		return true, nil
	}
	c := pinned.Constraints
	if c == nil || c.PlaybackActions == nil || len(c.AllowedTypePrefixes) != 0 {
		return false, errConditionUnchecked
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &args); err != nil {
		return false, errConditionUnchecked
	}
	action, ok := stringArg(args, c.PlaybackActions.Arg)
	if !ok {
		return false, nil
	}
	return slices.Contains(c.PlaybackActions.Values, action), nil
}

// coveringPermission returns the oldest standing permission that covers
// call, or nil. An error means the permissions could not be read.
func (c *Cards) coveringPermission(ctx context.Context, req CardRequest, call permissions.Call, now time.Time) (*permissions.Permission, error) {
	if c.cfg.Permissions == nil || c.cfg.Lowered == nil {
		return nil, nil
	}
	list, err := c.cfg.Permissions.LookupPAPermissions(ctx, call.Principal, req.ConnectionID, req.AuthorityRevision, req.Server, req.Tool, now)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Covers(call, now) {
			return &list[i], nil
		}
	}
	return nil, nil
}
