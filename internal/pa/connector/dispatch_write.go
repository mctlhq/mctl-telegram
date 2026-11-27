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

// dispatch_write.go is the server-side executor of an approved PA write or
// disclosure (#1320 slice P2-S3; threat model T2 "Execution-time check and
// dispatch", T7, T11, T12, I4, I9, I10). The worker has no part in it: the
// only input is the principal and the id of an approval that principal
// approved, and everything that is sent comes from the approval row.
//
// DispatchApproved, in order:
//
//  1. reads the approval (it must be approved, by this principal) and
//     re-reads what can turn a write off: PA_EXTERNAL_TOOLS_ENABLED, the
//     server's flag, PA_WRITES_ENABLED, the preview allowlist, the admin
//     disable, consent and the conversation. A value that cannot be read
//     refuses (I9); nothing is taken from the time the card was made;
//  2. registers the call under the connection (cancelled by /disconnect),
//     opens the access token server-side and asks FreshSurface for the
//     tool's current definition; a nil FreshSurface, a failed listing or a
//     hash that differs from the approval's refuses;
//  3. appends the pre-dispatch audit entry; a failed append refuses;
//  4. runs the pre-dispatch transaction (I4): budget lock, principal lock,
//     the connection row locked and re-checked at the bound revision, the
//     switches of step 1 read again, the receipt consumed (which inserts
//     the dispatching record), the arguments unsealed and their hash
//     recomputed against args_sha. It commits before anything is sent;
//  5. sends tools/call once, with the stored canonical argument bytes
//     verbatim (WriteEndpoint.CallToolExact). No transaction is open, and
//     nothing is retried: not on a timeout, not on a 401;
//  6. re-reads the connection (Call.Finish) and the principal's switches;
//     a change, or a failed read, discards the result as fenced;
//  7. records the dispatch's final status and the principal's notice in
//     one transaction, then appends the audit result entry.
//
// A refusal before step 4 commits burns the approval (refused) and tells
// the principal nothing was sent. After the commit the dispatch record is
// the truth: whoever moves it out of dispatching owes the notice and the
// audit result entry. That is step 7 here, or StaleWriteSweeper for a
// record whose executor died or could not write step 7; never both.
//
// DispatchLowered (lower.go, P2-S11) sends a call a standing permission
// covers through the same steps. It has no approval row to read in step 1;
// the row is created, approved and consumed inside the transaction of step
// 4, after the permission and the taint were read again there.
//
// Nothing in a deployed service calls either: the card callbacks and the
// card emitter are built in tests only, and PA_WRITES_ENABLED is off
// everywhere.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

// Refusal reasons of the write executor, next to the Reason* set in
// execute.go. A closed set: the record never carries error text.
const (
	// PA_WRITES_ENABLED is off or unreadable (T11, S2-F3).
	ReasonWritesOff = "writes_off"
	// The approval is not one this principal can dispatch.
	ReasonApprovalNotFound    = "approval_not_found"
	ReasonApprovalNotApproved = "approval_not_approved"
	ReasonApprovalConsumed    = "approval_consumed"
	ReasonApprovalExpired     = "approval_expired"
	ReasonApprovalEnded       = "approval_ended"
	ReasonApprovalUnreadable  = "approval_unreadable"
	// The stored arguments are not the ones the approval's args_sha names.
	ReasonArgsChanged = "args_changed"
	// Consent was withdrawn or is not the current one; the conversation
	// the approval was made in is closed.
	ReasonConsentGone        = "consent_gone"
	ReasonConversationClosed = "conversation_closed"
	// The principal has not consented to actions, withdrew that consent,
	// or consented to another version or text of it (#1320 slice P2-S14c).
	ReasonActionConsentRequired = "action_consent_required"
	// The connection does not hold the write scope the tool needs: it was
	// made for reading, the service narrowed its grant, or its granted
	// scope cannot be read.
	ReasonWriteScopeMissing = "write_scope_missing"
	// A switch of the principal (disable, consent, conversation) could not
	// be read.
	ReasonStateUnreadable = "state_unreadable"
	// The dispatch ended before the request was made: its caller went
	// away, or the token and tools/list used up the call's time.
	ReasonDispatchCancelled = "dispatch_cancelled"
	ReasonDispatchTimeout   = "dispatch_timeout"
	// The stale-dispatch sweep resolved a record whose lease ran out.
	ReasonLeaseExpired = "dispatch_lease_expired"
	// The stale-dispatch sweep ended a record whose request was never
	// made: the executor committed the dispatch, did not send, and could
	// not settle the record itself (S2-C12). Nothing was sent.
	ReasonNeverSent = "dispatch_never_sent"
)

// WriteStore is the part of *db.Store the write executor uses.
type WriteStore interface {
	approval.Store
	// BeginPAWrite opens a transaction holding the principal lock, and
	// with budget the budget lock before it.
	BeginPAWrite(ctx context.Context, principal int64, budget bool) (*sql.Tx, error)
	// LockPAConnection reads the connection row in tx and keeps it still.
	LockPAConnection(ctx context.Context, tx *sql.Tx, principal int64, id string) (connection.Connection, error)
	PAPrincipalDisabled(ctx context.Context, tx *sql.Tx, principal int64) (bool, error)
	GetPAConsent(ctx context.Context, tx *sql.Tx, principal int64) (convo.ConsentRecord, error)
	GetPAActionConsent(ctx context.Context, tx *sql.Tx, principal int64) (convo.ConsentRecord, error)
	PAConversationOpen(ctx context.Context, tx *sql.Tx, principal int64, conversationID string, now time.Time) error
	// PAConversationTaintIn returns true with any error (S2-I10).
	PAConversationTaintIn(ctx context.Context, tx *sql.Tx, principal int64, conversationID string) (bool, error)
	EnqueuePAOutbox(ctx context.Context, tx *sql.Tx, item jobs.OutboxItem, now time.Time) error
	// PAPermissionIn reads one standing permission in tx, whatever its
	// state, and keeps the row still. Only DispatchLowered uses it.
	PAPermissionIn(ctx context.Context, tx *sql.Tx, principal int64, id string) (permissions.Permission, error)
}

// WriteConnections is the connection manager's half (*connection.Manager).
type WriteConnections interface {
	BeginCall(ctx context.Context, principal int64, id string, boundRevision int64) (*connection.Call, error)
	AccessToken(ctx context.Context, principal int64, id string, boundRevision int64) (connection.Secret, connection.Connection, error)
}

// WriteEndpoint is an MCP surface that can send approved arguments byte
// for byte. *Endpoint is the only production implementation.
type WriteEndpoint interface {
	Server() string
	CallToolExact(ctx context.Context, token connection.Secret, tool string, canonicalArgs []byte) ([]byte, error)
}

var _ WriteEndpoint = (*Endpoint)(nil)

// FreshRequest names the tool whose current definition a dispatch needs.
type FreshRequest struct {
	Principal         int64
	ConnectionID      string
	AuthorityRevision int64
	Server            string
	Tool              string
	// Token is the connection's access token, for the tools/list.
	Token connection.Secret
}

// FreshTool is one tool's definition as the server lists it now, already
// checked against the catalog pin by the FreshSurface that returned it.
type FreshTool struct {
	SchemaSHA      string
	DescriptionSHA string
	AnnotationSHA  string
	Tier           catalog.Tier
	Class          catalog.Class
	// Lowerable and Constraints are what the pin says of the tool, not
	// the listing: whether a standing permission may lower it and on what
	// condition. Only a lowered dispatch reads them; the zero value is
	// "not lowerable".
	Lowerable   catalog.Lowerable
	Constraints *catalog.Constraints
	// InputSchema is the pin's input schema of the tool, the one whose
	// hash is SchemaSHA. A lowered dispatch reads the values a string
	// argument may take from it. A string, so that FreshTool stays comparable.
	InputSchema string
}

// FreshSurface fetches a tool's definition with a fresh tools/list at
// dispatch (threat model T7 "Approval-time drift"). It must fail, with a
// catalog error where one applies, on a listing it could not read, on a
// tool the pin does not have and on a definition that differs from the
// pin; it never returns a cached or partial answer (I9). The executor
// compares what it returns with the approval's hashes. PinFresh (fresh.go,
// slice P2-S4) implements it; a nil FreshSurface refuses every write.
type FreshSurface interface {
	FreshTool(ctx context.Context, req FreshRequest) (FreshTool, error)
}

// WriteConfig wires a WriteExecutor. Every field but Fresh, Metrics, Now
// and CallTimeout is required; without Fresh every dispatch is refused.
type WriteConfig struct {
	Store       WriteStore
	Connections WriteConnections
	Endpoints   map[string]WriteEndpoint
	// Executor supplies the audit sink, its alert hook and the clock.
	Executor *Executor
	Sealer   *approval.Sealer
	// Flags is called at every check. An error refuses.
	Flags func() (Flags, error)
	// Allowed is the preview allowlist (PA_ALLOWED_PRINCIPALS).
	Allowed func(principal int64) bool
	Fresh   FreshSurface
	// Scopes names the scope each write tool needs; nil is the compiled
	// table (connection.DefaultWriteScopes). A call is sent only on a
	// connection whose granted scope holds its tool's scope.
	Scopes *connection.WriteScopes
	// Devices reads a server's devices right before a call to one device
	// is sent, by server name (device_recheck.go). A call to a device on
	// a server without a reader is refused (ReasonNoWritePath).
	Devices map[string]DeviceLister
	// Scenarios reads a server's scenario right before a call that runs
	// one is sent, by server name (scenario.go). A scenario call on a
	// server without a reader is refused (ReasonNoWritePath).
	Scenarios map[string]ScenarioSteps
	Metrics   Metrics
	// CallTimeout bounds token, tools/list, the pre-dispatch transaction
	// and tools/call of one dispatch; 0 is DefaultCallTimeout.
	CallTimeout time.Duration
}

// WriteExecutor dispatches approved calls.
type WriteExecutor struct{ cfg WriteConfig }

// NewWriteExecutor refuses an incomplete configuration.
func NewWriteExecutor(cfg WriteConfig) (*WriteExecutor, error) {
	if cfg.Store == nil || cfg.Connections == nil || cfg.Executor == nil || cfg.Executor.Sink == nil ||
		cfg.Sealer == nil || cfg.Flags == nil || cfg.Allowed == nil {
		return nil, errors.New("pa connector: write executor needs a store, connections, an executor, a sealer, flags and an allowlist")
	}
	if cfg.CallTimeout < 0 || cfg.CallTimeout+writeLeaseMargin > approval.MaxDispatchLease {
		return nil, errors.New("pa connector: write call timeout does not fit a dispatch lease")
	}
	for name, ep := range cfg.Endpoints {
		if ep == nil || ep.Server() != name {
			return nil, fmt.Errorf("pa connector: write endpoint %q does not serve that name", name)
		}
		if cfg.Metrics != nil {
			cfg.Metrics.PreparePAWriteListingRefusals(name, WriteListingRefusalReasons)
		}
	}
	return &WriteExecutor{cfg: cfg}, nil
}

// WriteOutcome is what became of one DispatchApproved.
type WriteOutcome struct {
	// Status is refused (nothing was sent, or the server refused the
	// token), ok, tool_error, fenced or outcome_unknown.
	Status Status
	// Reason is the closed label of a refusal, a fence or an unknown
	// outcome; empty for ok and tool_error.
	Reason string
	// DispatchID is the dispatch record, empty when the receipt was not
	// consumed.
	DispatchID string
	// Output is the tool result, set for ok and tool_error only. It is
	// external content. A fenced or unknown result is never returned.
	Output []byte
}

const (
	// writeLeaseMargin is how long past the call deadline a dispatch
	// record stays dispatching before the sweep may resolve it: it covers
	// the post-dispatch checks and the final write.
	writeLeaseMargin = 2 * time.Minute
	// writeSettleTimeout bounds the writes that record something already
	// decided, on a context detached from the caller's cancellation.
	writeSettleTimeout = 10 * time.Second
)

func (w *WriteExecutor) now() time.Time { return w.cfg.Executor.now() }

func (w *WriteExecutor) callTimeout() time.Duration {
	if w.cfg.CallTimeout > 0 {
		return w.cfg.CallTimeout
	}
	return DefaultCallTimeout
}

// WriteListingRefusalReasons is the closed reason label set of
// mctl_pa_write_listing_refusals_total: why the fresh tools/list the
// executor reads for one dispatch (S2-A6) let nothing be sent. The server
// could not be listed or its listing was unusable (server_unavailable,
// listing_stale), the tool is not in the listing or not a write the pin
// allows (not_pinned, no_write_path, unknown_server), it differs from the
// pin or from what the card bound (tool_changed), or the error is one the
// executor does not know (internal). The read path counts its own failed
// listings in mctl_pa_pin_listing_failures_total; a write refused for the
// same cause is also in mctl_pa_dispatch_total, under a reason it shares
// with refusals that asked no listing.
var WriteListingRefusalReasons = []string{
	ReasonServerUnavailable, ReasonListingStale, ReasonNotPinned, ReasonNoWritePath,
	ReasonUnknownServer, ReasonToolChanged, ReasonInternal,
}

// countListingRefusal counts a write that the fresh listing refused.
func (w *WriteExecutor) countListingRefusal(server, reason string) {
	if w.cfg.Metrics != nil {
		w.cfg.Metrics.CountPAWriteListingRefusal(server, reason)
	}
}

func (w *WriteExecutor) count(server string, status Status, reason string) {
	if w.cfg.Metrics != nil {
		w.cfg.Metrics.CountPADispatch(server, string(status), reason)
	}
}

// scopes is the table of write tools and their scopes.
func (w *WriteExecutor) scopes() connection.WriteScopes {
	return connection.ScopesOrDefault(w.cfg.Scopes)
}

// flagsRefusal re-reads the switches and returns why server's writes are
// off now, or "". Only values read without an error turn a write on.
func (w *WriteExecutor) flagsRefusal(server string) string {
	f, err := w.cfg.Flags()
	if err != nil || !f.ExternalTools || !f.Servers[server] || f.ServerErrs[server] != nil {
		return ReasonFlagOff
	}
	if f.WritesErr != nil || !f.Writes {
		return ReasonWritesOff
	}
	return ""
}

// admit is every switch that can turn a's dispatch off, read now inside
// tx: the flags, the allowlist, the admin disable, consent and the
// conversation. It returns the refusal reason or "". The pre-check and the
// pre-dispatch transaction both run it; neither uses the other's answer.
func (w *WriteExecutor) admit(ctx context.Context, tx *sql.Tx, a approval.Approval, now time.Time) string {
	if r := w.flagsRefusal(a.Server); r != "" {
		return r
	}
	return w.principalRefusal(ctx, tx, a, now)
}

// principalRefusal is admit without the flags: the checks the
// post-dispatch fence repeats.
func (w *WriteExecutor) principalRefusal(ctx context.Context, tx *sql.Tx, a approval.Approval, now time.Time) string {
	if !w.cfg.Allowed(a.Principal) {
		return ReasonPrincipalNotAllowed
	}
	disabled, err := w.cfg.Store.PAPrincipalDisabled(ctx, tx, a.Principal)
	switch {
	case err != nil:
		return ReasonStateUnreadable
	case disabled:
		return ReasonPrincipalDisabled
	}
	rec, err := w.cfg.Store.GetPAConsent(ctx, tx, a.Principal)
	switch {
	case errors.Is(err, convo.ErrNotFound):
		return ReasonConsentGone
	case err != nil:
		return ReasonStateUnreadable
	case !convo.Satisfied(rec):
		return ReasonConsentGone
	}
	// The consent to actions, read in the same transaction. It is asked
	// of every write, approved on a card or lowered by a permission, and
	// again by the post-dispatch fence.
	switch err := pa.RequireActionConsent(ctx, tx, w.cfg.Store, a.Principal); {
	case errors.Is(err, pa.ErrActionConsentRequired):
		return ReasonActionConsentRequired
	case err != nil:
		return ReasonStateUnreadable
	}
	err = w.cfg.Store.PAConversationOpen(ctx, tx, a.Principal, a.ConversationID, now)
	switch {
	case errors.Is(err, jobs.ErrConversationGone):
		return ReasonConversationClosed
	case err != nil:
		return ReasonStateUnreadable
	}
	return ""
}

// approvalRefusal maps a ledger error to its reason. An error it does not
// know is unreadable, never a pass.
func approvalRefusal(err error) string {
	switch {
	case errors.Is(err, approval.ErrNotFound):
		return ReasonApprovalNotFound
	case errors.Is(err, approval.ErrNotApproved):
		return ReasonApprovalNotApproved
	case errors.Is(err, approval.ErrConsumed):
		return ReasonApprovalConsumed
	case errors.Is(err, approval.ErrExpired):
		return ReasonApprovalExpired
	case errors.Is(err, approval.ErrCancelled), errors.Is(err, approval.ErrRefused):
		return ReasonApprovalEnded
	case errors.Is(err, approval.ErrAuthorityChanged):
		return ReasonRevisionMismatch
	case errors.Is(err, approval.ErrConversationClosed):
		return ReasonConversationClosed
	}
	return ReasonApprovalUnreadable
}

func statusRefusal(s approval.Status) string {
	switch s {
	case approval.StatusPending:
		return ReasonApprovalNotApproved
	case approval.StatusDispatching, approval.StatusDone:
		return ReasonApprovalConsumed
	case approval.StatusExpired:
		return ReasonApprovalExpired
	case approval.StatusCancelled, approval.StatusRefused:
		return ReasonApprovalEnded
	}
	return ReasonApprovalUnreadable
}

// DispatchApproved dispatches the call of principal's approval approvalID,
// once. It must be called outside any transaction. The error is non-nil
// only for a call that names no principal or approval; every other outcome,
// refusals included, is in the WriteOutcome and already recorded.
func (w *WriteExecutor) DispatchApproved(ctx context.Context, principal int64, approvalID string) (WriteOutcome, error) {
	if w == nil || principal <= 0 || approvalID == "" {
		return WriteOutcome{}, fmt.Errorf("%w: dispatch needs a principal and an approval", ErrInvalidCall)
	}
	now := w.now()

	// Step 1: the approval and the switches.
	a, reason, found := w.precheck(ctx, principal, approvalID, now)
	if !found {
		// No row of this principal to describe the call with: the refusal
		// is recorded like a dispatcher refusal, with markers.
		w.cfg.Executor.RecordRefusal(ctx, Refusal{Principal: principal, Reason: reason}, func(string) bool { return false })
		w.count(invalidServer, StatusRefused, reason)
		return WriteOutcome{Status: StatusRefused, Reason: reason}, nil
	}
	return w.run(ctx, a, reason, nil), nil
}

// run is steps 2 to 7 of a dispatch, for an approval a card got approved
// (low is nil) and for a call a standing permission covers. reason is what
// step 1 refused it for, or "".
func (w *WriteExecutor) run(ctx context.Context, a approval.Approval, reason string, low *LoweredCall) WriteOutcome {
	principal := a.Principal
	dispatchID := approval.NewID()
	base := Entry{
		CallID:            dispatchID,
		Principal:         principal,
		ConnectionID:      a.ConnectionID,
		AuthorityRevision: a.AuthorityRevision,
		Server:            a.Server,
		Tool:              recordableName(a.Tool),
		ArgsSHA256:        a.ArgsSHA,
		Class:             a.Class,
		// Until the taint is read the record says external (S2-I10).
		Taint:      TaintExternal,
		ApprovalID: a.ID,
	}
	switch {
	case low != nil:
		// No principal approved this call: the record names the standing
		// permission that stands in for the card.
		base.Approver = permissionApprover(low.PermissionID)
	case a.Approver > 0:
		base.Approver = strconv.FormatInt(a.Approver, 10)
	}
	// refuse ends a dispatch that sent nothing. burn is false only for an
	// approval that is not this dispatch's to end (not approved, or
	// already ended). A lowered call has no approval row before the
	// pre-dispatch transaction commits, so there is nothing to burn.
	refuse := func(reason string, burn bool) WriteOutcome {
		if burn && low == nil {
			w.burn(ctx, a)
		}
		w.record(ctx, base, StatusRefused, reason, nil)
		return WriteOutcome{Status: StatusRefused, Reason: reason}
	}
	if reason != "" {
		return refuse(reason, a.Status == approval.StatusApproved)
	}

	// Step 2: the connection, its token and the tool's fresh definition.
	ep := w.cfg.Endpoints[a.Server]
	if ep == nil {
		return refuse(ReasonServerUnavailable, true)
	}
	call, err := w.cfg.Connections.BeginCall(ctx, principal, a.ConnectionID, a.AuthorityRevision)
	if err != nil {
		return refuse(connectionRefusal(err).reason, true)
	}
	sent := false
	defer func() {
		if !sent {
			call.Abandon()
		}
	}()
	cctx, cancel := context.WithTimeout(call.Ctx, w.callTimeout())
	defer cancel()
	token, conn, err := w.cfg.Connections.AccessToken(cctx, principal, a.ConnectionID, a.AuthorityRevision)
	if err != nil {
		return refuse(connectionRefusal(err).reason, true)
	}
	// A token is never sent to another provider's endpoint (S1-X3).
	if conn.ID != a.ConnectionID || conn.Principal != principal || string(conn.Server) != a.Server {
		return refuse(ReasonConnectionUnbound, true)
	}
	// The scope the connection holds is the one its token response
	// reported. A granted scope this build does not accept is a mismatch;
	// an accepted one without the tool's write scope sends nothing.
	if !connection.ScopeAccepted(conn) {
		return refuse(ReasonScopeMismatch, true)
	}
	if !w.scopes().Holds(conn, a.Tool) {
		return refuse(ReasonWriteScopeMissing, true)
	}
	if w.cfg.Fresh == nil {
		return refuse(ReasonNoWritePath, true)
	}
	fresh, err := w.cfg.Fresh.FreshTool(cctx, FreshRequest{
		Principal: principal, ConnectionID: a.ConnectionID, AuthorityRevision: a.AuthorityRevision,
		Server: a.Server, Tool: a.Tool, Token: token,
	})
	if err != nil {
		reason := PinRefusalReason(err)
		w.countListingRefusal(a.Server, reason)
		return refuse(reason, true)
	}
	if fresh.SchemaSHA != a.SchemaSHA || fresh.DescriptionSHA != a.DescriptionSHA ||
		fresh.AnnotationSHA != a.AnnotationSHA || fresh.Class != a.Class || fresh.Tier != catalog.TierApprove {
		w.countListingRefusal(a.Server, ReasonToolChanged)
		return refuse(ReasonToolChanged, true)
	}
	base.Tier = fresh.Tier
	if low != nil {
		// The pin, asked again here: a tool it does not make lowerable,
		// or a call that does not meet the tool's condition, is not sent
		// without a card whatever the caller decided.
		pinned := catalog.PinnedTool{Class: fresh.Class, Lowerable: fresh.Lowerable, Constraints: fresh.Constraints, InputSchema: json.RawMessage(fresh.InputSchema)}
		if met, err := loweringCondition(pinned, low.Args); !lowerable(a.Tool, pinned) || err != nil || !met {
			return refuse(ReasonNotLowerable, false)
		}
		// No card stands behind the call, so the checks a card's value
		// passed are made here again, on the bytes that will be sent and
		// against the pin as just read: the spelling and the range of
		// every value, the arguments the tool may carry and the device
		// id. The caller ran them (precheckDeviceWrite); the executor
		// does not take its word for it (S2-D2).
		if _, ref := precheckDeviceWrite(a.Tool, pinned, low.Args); ref != nil {
			// A value the pin does not allow is named as that; any other
			// failed check is a call this path does not carry.
			if ref.reason == ReasonValueNotAllowed {
				return refuse(ReasonValueNotAllowed, false)
			}
			return refuse(ReasonNotLowerable, false)
		}
	}
	if r := cancelRefusal(ctx, cctx); r != "" {
		return refuse(r, true)
	}

	// Steps 3 and 4 are local writes. They run on their own deadline, not
	// under the call's cancellation: a /disconnect that lands now is then
	// refused by the locked re-read of the connection, with its reason,
	// instead of surfacing as a failed append.
	sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), writeSettleTimeout)
	defer scancel()

	// Step 3: the pre-dispatch entry, fail-closed (T12, I9).
	pre := base
	pre.Phase, pre.Status, pre.At = PhasePreDispatch, StatusDispatching, w.now()
	if err := w.cfg.Executor.Sink.Append(sctx, pre); err != nil {
		slog.Error("pa write: pre-dispatch audit append failed; call refused", "server", a.Server, "tool", base.Tool, "err", err)
		if low == nil {
			w.burn(ctx, a)
		}
		w.count(a.Server, StatusRefused, ReasonAuditUnavailable)
		return WriteOutcome{Status: StatusRefused, Reason: ReasonAuditUnavailable}
	}

	// Step 4: the pre-dispatch transaction.
	c := w.consume(sctx, a, dispatchID, low)
	base.Taint = c.taint
	if c.reason != "" {
		if c.unsettled {
			// The commit's outcome is not known. Nothing was sent, so the
			// call is refused; whichever row the commit left is ended.
			if w.settleUnsent(ctx, a, dispatchID) {
				w.record(ctx, base, StatusRefused, c.reason, nil)
			}
			return WriteOutcome{Status: StatusRefused, Reason: c.reason}
		}
		return refuse(c.reason, true)
	}

	// The device the call goes to is read again, now, with the receipt
	// already consumed and nothing left between this read and the
	// request: it must still be the device the card was made from (S2-D2,
	// S2-D5; device_recheck.go). One read; nothing is sent when it fails
	// or differs, and the record says "refused", not "unknown".
	if targetsDevice(a.Tool) {
		if r := w.recheckTarget(cctx, a, token, c.args, c.detail, low != nil); r != "" {
			if w.settleUnsent(ctx, a, dispatchID) {
				w.record(ctx, base, StatusRefused, r, nil)
			}
			return WriteOutcome{Status: StatusRefused, Reason: r, DispatchID: dispatchID}
		}
	}

	// A scenario's steps are read again in the same place and for the
	// same reason: what runs must be what the card listed (S2-D6;
	// scenario.go).
	if _, ok := scenarioTools[a.Tool]; ok {
		if r := w.recheckScenario(cctx, a, token, c.args, c.detail); r != "" {
			if w.settleUnsent(ctx, a, dispatchID) {
				w.record(ctx, base, StatusRefused, r, nil)
			}
			return WriteOutcome{Status: StatusRefused, Reason: r, DispatchID: dispatchID}
		}
	}

	// A call cancelled by now is refused before the record is marked, so
	// that the record still says "unsent" if it cannot be settled here.
	if r := cancelRefusal(ctx, cctx); r != "" {
		if w.settleUnsent(ctx, a, dispatchID) {
			w.record(ctx, base, StatusRefused, r, nil)
		}
		return WriteOutcome{Status: StatusRefused, Reason: r, DispatchID: dispatchID}
	}

	// The record is marked as sent in a statement of its own, and only
	// then is the request made (S2-C12). A record the mark did not reach
	// was not sent, and the stale sweep says so instead of "unknown". The
	// statement has its own deadline: the device read above may have used
	// up the one the local writes started with.
	mctx, mcancel := context.WithTimeout(context.WithoutCancel(ctx), writeSettleTimeout)
	markErr := w.cfg.Store.MarkPADispatchSent(mctx, principal, dispatchID, w.now())
	mcancel()
	switch err := markErr; {
	case errors.Is(err, approval.ErrDispatchStale):
		// The lease ran out and the sweep ended the record, or is about
		// to: it writes the one result entry and the notice. The record
		// has no mark, so the reason is the one the sweep gives it.
		w.count(a.Server, StatusRefused, ReasonNeverSent)
		return WriteOutcome{Status: StatusRefused, Reason: ReasonNeverSent, DispatchID: dispatchID}
	case err != nil:
		slog.Error("pa write: dispatch not marked as sent; call refused", "server", a.Server, "err", err)
		if w.settleUnsent(ctx, a, dispatchID) {
			w.record(ctx, base, StatusRefused, ReasonStateUnreadable, nil)
		}
		return WriteOutcome{Status: StatusRefused, Reason: ReasonStateUnreadable, DispatchID: dispatchID}
	}

	if r := cancelRefusal(ctx, cctx); r != "" {
		// Cancelled between the mark and the request: nothing was sent,
		// and the record says so rather than "unknown".
		if w.settleUnsent(ctx, a, dispatchID) {
			w.record(ctx, base, StatusRefused, r, nil)
		}
		return WriteOutcome{Status: StatusRefused, Reason: r, DispatchID: dispatchID}
	}

	// Step 5: the call, once. No transaction is open here.
	sent = true
	out, callErr := w.callOnce(cctx, ep, token, a.Tool, c.args)

	// Steps 6 and 7.
	return w.finish(ctx, call, a, c.dispatch, base, out, callErr)
}

// cancelRefusal says why a dispatch whose call context has ended before
// the request was made is refused, or "" while it is live. caller is the
// context DispatchApproved was given; call derives from it through the
// connection's registration and the call timeout.
func cancelRefusal(caller, call context.Context) string {
	switch err := call.Err(); {
	case err == nil:
		return ""
	case caller.Err() != nil:
		return ReasonDispatchCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return ReasonDispatchTimeout
	}
	// The connection manager cancelled it: /disconnect, expiry, supersede.
	return ReasonConnectionInactive
}

// precheck reads the approval and runs admit, in one short transaction
// that changes nothing. found is false when there is no approval row to
// describe the call with (absent, another principal's, or unreadable).
func (w *WriteExecutor) precheck(ctx context.Context, principal int64, approvalID string, now time.Time) (a approval.Approval, reason string, found bool) {
	tx, err := w.cfg.Store.BeginPAWrite(ctx, principal, false)
	if err != nil {
		return approval.Approval{}, ReasonApprovalUnreadable, false
	}
	defer func() { _ = tx.Rollback() }()
	a, err = w.cfg.Store.GetPAApproval(ctx, tx, principal, approvalID)
	if err != nil {
		return approval.Approval{}, approvalRefusal(err), false
	}
	switch {
	case a.Principal != principal:
		// The store keys by principal (I10); this is its second barrier.
		return approval.Approval{}, ReasonApprovalNotFound, false
	case a.Status != approval.StatusApproved:
		return a, statusRefusal(a.Status), true
	case a.Approver != principal:
		return a, ReasonApprovalNotApproved, true
	case !now.Before(a.ExpiresAt):
		return a, ReasonApprovalExpired, true
	}
	return a, w.admit(ctx, tx, a, now), true
}

// consumed is the result of the pre-dispatch transaction.
type consumed struct {
	dispatch approval.Dispatch
	// args are the canonical argument bytes to send.
	args []byte
	// detail is what was sealed next to them: the device the card was
	// made from, for a call to one device. Nil for a call without one.
	detail []byte
	taint  Taint
	// reason is why nothing may be sent, "" after a commit.
	reason string
	// unsettled: the commit failed, so the receipt may or may not be
	// consumed.
	unsettled bool
}

// consume is the pre-dispatch transaction (threat model T2 step 1, I4).
// Every return with a reason leaves the transaction rolled back, except
// unsettled.
func (w *WriteExecutor) consume(ctx context.Context, a approval.Approval, dispatchID string, low *LoweredCall) consumed {
	out := consumed{taint: TaintExternal}
	tx, err := w.cfg.Store.BeginPAWrite(ctx, a.Principal, true)
	if err != nil {
		out.reason = ReasonStateUnreadable
		return out
	}
	defer func() { _ = tx.Rollback() }()
	now := w.now()

	conn, err := w.cfg.Store.LockPAConnection(ctx, tx, a.Principal, a.ConnectionID)
	switch {
	case errors.Is(err, connection.ErrNotFound):
		out.reason = ReasonConnectionInactive
	case err != nil:
		out.reason = ReasonConnectionUnreadable
	case conn.State == connection.StateExpired:
		out.reason = ReasonConnectionExpired
	case conn.State != connection.StateActive:
		out.reason = ReasonConnectionInactive
	case conn.AuthorityRevision != a.AuthorityRevision:
		out.reason = ReasonRevisionMismatch
	case conn.Principal != a.Principal || conn.ID != a.ConnectionID || string(conn.Server) != a.Server:
		out.reason = ReasonConnectionUnbound
	case !w.scopes().Holds(conn, a.Tool):
		// Read from the locked row, in the transaction that commits the
		// dispatch: nothing is sent on a connection without the scope.
		out.reason = ReasonWriteScopeMissing
	}
	if out.reason != "" {
		return out
	}

	// The switches are read again here, not carried over from the
	// pre-check: one turned off since then refuses (S2-F3).
	if out.reason = w.admit(ctx, tx, a, now); out.reason != "" {
		return out
	}

	// Only a flag read as clean is clean (S2-I10). It labels the record.
	if tainted, err := w.cfg.Store.PAConversationTaintIn(ctx, tx, a.Principal, a.ConversationID); err == nil && !tainted {
		out.taint = TaintClean
	}

	if low != nil {
		// A lowered call has no card to stand on, so what let it through
		// is read again here, under the locks this transaction holds, and
		// only then is its ledger row written.
		if out.reason = w.lower(ctx, tx, &a, conn, *low, out.taint, now); out.reason != "" {
			return out
		}
	}

	got, d, err := w.cfg.Store.ConsumePAApproval(ctx, tx, approval.ConsumeRequest{
		Principal: a.Principal, ApprovalID: a.ID, DispatchID: dispatchID,
		Now: now, Lease: w.callTimeout() + writeLeaseMargin,
	})
	if err != nil {
		out.reason = approvalRefusal(err)
		return out
	}
	// The row consumed is the row that was checked and audited.
	if got.Binding != a.Binding || got.ID != a.ID || got.Approver != a.Approver {
		out.reason = ReasonApprovalUnreadable
		return out
	}
	args, detail, err := w.cfg.Sealer.OpenWithDetail(got)
	if err != nil {
		out.reason = ReasonApprovalUnreadable
		return out
	}
	// The bytes that will be sent are hashed again and compared with the
	// hash the card bound (S2-A3). They must also be in canonical form:
	// they are sent as they are.
	canonical, err := catalog.CanonicalArgs(args)
	if err != nil || !bytes.Equal(canonical, args) || digest(args) != got.ArgsSHA {
		out.reason = ReasonArgsChanged
		return out
	}
	if err := tx.Commit(); err != nil {
		slog.Error("pa write: pre-dispatch commit failed; call refused", "server", a.Server, "err", err)
		out.reason, out.unsettled = ReasonStateUnreadable, true
		return out
	}
	out.dispatch, out.args, out.detail = d, args, detail
	return out
}

// callOnce sends the one tools/call of a dispatch. A panic in the endpoint
// is an unknown outcome like any other failure after the request began.
func (w *WriteExecutor) callOnce(ctx context.Context, ep WriteEndpoint, token connection.Secret, tool string, args []byte) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("pa write: endpoint panicked", "server", ep.Server())
			out, err = nil, errors.New("pa connector: endpoint panicked")
		}
	}()
	return ep.CallToolExact(ctx, token, tool, args)
}

// upstreamSilenceMarkers are the texts with which a pinned server reports,
// as a tool error, that the service behind it did not answer in time. The
// request had left the server by then, so the action may have happened.
var upstreamSilenceMarkers = []string{
	"did not respond within",
	"timed out",
	"timeout",
	"apierror 502",
	"apierror 503",
	"apierror 504",
}

// upstreamSilent reports whether a tool error result says the upstream
// service did not answer, rather than that it refused or failed the call.
func upstreamSilent(out []byte) bool {
	low := strings.ToLower(string(out))
	for _, m := range upstreamSilenceMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// classify maps what the one call returned to a status. Only an answer
// that was read and understood is ok or tool_error; a server that refused
// the token ran nothing; everything else, a timeout, a cancelled context,
// a transport error and a 5xx included, is outcome_unknown.
func classify(out []byte, callErr error) (Status, string) {
	switch {
	case errors.Is(callErr, ErrMCPUnauthorized):
		return StatusRefused, ReasonServerRefused
	case callErr != nil:
		return StatusOutcomeUnknown, ReasonOutcomeUnknown
	}
	isErr, err := toolResultIsError(out)
	switch {
	case err != nil:
		return StatusOutcomeUnknown, ReasonOutcomeUnknown
	case isErr && upstreamSilent(out):
		return StatusOutcomeUnknown, ReasonOutcomeUnknown
	case isErr:
		return StatusToolError, ""
	}
	return StatusOK, ""
}

func dispatchStatus(s Status) approval.DispatchStatus {
	switch s {
	case StatusOK:
		return approval.DispatchOK
	case StatusToolError:
		return approval.DispatchToolError
	case StatusRefused:
		return approval.DispatchRefused
	case StatusFenced:
		return approval.DispatchFenced
	}
	return approval.DispatchOutcomeUnknown
}

func writeNotice(s Status) jobs.OutboxKind {
	switch s {
	case StatusOK:
		return jobs.OutboxWriteDone
	case StatusToolError:
		return jobs.OutboxWriteFailed
	case StatusRefused:
		return jobs.OutboxWriteNotSent
	case StatusFenced:
		return jobs.OutboxWriteFenced
	}
	return jobs.OutboxWriteUnknown
}

// finish is the post-dispatch check and the final write (threat model T2
// step 3). It runs on a context detached from the caller's cancellation:
// the call was sent, so its record must not be lost with the request.
func (w *WriteExecutor) finish(ctx context.Context, call *connection.Call, a approval.Approval, d approval.Dispatch, base Entry, out []byte, callErr error) WriteOutcome {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeSettleTimeout)
	defer cancel()
	status, reason := classify(out, callErr)

	// The fence: the connection first (it also deregisters the call).
	fenceErr := call.Finish(fctx)
	if fenceErr != nil {
		status, reason = StatusFenced, ReasonFenced
	}
	unrecorded := WriteOutcome{Status: StatusOutcomeUnknown, Reason: ReasonOutcomeUnknown, DispatchID: d.ID}
	tx, err := w.cfg.Store.BeginPAWrite(fctx, a.Principal, false)
	if err != nil {
		// The record stays dispatching: the sweep resolves it to
		// outcome_unknown and owes the notice and the result entry.
		slog.Error("pa write: dispatch result not recorded; left to the stale sweep", "server", a.Server, "err", err)
		return unrecorded
	}
	defer func() { _ = tx.Rollback() }()
	now := w.now()
	// Then the principal: a result that arrives after consent was
	// withdrawn, the principal disabled or the conversation closed is
	// discarded too. A failed read fences (I9).
	if fenceErr == nil {
		if r := w.principalRefusal(fctx, tx, a, now); r != "" {
			status, reason = StatusFenced, ReasonFenced
		}
	}
	if _, err := w.cfg.Store.FinishPADispatch(fctx, tx, a.Principal, d.ID, dispatchStatus(status), now); err != nil {
		if !errors.Is(err, approval.ErrDispatchStale) {
			slog.Error("pa write: dispatch result not recorded; left to the stale sweep", "server", a.Server, "err", err)
		}
		// Stale: the sweep already resolved it and reported it.
		return unrecorded
	}
	if err := w.cfg.Store.EnqueuePAOutbox(fctx, tx, jobs.OutboxItem{
		Principal: a.Principal, Kind: writeNotice(status), ApprovalID: a.ID,
	}, now); err != nil {
		slog.Error("pa write: outcome notice not queued; left to the stale sweep", "server", a.Server, "err", err)
		return unrecorded
	}
	if err := tx.Commit(); err != nil {
		slog.Error("pa write: dispatch result not committed; left to the stale sweep", "server", a.Server, "err", err)
		return unrecorded
	}

	res := WriteOutcome{Status: status, Reason: reason, DispatchID: d.ID}
	var resultBytes []byte
	if status == StatusOK || status == StatusToolError {
		res.Output, resultBytes = out, out
	}
	w.record(fctx, base, status, reason, resultBytes)
	return res
}

// record appends a call's result entry, detached from ctx's cancellation,
// and counts it. output is digested for ok and tool_error only.
func (w *WriteExecutor) record(ctx context.Context, base Entry, status Status, reason string, output []byte) {
	post := base
	post.Phase, post.Status, post.Reason, post.At = PhaseResult, status, reason, w.now()
	if status == StatusOK || status == StatusToolError {
		post.ResultSHA256 = digest(output)
	}
	w.cfg.Executor.appendDetached(ctx, post)
	w.count(base.Server, status, reason)
}

// burn ends an approval whose dispatch was refused before the receipt was
// consumed (approved -> refused, arguments erased) and queues the "nothing
// was sent" notice with it. An approval that already ended some other way
// is left as it is, without a notice: whoever ended it answered for it.
func (w *WriteExecutor) burn(ctx context.Context, a approval.Approval) {
	bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeSettleTimeout)
	defer cancel()
	tx, err := w.cfg.Store.BeginPAWrite(bctx, a.Principal, false)
	if err != nil {
		slog.Error("pa write: refused approval not ended; it expires on its own", "err", err)
		return
	}
	defer func() { _ = tx.Rollback() }()
	now := w.now()
	if _, err := w.cfg.Store.RefusePAApproval(bctx, tx, a.Principal, a.ID, now); err != nil {
		if approvalRefusal(err) == ReasonApprovalUnreadable {
			slog.Error("pa write: refused approval not ended; it expires on its own", "err", err)
		}
		return
	}
	if err := w.cfg.Store.EnqueuePAOutbox(bctx, tx, jobs.OutboxItem{
		Principal: a.Principal, Kind: jobs.OutboxWriteNotSent, ApprovalID: a.ID,
	}, now); err != nil {
		slog.Error("pa write: refused approval not ended; it expires on its own", "err", err)
		return
	}
	if err := tx.Commit(); err != nil {
		slog.Error("pa write: refused approval not ended; it expires on its own", "err", err)
	}
}

// settleUnsent ends what the pre-dispatch transaction left for a call that
// was never sent: the dispatch record as refused, with the "not carried
// out" notice, if the commit happened; the approval as refused if it did
// not. It reports whether the caller may append the refused result entry.
// It may not when a dispatch record may still be dispatching: the stale
// sweep then ends it and writes the one result entry itself, as refused
// (dispatch_never_sent) while the record does not carry the sent mark.
func (w *WriteExecutor) settleUnsent(ctx context.Context, a approval.Approval, dispatchID string) bool {
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeSettleTimeout)
	defer cancel()
	tx, err := w.cfg.Store.BeginPAWrite(sctx, a.Principal, false)
	if err != nil {
		slog.Error("pa write: unsent dispatch not settled; left to the stale sweep", "err", err)
		return false
	}
	defer func() { _ = tx.Rollback() }()
	now := w.now()
	_, err = w.cfg.Store.FinishPADispatch(sctx, tx, a.Principal, dispatchID, approval.DispatchRefused, now)
	switch {
	case errors.Is(err, approval.ErrNotFound):
		// The commit did not happen: there is no record, and the approval
		// is still open.
		_ = tx.Rollback()
		w.burn(ctx, a)
		return true
	case err != nil:
		if !errors.Is(err, approval.ErrDispatchStale) {
			slog.Error("pa write: unsent dispatch not settled; left to the stale sweep", "err", err)
		}
		return false
	}
	if err := w.cfg.Store.EnqueuePAOutbox(sctx, tx, jobs.OutboxItem{
		Principal: a.Principal, Kind: jobs.OutboxWriteNotSent, ApprovalID: a.ID,
	}, now); err != nil {
		slog.Error("pa write: unsent dispatch not settled; left to the stale sweep", "err", err)
		return false
	}
	if err := tx.Commit(); err != nil {
		slog.Error("pa write: unsent dispatch not settled; left to the stale sweep", "err", err)
		return false
	}
	return true
}

// StaleDispatchStore is the ledger's restart sweep (*db.Store). It ends
// every dispatching record whose lease ran out, as refused when its
// request was never made and as outcome_unknown otherwise, and queues the
// principal's notice in the same transaction.
type StaleDispatchStore interface {
	SweepStalePADispatches(ctx context.Context, now time.Time) ([]approval.Dispatch, error)
}

// StaleWriteSweeper owns the dispatch records no executor finished: a
// crash between the pre-dispatch commit and the result, or a result that
// could not be written (threat model T2, S2-C12). The store resolves them,
// never to anything dispatchable: a record whose request may have been
// made to outcome_unknown, with the "may or may not have happened" notice,
// and a record that was never sent to refused, with the "not carried out"
// notice. The sweeper appends the audit result entry each one still lacks.
type StaleWriteSweeper struct {
	Store StaleDispatchStore
	// Executor supplies the audit sink, its alert hook and the clock.
	Executor *Executor
}

// StaleWriteSweepInterval is how often Run sweeps. A lease is at most
// approval.MaxDispatchLease, so a crashed dispatch is reported within that
// plus one interval.
const StaleWriteSweepInterval = time.Minute

// SweepOnce runs one pass and returns how many records it resolved. A
// failed pass is an error, never "nothing stale".
func (s StaleWriteSweeper) SweepOnce(ctx context.Context) (int, error) {
	if s.Store == nil || s.Executor == nil || s.Executor.Sink == nil {
		return 0, errors.New("pa connector: stale write sweeper needs a store and an executor")
	}
	moved, err := s.Store.SweepStalePADispatches(ctx, s.Executor.now())
	if err != nil {
		return 0, err
	}
	for _, d := range moved {
		// The record keeps hashes and ids only. The pre-dispatch entry
		// carries the call's tier, class and taint under the same call id;
		// here the taint is the conservative one.
		status, reason := StatusOutcomeUnknown, ReasonLeaseExpired
		if d.Status == approval.DispatchRefused {
			// The store ends a record as refused only when its request
			// was never made.
			status, reason = StatusRefused, ReasonNeverSent
		}
		s.Executor.appendDetached(ctx, Entry{
			CallID:            d.ID,
			Phase:             PhaseResult,
			Principal:         d.Principal,
			ConnectionID:      recordable(d.ConnectionID, unboundConnection),
			AuthorityRevision: d.AuthorityRevision,
			Server:            recordable(d.Server, invalidServer),
			Tool:              recordableName(d.Tool),
			ArgsSHA256:        d.ArgsSHA,
			Taint:             TaintExternal,
			ApprovalID:        recordable(d.ApprovalID, invalidMarker),
			Approver:          staleApprover(d),
			Status:            status,
			Reason:            reason,
			At:                s.Executor.now(),
		})
	}
	return len(moved), nil
}

// staleApprover is the approver of a record the sweep ended, read from
// the ledger: the standing permission of a lowered call, which no
// principal approved, and the principal otherwise.
func staleApprover(d approval.Dispatch) string {
	if d.PermissionID != "" {
		return recordable(permissionApprover(d.PermissionID), invalidMarker)
	}
	return strconv.FormatInt(d.Principal, 10)
}

// Run sweeps every interval (StaleWriteSweepInterval if 0) until ctx ends.
func (s StaleWriteSweeper) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = StaleWriteSweepInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if n, err := s.SweepOnce(ctx); err != nil {
			slog.Warn("pa stale write sweep failed", "err", err)
		} else if n > 0 {
			slog.Warn("pa stale write sweep: dispatches whose lease ran out were ended", "records", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
