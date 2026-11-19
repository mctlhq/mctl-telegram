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

// Package connector is the Personal Assistant's connector executor
// (threat model I1, T8, T12; issue #1315). The worker proposes a tool call;
// this package decides whether it runs and records it.
//
// This slice holds the decision and the audit path only: Execute checks the
// call against the catalog pin, appends a pre-dispatch audit entry, runs the
// dispatch closure the caller supplies only if that append succeeded, and
// appends the result entry. The dispatch itself (connection re-check, token
// use, the MCP request over internal/pa/egress, pa-job token checks) is a
// later slice; it must be written as the closure passed to Execute, so that
// no dispatch path exists that skips the pin or the audit.
//
// Nothing here is called from server startup.
package connector

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

// Taint is the provenance state of the run when the call was proposed
// (threat model T5, I6). It is recorded, never used here to lower a gate.
type Taint string

const (
	TaintClean    Taint = "clean"
	TaintExternal Taint = "external"
)

// Phase is which of a call's two audit entries an Entry is.
type Phase string

const (
	PhasePreDispatch Phase = "pre_dispatch"
	PhaseResult      Phase = "result"
)

// Status is the outcome recorded for a call (threat model T12).
type Status string

const (
	// StatusDispatching marks the pre-dispatch entry.
	StatusDispatching    Status = "dispatching"
	StatusOK             Status = "ok"
	StatusRefused        Status = "refused"
	StatusFenced         Status = "fenced"
	StatusOutcomeUnknown Status = "outcome_unknown"
	// StatusToolError: the server ran the call and answered with a tool
	// error (MCP isError). The output is the error result, still external
	// content.
	StatusToolError Status = "tool_error"
)

// Errors a dispatch closure returns to classify its failure. Any other
// error is recorded as outcome_unknown: the request may have reached the
// server.
var (
	// ErrDispatchRefused: the server refused the call before acting.
	ErrDispatchRefused = errors.New("pa connector: server refused the call")
	// ErrDispatchFenced: a server-side check (connection state, authority
	// revision, kill switch) stopped the call before it was sent.
	ErrDispatchFenced = errors.New("pa connector: call fenced before send")
)

// Errors from Execute. None carries argument, output or token text.
var (
	// ErrInvalidCall: the call is incomplete; nothing was sent.
	ErrInvalidCall = errors.New("pa connector: invalid call")
	// ErrUnboundConnection wraps ErrInvalidCall for a call whose connection
	// is not one the run bound. It was audited as connection_unbound.
	ErrUnboundConnection = errors.New("pa connector: connection not bound to the run")
	// ErrAuditUnavailable: the pre-dispatch audit append failed, so the
	// call was refused and nothing was sent (threat model T12, I9).
	ErrAuditUnavailable = errors.New("pa connector: audit append failed; call refused")
)

// Call is one tool call the worker proposed, bound to the run's policy.
type Call struct {
	// Policy is the run's context. The principal and the connection
	// revision come from it, never from the worker's request (I2, I10).
	Policy pa.Policy
	// ConnectionID selects one of the run's bound connections.
	ConnectionID string
	// Tool is the name the model proposed. It is untrusted until the pin
	// has looked it up.
	Tool string
	// Args is the exact argument bytes to send. Only its digest is audited.
	Args []byte
	// Taint is the run's provenance state.
	Taint Taint
	// ApprovalID and Approver identify the decision that admitted a
	// non-auto call. Phase 1 has none, so both stay empty.
	ApprovalID string
	Approver   string
}

// Result is what a dispatch returns. Output is the tool result as received;
// only its digest is audited.
type Result struct {
	Output []byte
	// ToolError marks an MCP tool error result (isError): the call ran and
	// failed. It is recorded as tool_error, not ok.
	ToolError bool
	// Cost is the call's cost in ledger units, 0 if none.
	Cost int64
}

// Dispatch performs the MCP call. Execute calls it at most once, and only
// after the pre-dispatch entry is durably appended.
type Dispatch func(ctx context.Context) (Result, error)

// Entry is one audit record. It holds digests and identifiers only: never
// arguments, outputs, message bodies or tokens (threat model T12).
type Entry struct {
	CallID            string
	Phase             Phase
	Principal         int64 // Telegram user id
	ConnectionID      string
	AuthorityRevision int64
	Server            string
	Tool              string
	ArgsSHA256        string
	Tier              catalog.Tier
	Class             catalog.Class
	Taint             Taint
	ApprovalID        string
	Approver          string
	Status            Status
	// ResultSHA256 is set on an ok result entry.
	ResultSHA256 string
	Cost         int64
	// Reason is the fixed label of a refusal (a Reason* constant), empty
	// otherwise. Never error text.
	Reason string
	At     time.Time
}

// Sink appends audit entries to the hash-chained log. Append returns nil
// only once the entry is durably recorded.
type Sink interface {
	Append(ctx context.Context, e Entry) error
}

// Executor runs calls through the pin and the audit log.
type Executor struct {
	Sink Sink
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// OnAuditAppendFailure is called when an entry that records something
	// already decided could not be appended: the result entry after a
	// dispatch, or the refused entry of a refusal. It raises the alert
	// threat model T12 requires. The failure is also logged. nil means log
	// only. A failed pre-dispatch append does not call it: that refuses the
	// call instead.
	OnAuditAppendFailure func(e Entry, err error)
}

func (x *Executor) now() time.Time {
	if x.Now != nil {
		return x.Now()
	}
	return time.Now()
}

// Execute is the only way a PA tool call is dispatched:
//
//  1. the call must name a principal; without one nothing is recorded;
//  2. the connection must be bound to the run, the taint known, and the pin
//     must authorize the tool against the server's current surface; any
//     refusal here is audited as a single refused entry and nothing is sent;
//  3. a pre-dispatch entry is appended; if that fails, the call is refused
//     with ErrAuditUnavailable and dispatch never runs;
//  4. dispatch runs once;
//  5. a result entry is appended, also when dispatch panics; if that fails,
//     the alert hook fires, and the dispatch result is still returned, since
//     the call already ran.
//
// Result and refusal entries are appended on a context detached from ctx's
// cancellation: a run cancelled mid-dispatch still gets its result row.
func (x *Executor) Execute(ctx context.Context, surface *catalog.Surface, call Call, dispatch Dispatch) (Result, error) {
	if x == nil || x.Sink == nil || surface == nil || dispatch == nil {
		return Result{}, fmt.Errorf("%w: executor not configured", ErrInvalidCall)
	}
	principal := call.Policy.Principal()
	if principal.IsZero() {
		// Without a principal there is no chain to record the refusal in.
		return Result{}, fmt.Errorf("%w: no principal", ErrInvalidCall)
	}
	callID, err := newCallID()
	if err != nil {
		return Result{}, fmt.Errorf("%w: call id: %v", ErrInvalidCall, err)
	}
	now := x.now()
	base := Entry{
		CallID:     callID,
		Principal:  principal.TelegramID(),
		Server:     surface.Server(),
		Tool:       recordableName(call.Tool),
		ArgsSHA256: digest(call.Args),
		Taint:      call.Taint,
		ApprovalID: recordable(call.ApprovalID, invalidMarker),
		Approver:   recordable(call.Approver, invalidMarker),
	}

	// From here the principal is known, so every refusal is audited. The
	// taint is normalised first so that any refusal entry below is
	// recordable: an unknown taint must not make FormatRecord drop the row.
	taintOK := call.Taint == TaintClean || call.Taint == TaintExternal
	if !taintOK {
		base.Taint = taintInvalid
	}
	conn, ok := call.Policy.Connection(call.ConnectionID)
	if !ok || call.ConnectionID == "" {
		base.ConnectionID, base.Reason = unboundConnection, ReasonConnectionUnbound
		return Result{}, x.refuse(ctx, base, now, fmt.Errorf("%w: %w", ErrInvalidCall, ErrUnboundConnection))
	}
	base.ConnectionID, base.AuthorityRevision = conn.ConnectionID, conn.AuthorityRevision
	if !taintOK {
		base.Reason = ReasonTaintInvalid
		return Result{}, x.refuse(ctx, base, now, fmt.Errorf("%w: unknown taint", ErrInvalidCall))
	}

	grant, authErr := surface.Authorize(call.Tool, now)
	if authErr != nil {
		base.Reason = PinRefusalReason(authErr)
		return Result{}, x.refuse(ctx, base, now, authErr)
	}
	base.Tier, base.Class = grant.Tier, grant.Class

	// The pre-dispatch append keeps the live context: if the run is already
	// cancelled, refusing the call is the right outcome.
	pre := base
	pre.Phase, pre.Status, pre.At = PhasePreDispatch, StatusDispatching, now
	if err := x.Sink.Append(ctx, pre); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrAuditUnavailable, err)
	}

	return x.dispatchRecorded(ctx, base, dispatch)
}

// dispatchRecorded runs dispatch once and appends its result entry. The
// result entry is written even if dispatch panics or exits the goroutine
// (as outcome_unknown); a panic is then re-raised.
func (x *Executor) dispatchRecorded(ctx context.Context, base Entry, dispatch Dispatch) (res Result, dispatchErr error) {
	completed := false
	defer func() {
		if completed {
			return
		}
		r := recover()
		post := base
		post.Phase, post.At, post.Status = PhaseResult, x.now(), StatusOutcomeUnknown
		x.appendDetached(ctx, post)
		if r != nil {
			panic(r)
		}
	}()
	res, dispatchErr = dispatch(ctx)
	completed = true

	post := base
	post.Phase, post.At, post.Cost = PhaseResult, x.now(), res.Cost
	switch {
	case dispatchErr == nil && res.ToolError:
		post.Status = StatusToolError
		post.ResultSHA256 = digest(res.Output)
	case dispatchErr == nil:
		post.Status = StatusOK
		post.ResultSHA256 = digest(res.Output)
	case errors.Is(dispatchErr, ErrDispatchFenced):
		post.Status = StatusFenced
	case errors.Is(dispatchErr, ErrDispatchRefused):
		post.Status = StatusRefused
	default:
		post.Status = StatusOutcomeUnknown
	}
	x.appendDetached(ctx, post)
	return res, dispatchErr
}

// refuse records a refusal as a single result entry and returns cause. The
// call is refused whether or not the entry could be written; a missing
// entry raises the alert.
func (x *Executor) refuse(ctx context.Context, base Entry, at time.Time, cause error) error {
	refused := base
	refused.Phase, refused.Status, refused.At = PhaseResult, StatusRefused, at
	x.appendDetached(ctx, refused)
	return cause
}

// auditDetachTimeout bounds a result or refusal append that no longer
// follows the run's cancellation.
const auditDetachTimeout = 5 * time.Second

// appendDetached appends an entry describing something that already
// happened (a dispatch, a refusal). The run's cancellation must not lose it,
// so the append runs on a context detached from ctx's cancellation, with its
// own deadline. A failure raises the alert.
func (x *Executor) appendDetached(ctx context.Context, e Entry) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditDetachTimeout)
	defer cancel()
	if err := x.Sink.Append(dctx, e); err != nil {
		x.alert(e, err)
	}
}

// Markers recorded for a refused call whose own values are not recordable.
const (
	unboundConnection = "unbound"
	taintInvalid      = Taint("invalid")
	// invalidMarker replaces an optional identifier (approval id, approver)
	// that came from worker or model input and is outside the record's
	// alphabet, so the refusal is still recorded instead of dropped.
	invalidMarker = "invalid"
	// invalidServer replaces a server name that is not in the catalog.
	invalidServer = "invalid-server"
	// noConnection marks a refusal decided before a connection was resolved.
	noConnection = "none"
)

// Refusal reasons recorded in Entry.Reason. A closed set: the record never
// carries error text.
const (
	ReasonTokenExpired         = "token_expired"
	ReasonTokenRevoked         = "token_revoked"
	ReasonTokenInvalid         = "token_invalid"
	ReasonTokenUnverifiable    = "token_unverifiable"
	ReasonBadRequest           = "bad_request"
	ReasonFlagOff              = "flag_off"
	ReasonToolNotInSet         = "tool_not_in_set"
	ReasonToolCap              = "tool_cap"
	ReasonBudget               = "budget"
	ReasonJobStale             = "job_stale"
	ReasonJobGone              = "job_gone"
	ReasonJobUnreadable        = "job_unreadable"
	ReasonConnectionUnbound    = "connection_unbound"
	ReasonConnectionAmbiguous  = "connection_ambiguous"
	ReasonConnectionInactive   = "connection_not_active"
	ReasonRevisionMismatch     = "revision_mismatch"
	ReasonConnectionUnreadable = "connection_unreadable"
	ReasonScopeMismatch        = "scope_mismatch"
	ReasonServerUnavailable    = "server_unavailable"
	ReasonUnknownServer        = "unknown_server"
	ReasonListingStale         = "listing_stale"
	ReasonNotPinned            = "not_pinned"
	ReasonToolChanged          = "tool_changed"
	ReasonNoWritePath          = "no_write_path"
	ReasonTaintInvalid         = "taint_invalid"
	ReasonInternal             = "internal"
	// Outcomes of a call that reached Execute, as the worker sees them.
	ReasonAuditUnavailable = "audit_unavailable"
	ReasonFenced           = "fenced"
	ReasonServerRefused    = "server_refused"
	ReasonOutcomeUnknown   = "outcome_unknown"
)

// PinRefusalReason maps a catalog Authorize error to its reason. An error
// it does not know is ReasonInternal, never a pass.
func PinRefusalReason(err error) string {
	switch {
	case errors.Is(err, catalog.ErrServerUnavailable):
		return ReasonServerUnavailable
	case errors.Is(err, catalog.ErrUnknownServer):
		return ReasonUnknownServer
	case errors.Is(err, catalog.ErrListingStale):
		return ReasonListingStale
	case errors.Is(err, catalog.ErrNotPinned):
		return ReasonNotPinned
	case errors.Is(err, catalog.ErrToolChanged):
		return ReasonToolChanged
	case errors.Is(err, catalog.ErrNoWritePath):
		return ReasonNoWritePath
	}
	return ReasonInternal
}

// Refusal is a call refused before Execute could run: the token, the
// request, a flag, the job ledger or the connection said no. Every field
// may come from the worker; RecordRefusal normalises each one.
type Refusal struct {
	Principal         int64
	Server            string
	Tool              string
	ConnectionID      string
	AuthorityRevision int64
	Args              []byte
	Reason            string
}

// RecordRefusal appends a single refused entry for r in the principal's
// chain (threat model T12: "every call and refusal"). Server, tool and
// connection are normalised to the record's alphabet, with fixed markers
// in place of anything else, so a hostile value can neither enter the
// record nor make the sink drop the row. A principal <= 0 has no chain and
// is not recorded. A failed append raises the alert hook.
func (x *Executor) RecordRefusal(ctx context.Context, r Refusal, servers func(string) bool) {
	if x == nil || x.Sink == nil || r.Principal <= 0 {
		return
	}
	callID, err := newCallID()
	if err != nil {
		slog.Error("pa connector: refusal call id", "err", err)
		return
	}
	server := invalidServer
	if servers != nil && servers(r.Server) {
		server = r.Server
	}
	conn := noConnection
	if r.ConnectionID != "" {
		conn = recordable(r.ConnectionID, unboundConnection)
	}
	reason := r.Reason
	if !reasonRE.MatchString(reason) {
		reason = ReasonInternal
	}
	e := Entry{
		CallID:            callID,
		Phase:             PhaseResult,
		Principal:         r.Principal,
		ConnectionID:      conn,
		AuthorityRevision: max(r.AuthorityRevision, 0),
		Server:            server,
		Tool:              recordableName(r.Tool),
		ArgsSHA256:        digest(r.Args),
		Taint:             TaintExternal,
		Status:            StatusRefused,
		Reason:            reason,
		At:                x.now(),
	}
	x.appendDetached(ctx, e)
}

var reasonRE = regexp.MustCompile(`^[a-z_]{1,40}$`)

// recordable returns v if it is in the record's alphabet (or empty), and
// marker otherwise.
func recordable(v, marker string) string {
	if v == "" || safeToken.MatchString(v) {
		return v
	}
	return marker
}

func (x *Executor) alert(e Entry, err error) {
	slog.Error("pa connector: audit append failed",
		"call_id", e.CallID, "server", e.Server, "tool", e.Tool,
		"phase", string(e.Phase), "status", string(e.Status), "err", err)
	if x.OnAuditAppendFailure != nil {
		x.OnAuditAppendFailure(e, err)
	}
}

// digest is the hex SHA-256 of b. Arguments and outputs are recorded only
// this way.
func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// recordableName returns the proposed tool name if it is a plausible tool
// name, and a fixed marker otherwise. The name is model output: a refused
// call must not carry arbitrary text into the audit log.
func recordableName(name string) string {
	if toolNameRE.MatchString(name) {
		return name
	}
	return "invalid-tool-name"
}

var toolNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func newCallID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
