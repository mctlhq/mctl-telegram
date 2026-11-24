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

// Package approval is the durable approval and dispatch ledger of a PA
// write (threat model T2 "Execution-time check and dispatch", T7; #1320
// slice P2-S2). It holds the types, the state machine and the store
// contract; internal/db implements the store.
//
// An approval is a single-use receipt for one exact call. It binds the
// principal, the connection and its authority_revision, the server and
// tool, the schema, description and annotation hashes, the hash of the
// canonical arguments, the conversation, a five-minute expiry and a
// server-generated idempotency key.
//
// Approval states:
//
//	pending -> approved                the principal tapped Approve
//	pending | approved -> cancelled    Cancel, /new, disconnect
//	pending | approved -> expired      five minutes passed
//	pending | approved -> refused      the executor burned it (drift)
//	approved -> dispatching            the receipt was consumed (compare-and-set)
//	dispatching -> done                its dispatch reached a final status
//
// Nothing leaves done, cancelled, expired or refused, and nothing returns
// to approved: a consumed receipt is never usable again.
//
// Dispatch states (commit-then-call):
//
//	dispatching -> ok | tool_error | refused | fenced | outcome_unknown
//
// The dispatching row is committed before the outbound call, and marked
// as sent (MarkPADispatchSent) immediately before the request is made. A
// row whose lease ran out (a crash between that commit and the result) is
// never dispatched again: one that carries the mark, or was written by a
// build that had no mark, becomes outcome_unknown; one that is known not to
// have been sent becomes refused.
//
// Retention: the sealed arguments leave the row in the transaction that
// ends pending/approved (consume, cancel, expire, refuse). Rows hold
// hashes only after that. The conversation sweep deletes them Retention
// after they were created; /forget and consent withdrawal delete them at
// once, except the two rows of a call that is on the wire; account
// deletion deletes every row.
//
// Nothing in the running service calls this package yet (P2-S2 is the
// store only); PA_WRITES_ENABLED stays off.
package approval

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

// TTL is how long an approval can be approved and consumed (T7). The store
// derives the expiry from the creation time and this constant; no caller
// can ask for a longer one.
const TTL = 5 * time.Minute

// Retention is how long a row without arguments is kept after it was
// created, for the "already done" answer and the dispatch record. It is
// the conversation lifetime: nothing about a call outlives the
// conversation it was made in, except the audit's hashes.
const Retention = 24 * time.Hour

// MaxDispatchLease bounds a dispatch lease, so a crashed dispatch is
// resolved (outcome_unknown, or refused when it was never sent) within
// minutes.
const MaxDispatchLease = 10 * time.Minute

// Status is an approval's state.
type Status string

const (
	StatusPending     Status = "pending"
	StatusApproved    Status = "approved"
	StatusDispatching Status = "dispatching"
	StatusDone        Status = "done"
	StatusCancelled   Status = "cancelled"
	StatusExpired     Status = "expired"
	StatusRefused     Status = "refused"
)

// Valid reports whether s is a state this build knows.
func (s Status) Valid() bool {
	switch s {
	case StatusPending, StatusApproved, StatusDispatching, StatusDone,
		StatusCancelled, StatusExpired, StatusRefused:
		return true
	}
	return false
}

// Open reports whether s still holds a usable receipt (and its arguments).
func (s Status) Open() bool { return s == StatusPending || s == StatusApproved }

// DispatchStatus is a dispatch record's state.
type DispatchStatus string

const (
	DispatchDispatching    DispatchStatus = "dispatching"
	DispatchOK             DispatchStatus = "ok"
	DispatchToolError      DispatchStatus = "tool_error"
	DispatchRefused        DispatchStatus = "refused"
	DispatchFenced         DispatchStatus = "fenced"
	DispatchOutcomeUnknown DispatchStatus = "outcome_unknown"
)

// Valid reports whether s is a state this build knows.
func (s DispatchStatus) Valid() bool {
	return s == DispatchDispatching || s.Final()
}

// Final reports whether s is a result a dispatch can finish with.
func (s DispatchStatus) Final() bool {
	switch s {
	case DispatchOK, DispatchToolError, DispatchRefused, DispatchFenced, DispatchOutcomeUnknown:
		return true
	}
	return false
}

var (
	// ErrNotFound is the documented absence signal: the principal has no
	// such approval or dispatch. Another principal's id is ErrNotFound.
	ErrNotFound = errors.New("pa approval: not found")
	// ErrUnreadable is any failure to read or interpret a row, and any
	// write whose outcome could not be observed. It is never absence and
	// never "expired" (I9).
	ErrUnreadable = errors.New("pa approval: state unreadable")
	// ErrInvalid is a call the store refuses before touching a row.
	ErrInvalid = errors.New("pa approval: invalid request")
	// ErrBinding is an approval created for a conversation that is not the
	// principal's open one, or a connection that is not the principal's,
	// active and at the bound authority_revision.
	ErrBinding = errors.New("pa approval: binding does not hold")
	// ErrExpired: the five minutes passed.
	ErrExpired = errors.New("pa approval: expired")
	// ErrConsumed: the receipt was already used (replay, double tap).
	ErrConsumed = errors.New("pa approval: receipt already consumed")
	// ErrNotApproved: the receipt of a pending approval cannot be consumed.
	ErrNotApproved = errors.New("pa approval: not approved")
	// ErrAlreadyApproved: the approval was approved before this tap.
	ErrAlreadyApproved = errors.New("pa approval: already approved")
	// ErrCancelled and ErrRefused: the approval ended without a dispatch.
	ErrCancelled = errors.New("pa approval: cancelled")
	ErrRefused   = errors.New("pa approval: refused")
	// ErrAuthorityChanged: the connection is not active at the
	// authority_revision the approval was bound to.
	ErrAuthorityChanged = errors.New("pa approval: connection authority changed")
	// ErrConversationClosed: the conversation the approval was made in is
	// closed, expired or gone.
	ErrConversationClosed = errors.New("pa approval: conversation closed")
	// ErrDispatchStale: the dispatch is no longer dispatching (the restart
	// sweep resolved it, or it was finished before). The caller's result is
	// not recorded.
	ErrDispatchStale = errors.New("pa approval: dispatch is not dispatching")
)

// Binding is what an approval is bound to (T7).
type Binding struct {
	Principal         int64
	ConnectionID      string
	AuthorityRevision int64
	Server            string
	Tool              string
	// Class is the pin's class of the tool: a write or a disclosure.
	Class catalog.Class
	// SchemaSHA, DescriptionSHA and AnnotationSHA are the hex SHA-256 of
	// the tool definition the card was built from; DescriptionSHA is the
	// live server description hash. ArgsSHA is catalog.CanonicalArgsSHA256
	// of the exact arguments.
	SchemaSHA      string
	DescriptionSHA string
	AnnotationSHA  string
	ArgsSHA        string
	ConversationID string
	// JobID is the run that proposed the call, 0 if none.
	JobID int64
}

// Approval is one approval row.
type Approval struct {
	Binding
	ID string
	// ApproveCallbackID and CancelCallbackID are the opaque callback_data
	// ids of the card's two buttons. They stay on the row after the
	// callbacks are consumed, so a later tap is answered from it.
	ApproveCallbackID string
	CancelCallbackID  string
	// IdempotencyKey is generated here, never by the worker (T2).
	IdempotencyKey string
	// SealedArgs is the canonical arguments sealed by Sealer. Only
	// ConsumePAApproval returns it; every other read leaves it nil.
	SealedArgs []byte
	Status     Status
	// PermissionID is the standing permission a lowered call stands on: the
	// ledger row of such a call is created with it, and no principal
	// approves it. "" for a call that has a card.
	PermissionID string
	// Approver is the principal that tapped Approve; 0 before that, and 0
	// for a lowered call, which nobody tapped.
	Approver   int64
	CreatedAt  time.Time
	ExpiresAt  time.Time
	FinishedAt time.Time
}

// Dispatch is one dispatch record: a call that was, or is about to be,
// sent. It holds hashes and ids only.
type Dispatch struct {
	Principal         int64
	ID                string
	ApprovalID        string
	ConnectionID      string
	AuthorityRevision int64
	Server            string
	Tool              string
	ArgsSHA           string
	IdempotencyKey    string
	Status            DispatchStatus
	// Send says whether the request was made (see SendState).
	Send SendState
	// PermissionID is the standing permission that stood in for the card
	// of a lowered call, "" for a call the principal approved.
	PermissionID string
	LeaseUntil   time.Time
	CreatedAt    time.Time
	FinishedAt   time.Time
}

// SendState records, on a dispatch record, whether its request was made.
// The executor commits SendSent immediately before the one request, in a
// statement that fails once the record is no longer dispatching or its
// lease ran out, so a record that still reads SendUnsent was not sent and
// never will be.
type SendState string

const (
	// SendNotRecorded is a record written by a build that did not record
	// the state: nothing is known about its request.
	SendNotRecorded SendState = ""
	// SendUnsent: the pre-dispatch transaction committed and the request
	// has not been made.
	SendUnsent SendState = "unsent"
	// SendSent: the request may have been made.
	SendSent SendState = "sent"
)

// Valid reports whether s is a send state this build knows.
func (s SendState) Valid() bool {
	return s == SendNotRecorded || s == SendUnsent || s == SendSent
}

// newOpaqueID returns 128 random bits, base64url (22 bytes).
func newOpaqueID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error (Go 1.24+).
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewID returns a fresh opaque id for an approval, a callback or a
// dispatch.
func NewID() string { return newOpaqueID() }

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Validate refuses a binding with a missing or malformed part: an approval
// that does not bind everything binds nothing.
func (b Binding) Validate() error {
	switch {
	case b.Principal <= 0:
		return fmt.Errorf("%w: no principal", ErrInvalid)
	case b.ConnectionID == "" || b.AuthorityRevision <= 0:
		return fmt.Errorf("%w: no connection or authority_revision", ErrInvalid)
	case b.Server == "" || b.Tool == "":
		return fmt.Errorf("%w: no server or tool", ErrInvalid)
	case b.Class != catalog.ClassWrite && b.Class != catalog.ClassDisclosure:
		return fmt.Errorf("%w: class %q is not a write or a disclosure", ErrInvalid, b.Class)
	case !isSHA256Hex(b.SchemaSHA) || !isSHA256Hex(b.DescriptionSHA) ||
		!isSHA256Hex(b.AnnotationSHA) || !isSHA256Hex(b.ArgsSHA):
		return fmt.Errorf("%w: a hash is not a hex SHA-256", ErrInvalid)
	case b.ConversationID == "":
		return fmt.Errorf("%w: no conversation", ErrInvalid)
	case b.JobID < 0:
		return fmt.Errorf("%w: job id", ErrInvalid)
	}
	return nil
}

// New returns a pending approval for b, created at now, with fresh ids and
// a fresh idempotency key and without arguments: Sealer.Seal adds them.
func New(b Binding, now time.Time) (Approval, error) {
	if err := b.Validate(); err != nil {
		return Approval{}, err
	}
	if now.IsZero() {
		return Approval{}, fmt.Errorf("%w: no creation time", ErrInvalid)
	}
	now = now.UTC().Truncate(time.Millisecond)
	return Approval{
		Binding:           b,
		ID:                newOpaqueID(),
		ApproveCallbackID: newOpaqueID(),
		CancelCallbackID:  newOpaqueID(),
		IdempotencyKey:    newOpaqueID(),
		Status:            StatusPending,
		CreatedAt:         now,
		ExpiresAt:         now.Add(TTL),
	}, nil
}

// ConsumeRequest consumes an approved receipt for one dispatch.
type ConsumeRequest struct {
	Principal  int64
	ApprovalID string
	// DispatchID is the id of the dispatch record to insert (NewID).
	DispatchID string
	Now        time.Time
	// Lease is how long the dispatch may stay dispatching before the sweep
	// ends it; at most MaxDispatchLease.
	Lease time.Duration
}

// Validate refuses a request the store would not act on.
func (r ConsumeRequest) Validate() error {
	if r.Principal <= 0 || r.ApprovalID == "" || r.DispatchID == "" || r.Now.IsZero() ||
		r.Lease <= 0 || r.Lease > MaxDispatchLease {
		return fmt.Errorf("%w: consume", ErrInvalid)
	}
	return nil
}

// Store is the approval and dispatch ledger. Every method that takes a
// transaction runs in the caller's, so the caller decides what commits
// with it. Every lookup is keyed by (principal, id) (I10). A failed read
// wraps ErrUnreadable and is never ErrNotFound, ErrExpired or an empty
// result (I9).
type Store interface {
	// CreatePAApproval inserts a as pending. It refuses (ErrBinding) unless
	// the conversation is the principal's open one and the connection is
	// the principal's, active and at a.AuthorityRevision. The expiry is
	// a.CreatedAt + TTL whatever a.ExpiresAt says.
	CreatePAApproval(ctx context.Context, tx *sql.Tx, a Approval) error
	// GetPAApproval reads one approval, without its arguments.
	GetPAApproval(ctx context.Context, tx *sql.Tx, principal int64, id string) (Approval, error)
	// LookupPAApprovalByCallback finds the principal's approval whose
	// Approve or Cancel button carried callbackID, in whatever state it is,
	// for the answer to a tap whose callback is already gone.
	LookupPAApprovalByCallback(ctx context.Context, tx *sql.Tx, principal int64, callbackID string) (Approval, error)
	// ApprovePAApproval moves pending -> approved before the expiry and
	// records the approver. It deletes both of the card's callbacks.
	ApprovePAApproval(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) (Approval, error)
	// CancelPAApproval moves pending or approved -> cancelled, erases the
	// arguments and deletes the card's callbacks. A consumed receipt is
	// ErrConsumed and is left alone: a dispatched call is never marked
	// cancelled.
	CancelPAApproval(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) (Approval, error)
	// RefusePAApproval is CancelPAApproval ending in refused.
	RefusePAApproval(ctx context.Context, tx *sql.Tx, principal int64, id string, now time.Time) (Approval, error)
	// CancelPAApprovalsForConnection cancels every pending or approved
	// approval of the principal bound to connectionID (/disconnect step 4)
	// and returns how many.
	CancelPAApprovalsForConnection(ctx context.Context, tx *sql.Tx, principal int64, connectionID string, now time.Time) (int64, error)
	// ConsumePAApproval is the receipt compare-and-set of the pre-dispatch
	// transaction (T2 step 1): approved -> dispatching, only before the
	// expiry, only while the bound connection is active at the bound
	// authority_revision and only while the bound conversation is open. In
	// the same transaction it takes the arguments off the row and inserts
	// the dispatching record. It returns the approval as consumed, with
	// its sealed arguments, and the dispatch.
	//
	// A refusal names its reason: ErrNotFound, ErrNotApproved,
	// ErrConsumed, ErrCancelled, ErrRefused, ErrExpired,
	// ErrAuthorityChanged, ErrConversationClosed, or ErrUnreadable when
	// the reason could not be read or the dispatch could not be recorded.
	// The caller must roll back on every error: some are returned after
	// the receipt was moved in this transaction.
	ConsumePAApproval(ctx context.Context, tx *sql.Tx, req ConsumeRequest) (Approval, Dispatch, error)
	// MarkPADispatchSent records, in a statement of its own, that the
	// request of the dispatching record is about to be made. It succeeds
	// only for a record that is dispatching, unsent and inside its lease;
	// any other is ErrDispatchStale, and the caller must not send. An
	// error that is not ErrDispatchStale leaves the mark unknown, and the
	// caller must not send either.
	MarkPADispatchSent(ctx context.Context, principal int64, dispatchID string, now time.Time) error
	// FinishPADispatch moves dispatching -> status (a Final one) and its
	// approval to done. A dispatch that is no longer dispatching is
	// ErrDispatchStale and keeps the status it has.
	FinishPADispatch(ctx context.Context, tx *sql.Tx, principal int64, dispatchID string, status DispatchStatus, now time.Time) (Dispatch, error)
	// SweepStalePADispatches ends every dispatching record whose lease ran
	// out, and moves its approval to done, in one transaction of its own,
	// and returns the records it moved with the status it gave them:
	// refused for a record that is SendUnsent (nothing was sent),
	// outcome_unknown for every other. It never makes a receipt usable
	// again.
	SweepStalePADispatches(ctx context.Context, now time.Time) ([]Dispatch, error)
}
