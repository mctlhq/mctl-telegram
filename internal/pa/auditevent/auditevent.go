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

// Package auditevent is the audit record of a Personal Assistant change
// that is not a tool call: a standing permission granted or revoked, an
// approval cancelled (threat model T12; S2-A8, S2-C9; #1320 slice P2-S15a).
//
// Such a change is one database transaction, and the audit chain has its
// own (ADR 0003: the per-user hash chain is extended under its own lock).
// So the change writes an Event row in its transaction, and a sweeper
// moves each row into the chain, deleting the row in the commit that
// appends it. An event is therefore never lost with a committed change,
// and is appended once.
//
// An Event holds identifiers, digests and closed labels only: never
// arguments, device names, message text or tokens. It names no operator.
package auditevent

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Kind is what happened. It is the status of the audit row.
type Kind string

const (
	// PermissionGranted: /permissions created a standing permission.
	PermissionGranted Kind = "permission_granted"
	// PermissionRevoked: a standing permission stopped counting before
	// its expiry.
	PermissionRevoked Kind = "permission_revoked"
	// ApprovalCancelled: an approval that was not dispatched was ended
	// by something other than a refusal of its own call.
	ApprovalCancelled Kind = "approval_cancelled"
)

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	return k == PermissionGranted || k == PermissionRevoked || k == ApprovalCancelled
}

// The reasons are a closed set. Each says which change ended the
// permission or the approval; none is error text.
const (
	// ReasonByPrincipal: the principal pressed Revoke on /permissions or
	// Cancel on the card.
	ReasonByPrincipal = "by_principal"
	// ReasonConnectionChanged: the connection's authority revision moved
	// (/disconnect, a reconnect, a revocation by the refresh flight).
	ReasonConnectionChanged = "connection_changed"
	// ReasonConversationClosed: /new closed the conversation the approval
	// belonged to.
	ReasonConversationClosed = "conversation_closed"
	// ReasonDataForgotten: /forget or a consent withdrawal.
	ReasonDataForgotten = "data_forgotten"
	// ReasonPrincipalDisabled: an operator disabled the principal.
	ReasonPrincipalDisabled = "principal_disabled"
)

// Reasons lists every reason.
var Reasons = []string{
	ReasonByPrincipal, ReasonConnectionChanged, ReasonConversationClosed, ReasonDataForgotten, ReasonPrincipalDisabled,
}

// ValidReason reports whether r may stand on an event of kind k. A grant
// has no reason; a revocation or a cancellation has one of Reasons, and
// only an approval is ended by a closed conversation.
func ValidReason(k Kind, r string) bool {
	switch k {
	case PermissionGranted:
		return r == ""
	case PermissionRevoked:
		return r == ReasonByPrincipal || r == ReasonConnectionChanged || r == ReasonDataForgotten || r == ReasonPrincipalDisabled
	case ApprovalCancelled:
		return r == ReasonByPrincipal || r == ReasonConnectionChanged || r == ReasonConversationClosed ||
			r == ReasonDataForgotten || r == ReasonPrincipalDisabled
	}
	return false
}

// Event is one queued record.
type Event struct {
	// Principal is the Telegram id of the principal the change belongs to.
	Principal int64
	Kind      Kind
	// Subject is the id of the permission or of the approval.
	Subject           string
	Server            string
	Tool              string
	ConnectionID      string
	AuthorityRevision int64
	// ArgsSHA256 is the digest the approval was bound to; empty for a
	// permission, which binds no arguments.
	ArgsSHA256 string
	Reason     string
	// AtMS is when the change was made, in unix milliseconds. The audit
	// row's own time is when the sweeper appended it.
	AtMS int64
}

// ErrUnrecordable is returned for an event that cannot be rendered.
var ErrUnrecordable = errors.New("pa audit event: cannot be recorded")

// RecordVersion opens the record of an event. It differs from the tool
// call record's ("pa/v1"), so a reader tells the two shapes apart by the
// first token.
const RecordVersion = "pa-event/v1"

// safeToken is the alphabet of every identifier in a record, the one of
// the tool call record. A value outside it is refused, not escaped.
var safeToken = regexp.MustCompile(`^[A-Za-z0-9_.:/-]{1,128}$`)

// Record renders e: space-separated key=value pairs in a fixed order.
// Absent optional values are "-".
func (e Event) Record() (string, error) {
	if e.Principal <= 0 || !e.Kind.Valid() || !ValidReason(e.Kind, e.Reason) || e.AtMS <= 0 || e.AuthorityRevision < 0 {
		return "", fmt.Errorf("%w: principal, kind, reason, revision or time", ErrUnrecordable)
	}
	permission, approval := "", ""
	if e.Kind == ApprovalCancelled {
		approval = e.Subject
	} else {
		permission = e.Subject
	}
	fields := []struct {
		key, val string
		required bool
	}{
		{"event", string(e.Kind), true},
		{"principal", strconv.FormatInt(e.Principal, 10), true},
		{"server", e.Server, true},
		{"tool", e.Tool, true},
		{"conn", e.ConnectionID, true},
		{"rev", strconv.FormatInt(e.AuthorityRevision, 10), true},
		{"permission", permission, e.Kind != ApprovalCancelled},
		{"approval", approval, e.Kind == ApprovalCancelled},
		{"args", e.ArgsSHA256, e.Kind == ApprovalCancelled},
		{"reason", e.Reason, e.Kind != PermissionGranted},
		{"at", strconv.FormatInt(e.AtMS, 10), true},
	}
	var b strings.Builder
	b.WriteString(RecordVersion)
	for _, f := range fields {
		v := f.val
		switch {
		case v == "" && f.required:
			return "", fmt.Errorf("%w: %s is empty", ErrUnrecordable, f.key)
		case v == "":
			v = "-"
		case !safeToken.MatchString(v):
			return "", fmt.Errorf("%w: %s has unsafe characters", ErrUnrecordable, f.key)
		}
		b.WriteByte(' ')
		b.WriteString(f.key)
		b.WriteByte('=')
		b.WriteString(v)
	}
	return b.String(), nil
}
