// Package mctlapi is the facade's client for the mctl-api wire protocol
// glovo-facade-mctl-api/v1alpha1.
//
// STATUS: the routes below are a CANDIDATE HARNESS INTERFACE served only by
// ./fakeapi. They are not an existing mctl-api API. The canonical route,
// verb and schema matrix is owned by mctl-api#957 and must replace this
// table before any integration (see docs/contracts/glovo-facade-mctl-api.md).
// Swapping it must stay local to this package behind Client.
package mctlapi

import (
	"context"
	"encoding/json"
	"time"
)

// WireVersion is the version of the candidate wire protocol.
const WireVersion = "glovo-facade-mctl-api/v1alpha1"

// BasePath is the candidate route prefix under the mctl-api base URL.
const BasePath = "/api/v1/assistants/glovo/v1alpha1"

// Typed refusal codes (ADR 0010 plus facade-local codes). Closed set.
const (
	CodeNotAuthorized       = "not_authorized"
	CodeNoTenant            = "no_tenant"
	CodeAmbiguousTenant     = "ambiguous_tenant"
	CodeScopeUnsupported    = "scope_unsupported"
	CodeNotInPilot          = "not_in_pilot"
	CodeNoInstall           = "no_install"
	CodeStaleInstall        = "stale_install"
	CodeNoConnection        = "no_connection"
	CodeConnectionRevoked   = "connection_revoked"
	CodeConnectionExpired   = "connection_expired"
	CodeNotFound            = "not_found"
	CodeInvalidArguments    = "invalid_arguments"
	CodeRateLimited         = "rate_limited"
	CodeUpstreamUnavailable = "upstream_unavailable"
	CodeUpstreamInvalid     = "upstream_invalid"
)

var upstreamCodes = map[string]bool{
	CodeNotAuthorized: true, CodeNoTenant: true, CodeAmbiguousTenant: true,
	CodeScopeUnsupported: true, CodeNotInPilot: true, CodeNoInstall: true,
	CodeStaleInstall: true, CodeNoConnection: true, CodeConnectionRevoked: true,
	CodeConnectionExpired: true, CodeNotFound: true,
}

// RefusalError is a typed refusal. Code is from the closed set above and is
// the only thing a tool result ever carries about a failure.
type RefusalError struct{ Code string }

func (e *RefusalError) Error() string { return "glovo: " + e.Code }

// Refuse builds a RefusalError.
func Refuse(code string) error { return &RefusalError{Code: code} }

// Scope is the short-lived resolved tenant scope returned by Resolve. Ref is
// an opaque handle bound by mctl-api to the subject token; it is never
// exposed to tools or logs.
type Scope struct {
	Ref       string
	Tenant    string
	ExpiresAt time.Time
}

// Op identifies one mctl-api operation.
type Op string

// Candidate operations. Read operations never write; Effect reports whether
// the operation can create state.
const (
	OpConnection Op = "connection"
	OpConnect    Op = "connect"
	OpOrders     Op = "orders"
	OpPreview    Op = "preview"
	OpBasket     Op = "basket"
	OpPrepare    Op = "prepare"
	OpOrder      Op = "order"
)

// Client is what the tool handlers depend on.
type Client interface {
	// Resolve re-verifies the caller (token, membership, pilot allowlist,
	// install) and returns the tenant scope. It is called on every tool call.
	Resolve(ctx context.Context) (Scope, error)
	// Do performs one operation within scope. body is marshalled as JSON for
	// POST operations; pathID is the opaque id for OpOrder. The returned
	// bytes are the unvalidated upstream JSON object.
	Do(ctx context.Context, scope Scope, op Op, body any, pathID string) (json.RawMessage, error)
	// Health checks mctl-api liveness (readiness probe).
	Health(ctx context.Context) error
}
