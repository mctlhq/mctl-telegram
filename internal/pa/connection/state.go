// Package connection is the Personal Assistant connection store logic
// (issue #1314, threat model T2, T3 and T8): the connection state machine,
// the two counters, per-connection secret sealing, the executor-side
// effective-scope check, the read gate and the fencing check.
//
// It holds no linking flow (Mini App, OAuth, callback; S1-L1..L14). That is a
// later slice, which drives a connection through the pending_* states with
// the Manager methods here. Nothing in this package is wired into server
// startup.
//
// The persistent store is internal/db (pa_connections.go), which implements
// Store. Every Store method is keyed by (principal, id) (I10): a principal
// never reaches another principal's row, not even to learn that it exists.
//
// "Could not observe" is never "observed absent" (I9): a failed read of a
// connection row is ErrUnreadable at the gate, never "not active" and never
// "active".
package connection

import (
	"errors"
	"fmt"
	"time"
)

// Server names a catalog MCP server a connection points at. Phase 1 has two.
type Server string

const (
	ServerTG    Server = "tg"
	ServerAlice Server = "alice"
)

// Valid reports whether s is a server a connection may be created for.
func (s Server) Valid() bool {
	_, ok := allowedScopes[s]
	return ok
}

// State is a connection's lifecycle state (threat model T2):
//
//	pending_link -> pending_oauth -> pending_return -> pending_confirm -> active
//	active -> expired
//	any non-terminal -> failed
//	any -> revoked (terminal)
//
// expired, failed and revoked are never re-activated in place. A reconnect,
// and any scope escalation, is a new connection id through the whole flow.
type State string

const (
	StatePendingLink    State = "pending_link"
	StatePendingOAuth   State = "pending_oauth"
	StatePendingReturn  State = "pending_return"
	StatePendingConfirm State = "pending_confirm"
	StateActive         State = "active"
	StateExpired        State = "expired"
	StateFailed         State = "failed"
	StateRevoked        State = "revoked"
)

// AllStates lists every state, in lifecycle order.
var AllStates = []State{
	StatePendingLink, StatePendingOAuth, StatePendingReturn, StatePendingConfirm,
	StateActive, StateExpired, StateFailed, StateRevoked,
}

// Valid reports whether s is one of the known states. A row carrying any
// other value is unreadable, not "some state that is not active".
func (s State) Valid() bool {
	for _, k := range AllStates {
		if s == k {
			return true
		}
	}
	return false
}

// Pending reports whether s is one of the pending_* linking states.
func (s State) Pending() bool {
	switch s {
	case StatePendingLink, StatePendingOAuth, StatePendingReturn, StatePendingConfirm:
		return true
	}
	return false
}

// NonTerminal reports whether s may still move to failed: the pending_*
// states and active. expired and failed are final except for revoked;
// revoked is absorbing.
func (s State) NonTerminal() bool {
	return s.Pending() || s == StateActive
}

// CanTransition reports whether from -> to is a legal edge. Everything not
// listed is illegal, including every self-loop and every way back to active.
func CanTransition(from, to State) bool {
	if !from.Valid() || !to.Valid() {
		return false
	}
	switch to {
	case StatePendingOAuth:
		return from == StatePendingLink
	case StatePendingReturn:
		return from == StatePendingOAuth
	case StatePendingConfirm:
		return from == StatePendingReturn
	case StateActive:
		return from == StatePendingConfirm
	case StateExpired:
		return from == StateActive
	case StateFailed:
		return from.NonTerminal()
	case StateRevoked:
		return from != StateRevoked
	}
	return false
}

// WipesSecrets reports whether entering s destroys every sealed secret of
// the connection, including the wrapped DEK. Those states can never be used
// again, so nothing in them needs a key.
func (s State) WipesSecrets() bool {
	return s == StateExpired || s == StateFailed || s == StateRevoked
}

// Connection is one connection row without its secret material.
//
// AuthorityRevision changes on every state change, and so with confirmation,
// scope, account identity, disable and revocation. Jobs, approvals and
// standing permissions bind to it. TokenGeneration changes on every token
// rotation and nothing binds to it, so a routine refresh does not invalidate
// a run's next call (S1-C3).
type Connection struct {
	ID                string
	Principal         int64
	Server            Server
	State             State
	AccountID         string
	GrantedScope      string
	AuthorityRevision int64
	TokenGeneration   int64
	FailureReason     string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// Sealed is a connection's secret material, as stored. None of it is
// plaintext: WrappedDEK is wrapped by the KEK named by KEKID, and
// SealedCode/SealedTokens are sealed by that DEK with the connection's
// identity as associated data.
type Sealed struct {
	KEKID        string
	WrappedDEK   []byte
	SealedCode   []byte
	SealedTokens []byte
}

// Transition is one compare-and-set state change. The store applies it only
// if the row is still in From at ExpectRevision, bumps AuthorityRevision, and
// refuses an illegal edge before touching the row.
type Transition struct {
	From           State
	To             State
	ExpectRevision int64
	// AccountID and GrantedScope are set exactly when To is
	// pending_confirm, and only then: an existing connection never changes
	// its account or its scope (S1-C8).
	AccountID    string
	GrantedScope string
	// SealedCode is set exactly when To is pending_return.
	SealedCode []byte
	// SealedTokens is set exactly when To is pending_confirm.
	SealedTokens []byte
	// Reason is recorded for failed and expired. It is a reason code, never
	// a token, a server response body or a user value.
	Reason string
	// At is when the transition happens, from the Manager's clock. The
	// store records it as the connection's updated time, so the pending-age
	// sweep and the transitions it judges share one clock. Zero means the
	// store's own clock.
	At time.Time
}

// Validate checks the transition's shape before any store work.
func (t Transition) Validate() error {
	if !CanTransition(t.From, t.To) {
		return fmt.Errorf("%w: %s -> %s", ErrIllegalTransition, t.From, t.To)
	}
	if t.ExpectRevision <= 0 {
		return fmt.Errorf("%w: expected revision must be positive", ErrInvalidTransition)
	}
	confirm := t.To == StatePendingConfirm
	if confirm != (t.AccountID != "") || confirm != (t.GrantedScope != "") || confirm != (len(t.SealedTokens) > 0) {
		return fmt.Errorf("%w: account, scope and tokens are set exactly on pending_confirm", ErrInvalidTransition)
	}
	if (t.To == StatePendingReturn) != (len(t.SealedCode) > 0) {
		return fmt.Errorf("%w: the authorization code is set exactly on pending_return", ErrInvalidTransition)
	}
	return nil
}

// Rotation replaces the sealed tokens of an active connection after a
// refresh. The store applies it only if the row is still active at
// ExpectRevision and ExpectGeneration, still has GrantedScope, and is leased
// to LeaseOwner with a lease that has not ended at Now. It bumps
// TokenGeneration, never AuthorityRevision, and releases the lease.
type Rotation struct {
	ExpectRevision   int64
	ExpectGeneration int64
	GrantedScope     string
	LeaseOwner       string
	SealedTokens     []byte
	// Now is the manager's clock at the store write; the lease must end
	// after it. It is the same clock that set the lease, so the check does
	// not depend on how this replica's clock compares with the database's.
	Now time.Time
}

// Errors. None carries a token, a scope value from a server or a user value.
var (
	// ErrNotFound: no row for (principal, id). A row of another principal is
	// reported exactly like a missing row.
	ErrNotFound = errors.New("pa connection: not found")
	// ErrConflict: the compare-and-set lost (state, revision, generation or
	// lease moved).
	ErrConflict = errors.New("pa connection: concurrent change")
	// ErrIllegalTransition: the edge is not in the state machine.
	ErrIllegalTransition = errors.New("pa connection: illegal state transition")
	// ErrInvalidTransition: the edge is legal but its fields are not.
	ErrInvalidTransition = errors.New("pa connection: invalid transition fields")
	// ErrUnreadable: the row, or its secret material, could not be read.
	// Never treated as active (I9, S1-C5).
	ErrUnreadable = errors.New("pa connection: unreadable")
	// ErrNoConsent: activation (pending_confirm -> active) found no
	// current data-flow consent for the principal, read under the
	// principal's lock in the activating transaction. The connection is
	// left pending; the caller fails it and revokes its tokens.
	ErrNoConsent = errors.New("pa connection: no current consent")
	// ErrNotActive: the connection is in a state that refuses every call.
	ErrNotActive = errors.New("pa connection: not active")
	// ErrRevisionMismatch: the connection moved past the bound revision.
	ErrRevisionMismatch = errors.New("pa connection: authority revision changed")
	// ErrScopeMismatch: the effective scope is not exactly the allowed set.
	ErrScopeMismatch = errors.New("pa connection: effective scope is not the allowed set")
	// ErrTokenResponse: a token response could not be parsed.
	ErrTokenResponse = errors.New("pa connection: malformed token response")
	// ErrFenced: a result arrived after the connection changed; it is
	// discarded.
	ErrFenced = errors.New("pa connection: result fenced")
	// ErrRefreshInProgress: another replica holds the refresh lease.
	ErrRefreshInProgress = errors.New("pa connection: refresh in progress elsewhere")
	// ErrInvalidGrant and ErrRefreshTokenReuse are what a RefreshFunc wraps
	// when the authorization server answers invalid_grant or reports reuse
	// of a refresh token.
	ErrInvalidGrant      = errors.New("pa connection: invalid_grant")
	ErrRefreshTokenReuse = errors.New("pa connection: refresh token reuse detected")
	// ErrTooManyPending: the principal already has MaxPendingConnections
	// connections in a pending_* state (threat model T10).
	ErrTooManyPending = errors.New("pa connection: too many connections being linked")
	// ErrPrincipalDisabled: activation (pending_confirm -> active) found
	// the principal disabled by an admin, or could not read whether it is,
	// under the principal's lock in the activating transaction. The
	// connection is left pending; the caller fails it and revokes its
	// tokens (#1318).
	ErrPrincipalDisabled = errors.New("pa connection: principal disabled")
	// ErrNoRefreshToken: the server rejected the access token and the
	// connection holds no refresh token, so only a new /connect can make it
	// usable again. The connection is moved to expired.
	ErrNoRefreshToken = errors.New("pa connection: no refresh token")
	// ErrRefreshUnavailable: no refresh-token grant is configured.
	ErrRefreshUnavailable = errors.New("pa connection: refresh not configured")
	// ErrRefreshFailed wraps a refresh-token grant that failed for any
	// reason other than invalid_grant or reported reuse (the network, the
	// server, a timeout). The connection is unchanged; only the call that
	// needed the refresh fails, and nothing retries it.
	ErrRefreshFailed = errors.New("pa connection: refresh failed")
	// ErrExpired is ErrNotActive for a connection in state expired: the
	// service stopped accepting it, and only a new /connect helps. It
	// wraps ErrNotActive, so every check for "not active" still refuses.
	ErrExpired = fmt.Errorf("%w: connection expired", ErrNotActive)
	// ErrPrincipalDeleted: the principal's account was deleted after this
	// Begin was admitted, so it may not create a connection (#1338).
	ErrPrincipalDeleted = errors.New("pa connection: the account was deleted")
)

// MaxPendingConnections is the per-principal cap on connections in a
// pending_* state (threat model T10, #1338). Each Begin wraps a fresh DEK
// with the KEK, which may be a Vault Transit call, and each pending row lives
// up to the linking sweep's PendingMaxAge, so without a cap a principal
// could have the server wrap keys and keep rows without bound. Three covers
// a link attempt per catalog server plus one retry; a principal that hits it
// waits for an attempt to finish or for the sweep to fail it.
const MaxPendingConnections = 3

// Admission is a store's permission for one Begin, read before the KEK wrap
// (Store.AdmitPAConnection) and checked again when the row is created
// (Store.CreatePAConnection). Its fields belong to the store; the manager
// only passes it along.
type Admission struct {
	// PurgeMark is the principal's account-deletion mark when admitted.
	PurgeMark int64
	// ReadAt is when the store admitted the Begin, on the store's clock.
	ReadAt time.Time
}
