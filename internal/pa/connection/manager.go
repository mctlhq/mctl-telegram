package connection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Store is the persistent connection store. internal/db.Store implements it.
// Every method is keyed by (principal, id); a row of another principal is
// ErrNotFound. A failed read is an error, never a zero Connection.
type Store interface {
	// AdmitPAConnection decides whether principal may begin a connection:
	// ErrTooManyPending when it has MaxPendingConnections pending ones. A
	// failed read is an error, never an admission.
	AdmitPAConnection(ctx context.Context, principal int64) (Admission, error)
	// CreatePAConnection inserts a new pending_link row under the
	// principal's lock, after checking again in the same transaction that
	// the cap holds (ErrTooManyPending) and that the principal's account was
	// not deleted since a was issued (ErrPrincipalDeleted).
	CreatePAConnection(ctx context.Context, c Connection, s Sealed, a Admission) error
	GetPAConnection(ctx context.Context, principal int64, id string) (Connection, error)
	GetPAConnectionSealed(ctx context.Context, principal int64, id string) (Connection, Sealed, error)
	ListPAConnections(ctx context.Context, principal int64) ([]Connection, error)
	// TransitionPAConnection applies t by compare-and-set and returns the
	// row after it. ErrNotFound, ErrConflict, ErrIllegalTransition and
	// ErrInvalidTransition as documented on Transition. The activation
	// edge is applied as ActivatePAConnection, every check included.
	// Moving a row from active to expired also queues, in the same
	// transaction, the one "link it again" notice that transition owes.
	TransitionPAConnection(ctx context.Context, principal int64, id string, t Transition) (Connection, error)
	// ActivatePAConnection applies the pending_confirm -> active edge t. In
	// one transaction, under the principal's lock, it requires a current
	// consent (ErrNoConsent) and a principal that is not disabled
	// (ErrPrincipalDisabled; an unreadable disable refuses too), and then
	// revokes every other active or expired connection of the principal on
	// the same server: a reconnect never leaves two connections a run
	// could bind. It returns the superseded rows with their secret
	// material as it was just before, for remote revocation.
	ActivatePAConnection(ctx context.Context, principal int64, id string, t Transition) (Connection, []Superseded, error)
	// RevokePAConnection moves the row to revoked from whatever state it is
	// in, bumps the revision and destroys every sealed secret, in one
	// transaction. It returns the row after the change and the secret
	// material as it was just before, so the caller can still revoke the
	// token remotely. A row already revoked returns alreadyRevoked=true and
	// changes nothing.
	RevokePAConnection(ctx context.Context, principal int64, id, reason string) (c Connection, before Sealed, alreadyRevoked bool, err error)
	// RevokePAConnectionAt is RevokePAConnection for one known row version:
	// it changes the row only while it is still at revision and generation,
	// and is ErrConflict otherwise. A row already revoked is ErrConflict too.
	RevokePAConnectionAt(ctx context.Context, principal int64, id string, revision, generation int64, reason string) (Connection, error)
	// ClaimPAConnectionRefresh takes the refresh lease of an active row at
	// generation for owner until until, if no unexpired lease is held. It
	// reports whether the lease was taken.
	ClaimPAConnectionRefresh(ctx context.Context, principal int64, id string, generation int64, owner string, now, until time.Time) (bool, error)
	// ReleasePAConnectionRefresh drops owner's lease, if it still holds it.
	ReleasePAConnectionRefresh(ctx context.Context, principal int64, id, owner string) error
	// RotatePAConnectionTokens applies r by compare-and-set.
	RotatePAConnectionTokens(ctx context.Context, principal int64, id string, r Rotation) (Connection, error)
}

// Superseded is a connection an activation on the same server revoked,
// with its secret material as it was before (see ActivatePAConnection).
type Superseded struct {
	Connection Connection
	Before     Sealed
}

// TokenHint is the RFC 7009 token_type_hint of a revocation.
type TokenHint string

const (
	HintAccessToken  TokenHint = "access_token"
	HintRefreshToken TokenHint = "refresh_token"
)

// Revoker calls a server's token revocation endpoint (RFC 7009). It is
// best-effort from the store's point of view: local revocation never waits
// for it and never depends on it.
type Revoker interface {
	Revoke(ctx context.Context, server Server, token Secret, hint TokenHint) error
}

// FenceEvent is one discarded late result (threat model T2, T12 status
// "fenced"). It carries ids and a reason code, never a result body.
type FenceEvent struct {
	Principal     int64
	ConnectionID  string
	Server        Server
	BoundRevision int64
	// Reason is "revision_changed", "not_active" or "unreadable".
	Reason string
}

// FenceAuditor records fenced results. The hash-chained audit wiring is
// #1315's; this is the seam.
type FenceAuditor interface {
	RecordFenced(ctx context.Context, ev FenceEvent) error
}

// RefreshFunc performs the refresh-token grant against the server and
// returns the raw token response. It wraps ErrInvalidGrant or
// ErrRefreshTokenReuse when the server says so; any other error is
// transient.
type RefreshFunc func(ctx context.Context, server Server, refreshToken Secret) ([]byte, error)

// Config builds a Manager. Store, KEK, Revoker and Auditor are required.
type Config struct {
	Store   Store
	KEK     KEK
	Revoker Revoker
	Auditor FenceAuditor
	// Now defaults to time.Now.
	Now func() time.Time
	// RefreshLease bounds how long one replica may hold the refresh lease.
	// Default 60s.
	RefreshLease time.Duration
	// Refresh is the refresh-token grant AccessToken and RefreshAccess use
	// (#1318 slice C2b). Nil: no connection is ever refreshed, AccessToken
	// hands out the stored token until the server rejects it, and
	// RefreshAccess is ErrRefreshUnavailable.
	Refresh RefreshFunc
}

// RefreshAhead is how long before its known expiry an access token is
// refreshed instead of used (#1318 slice C2b).
const RefreshAhead = 60 * time.Second

// Manager is the connection logic over a Store. It is safe for concurrent
// use. One Manager per process: its single-flight group and its in-flight
// call registry are per process, and the store's refresh lease covers other
// replicas.
type Manager struct {
	store   Store
	kek     KEK
	revoker Revoker
	auditor FenceAuditor
	now     func() time.Time
	lease   time.Duration
	owner   string
	grant   RefreshFunc

	refreshes singleflight.Group

	mu       sync.Mutex
	inflight map[string]map[*Call]context.CancelFunc
}

// NewManager validates cfg.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.Store == nil || cfg.KEK == nil || cfg.Revoker == nil || cfg.Auditor == nil {
		return nil, errors.New("pa connection: manager needs a store, a KEK, a revoker and an auditor")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	lease := cfg.RefreshLease
	if lease <= 0 {
		lease = 60 * time.Second
	}
	owner, err := randomID("lease_")
	if err != nil {
		return nil, err
	}
	return &Manager{
		store: cfg.Store, kek: cfg.KEK, revoker: cfg.Revoker, auditor: cfg.Auditor,
		now: now, lease: lease, owner: owner, grant: cfg.Refresh,
		inflight: map[string]map[*Call]context.CancelFunc{},
	}, nil
}

func randomID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("pa connection: random id: %w", err)
	}
	return prefix + hex.EncodeToString(b), nil
}

func validPrincipal(p int64) error {
	if p <= 0 {
		return errors.New("pa connection: principal must be a positive Telegram id")
	}
	return nil
}

// readErr turns a store read error into what a gate acts on: ErrNotFound
// stays ErrNotFound; anything else is ErrUnreadable. Neither is "active".
func readErr(err error) error {
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnreadable) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrUnreadable, err)
}

// Begin creates a new connection in pending_link with its own DEK. Every
// link attempt, every reconnect and every scope escalation calls Begin and
// gets a new id (S1-C8); no method re-activates an existing row.
//
// The store admits the Begin before the KEK wrap, so a principal at
// MaxPendingConnections costs no wrap (T10), and checks again when it
// creates the row, under the principal's lock: concurrent Begins cannot
// both pass the cap, and a Begin admitted before an account deletion
// cannot leave a row after it (ErrPrincipalDeleted, #1338). Begin takes
// the principal lock itself, so it must not be called while the caller's
// transaction holds that lock: it would wait for itself until ctx ends.
func (m *Manager) Begin(ctx context.Context, principal int64, server Server) (Connection, error) {
	if err := validPrincipal(principal); err != nil {
		return Connection{}, err
	}
	if !server.Valid() {
		return Connection{}, errors.New("pa connection: unknown server")
	}
	adm, err := m.store.AdmitPAConnection(ctx, principal)
	if err != nil {
		return Connection{}, fmt.Errorf("pa connection: admit: %w", err)
	}
	id, err := randomID("pac_")
	if err != nil {
		return Connection{}, err
	}
	dek, err := newDEK()
	if err != nil {
		return Connection{}, err
	}
	defer zero(dek)
	wrapped, err := m.kek.Wrap(ctx, dek)
	if err != nil {
		return Connection{}, fmt.Errorf("pa connection: wrap dek: %w", err)
	}
	now := m.now().UTC()
	c := Connection{
		ID: id, Principal: principal, Server: server, State: StatePendingLink,
		AuthorityRevision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := m.store.CreatePAConnection(ctx, c, Sealed{KEKID: m.kek.ID(), WrappedDEK: wrapped}, adm); err != nil {
		return Connection{}, fmt.Errorf("pa connection: create: %w", err)
	}
	return c, nil
}

// Get returns the principal's connection. ErrNotFound for another
// principal's.
func (m *Manager) Get(ctx context.Context, principal int64, id string) (Connection, error) {
	c, err := m.store.GetPAConnection(ctx, principal, id)
	if err != nil {
		return Connection{}, readErr(err)
	}
	return c, nil
}

// List returns the principal's connections only.
func (m *Manager) List(ctx context.Context, principal int64) ([]Connection, error) {
	cs, err := m.store.ListPAConnections(ctx, principal)
	if err != nil {
		return nil, readErr(err)
	}
	return cs, nil
}

// StartOAuth moves pending_link -> pending_oauth.
func (m *Manager) StartOAuth(ctx context.Context, principal int64, id string, expectRevision int64) (Connection, error) {
	return m.transition(ctx, principal, id, Transition{
		From: StatePendingLink, To: StatePendingOAuth, ExpectRevision: expectRevision,
	})
}

// StoreAuthorizationCode seals the unexchanged code under the connection's
// DEK and moves pending_oauth -> pending_return (threat model T1 step 3).
func (m *Manager) StoreAuthorizationCode(ctx context.Context, principal int64, id string, expectRevision int64, code Secret) (Connection, error) {
	if code.Empty() {
		return Connection{}, fmt.Errorf("%w: empty authorization code", ErrInvalidTransition)
	}
	c, s, err := m.store.GetPAConnectionSealed(ctx, principal, id)
	if err != nil {
		return Connection{}, readErr(err)
	}
	dek, err := m.unwrap(ctx, s)
	if err != nil {
		return Connection{}, err
	}
	defer zero(dek)
	blob, err := sealWithDEK(dek, []byte(code.Reveal()), aad(c.Principal, c.ID, purposeCode))
	if err != nil {
		return Connection{}, err
	}
	return m.transition(ctx, principal, id, Transition{
		From: StatePendingOAuth, To: StatePendingReturn, ExpectRevision: expectRevision, SealedCode: blob,
	})
}

// AuthorizationCode opens the code stored by StoreAuthorizationCode. Only a
// pending_return connection has one.
func (m *Manager) AuthorizationCode(ctx context.Context, principal int64, id string) (Secret, error) {
	c, s, err := m.store.GetPAConnectionSealed(ctx, principal, id)
	if err != nil {
		return Secret{}, readErr(err)
	}
	if c.State != StatePendingReturn || len(s.SealedCode) == 0 {
		return Secret{}, fmt.Errorf("%w: no stored authorization code", ErrNotActive)
	}
	dek, err := m.unwrap(ctx, s)
	if err != nil {
		return Secret{}, err
	}
	defer zero(dek)
	pt, err := openWithDEK(dek, s.SealedCode, aad(c.Principal, c.ID, purposeCode))
	if err != nil {
		return Secret{}, err
	}
	return NewSecret(string(pt)), nil
}

// AccountResolver reads the stable account identifier of a freshly issued
// token from the server's pinned source (threat model T1 step 4) and, where
// the server can prove it, checks that the account belongs to the principal
// (T1 step 6, S1-L13). It runs after the scope check and before anything is
// stored. Any error, or an empty id, fails the connection and revokes the
// issued tokens; the connection never reaches pending_confirm.
type AccountResolver func(ctx context.Context, server Server, tokens TokenSet) (accountID string, err error)

// CompleteExchange is CompleteExchangeWith for a caller that already knows
// the stable account id.
func (m *Manager) CompleteExchange(ctx context.Context, principal int64, id string, expectRevision int64, accountID string, tokenResponse []byte) (Connection, error) {
	return m.CompleteExchangeWith(ctx, principal, id, expectRevision, tokenResponse,
		func(context.Context, Server, TokenSet) (string, error) { return accountID, nil })
}

// CompleteExchangeWith records the result of the code exchange (threat
// model T1 step 4): pending_return -> pending_confirm with the stable
// account id, the granted scope and the sealed tokens.
//
//   - Before anything is stored, the effective scope must equal the allowed
//     set (T8, S1-T9). A failure moves the connection to failed and revokes
//     what the server issued; the error wraps ErrScopeMismatch or
//     ErrTokenResponse.
//   - Then resolve reads the account id with the new tokens. Its error, or
//     an empty id, also fails the connection and revokes the tokens (S1-L13).
//   - If the connection left pending_return meanwhile (ErrConflict), or the
//     final store write fails, the issued tokens are revoked and never
//     stored.
//   - Only when the row cannot be read at all (ErrUnreadable, ErrNotFound)
//     is the server unknown here. The caller must then revoke the response
//     itself with RevokeTokenResponse; the linking flow does.
func (m *Manager) CompleteExchangeWith(ctx context.Context, principal int64, id string, expectRevision int64, tokenResponse []byte, resolve AccountResolver) (Connection, error) {
	if resolve == nil {
		return Connection{}, errors.New("pa connection: exchange needs an account resolver")
	}
	// The response has just been received: its expires_in counts from
	// here, not from when the tokens are sealed below.
	received := m.now()
	c, s, err := m.store.GetPAConnectionSealed(ctx, principal, id)
	if err != nil {
		return Connection{}, readErr(err)
	}
	check := VerifyTokenResponse(c.Server, tokenResponse)
	check.Tokens = check.Tokens.receivedAt(received)
	if c.State != StatePendingReturn || c.AuthorityRevision != expectRevision {
		// The connection moved (for example a /disconnect) while the code was
		// being exchanged: what the server issued is never stored, and is
		// revoked.
		return Connection{}, errors.Join(
			fmt.Errorf("%w: exchange needs pending_return at the expected revision", ErrConflict),
			m.revokeTokens(ctx, c.Server, check.Tokens))
	}
	if check.Err != nil {
		return m.failAndRevoke(ctx, c, check.Tokens, "exchange_scope_check", check.Err)
	}
	accountID, err := resolve(ctx, c.Server, check.Tokens)
	if err == nil && accountID == "" {
		err = fmt.Errorf("%w: no stable account id", ErrTokenResponse)
	}
	if err != nil {
		return m.failAndRevoke(ctx, c, check.Tokens, "exchange_account_check", err)
	}
	dek, err := m.unwrap(ctx, s)
	if err != nil {
		return m.failAndRevoke(ctx, c, check.Tokens, "exchange_unseal", err)
	}
	defer zero(dek)
	blob, err := m.sealTokens(dek, c, check.Tokens)
	if err != nil {
		return m.failAndRevoke(ctx, c, check.Tokens, "exchange_seal", err)
	}
	out, err := m.transition(ctx, principal, id, Transition{
		From: StatePendingReturn, To: StatePendingConfirm, ExpectRevision: expectRevision,
		AccountID: accountID, GrantedScope: check.Granted, SealedTokens: blob,
	})
	if err != nil {
		// Not stored, so never usable by MCTL; revoke it at the server too.
		return Connection{}, errors.Join(err, m.revokeTokens(ctx, c.Server, check.Tokens))
	}
	return out, nil
}

// RevokeTokenResponse revokes, best-effort, every token in a raw token
// response at server. It is the caller's half of the CompleteExchange
// contract: when the row could not be read, the manager does not know the
// server, so the caller that does revokes what was issued. A response that
// carries no usable access token revokes nothing and returns nil.
func (m *Manager) RevokeTokenResponse(ctx context.Context, server Server, tokenResponse []byte) error {
	if !server.Valid() {
		return errors.New("pa connection: revoke for an unknown server")
	}
	return m.revokeTokens(ctx, server, VerifyTokenResponse(server, tokenResponse).Tokens)
}

// Confirm moves pending_confirm -> active. The callback_query check (from.id
// == principal within 10 minutes) is the linking slice's; this is the store
// edge it ends in.
//
// Any other active or expired connection of the principal on the same
// server is revoked in the same transaction (ActivatePAConnection), so a
// /connect next to a dead connection leaves exactly one a run can bind.
// The superseded connections' in-flight calls are cancelled and their
// tokens revoked at the server, best-effort: a remote failure is logged
// and does not undo the activation.
func (m *Manager) Confirm(ctx context.Context, principal int64, id string, expectRevision int64) (Connection, error) {
	out, superseded, err := m.store.ActivatePAConnection(ctx, principal, id, Transition{
		From: StatePendingConfirm, To: StateActive, ExpectRevision: expectRevision, At: m.now().UTC(),
	})
	if err != nil {
		return Connection{}, err
	}
	for _, old := range superseded {
		m.cancelInflight(old.Connection.ID)
		if len(old.Before.SealedTokens) == 0 {
			continue
		}
		ts, err := m.openTokens(ctx, old.Connection, old.Before)
		if err == nil {
			err = m.revokeTokens(ctx, old.Connection.Server, ts)
		}
		if err != nil {
			slog.Warn("pa connection: superseded connection not revoked at the server",
				"server", string(old.Connection.Server), "err", err)
		}
	}
	return out, nil
}

// Fail moves a non-terminal connection to failed.
func (m *Manager) Fail(ctx context.Context, principal int64, id string, expectRevision int64, reason string) (Connection, error) {
	c, err := m.store.GetPAConnection(ctx, principal, id)
	if err != nil {
		return Connection{}, readErr(err)
	}
	return m.transition(ctx, principal, id, Transition{
		From: c.State, To: StateFailed, ExpectRevision: expectRevision, Reason: reason,
	})
}

// Abandon moves a pending_* connection still at expectRevision to failed
// and revokes, best-effort, any tokens it already holds (an unanswered or
// expired confirm card, T1 step 5). The local move happens first and never
// waits for the remote revocation; a remote failure is reported in
// RemoteErr. A connection that moved on is ErrConflict and is left alone.
func (m *Manager) Abandon(ctx context.Context, principal int64, id string, expectRevision int64, reason string) (DisconnectResult, error) {
	c, s, err := m.store.GetPAConnectionSealed(ctx, principal, id)
	if err != nil {
		return DisconnectResult{}, readErr(err)
	}
	if !c.State.Pending() || c.AuthorityRevision != expectRevision {
		return DisconnectResult{}, fmt.Errorf("%w: abandon needs a pending connection at the expected revision", ErrConflict)
	}
	var ts TokenSet
	var openErr error
	if len(s.SealedTokens) > 0 {
		ts, openErr = m.openTokens(ctx, c, s)
	}
	out, err := m.transition(ctx, principal, id, Transition{
		From: c.State, To: StateFailed, ExpectRevision: expectRevision, Reason: reason,
	})
	if err != nil {
		return DisconnectResult{}, err
	}
	res := DisconnectResult{Connection: out}
	if openErr != nil {
		res.RemoteErr = fmt.Errorf("pa connection: tokens for remote revocation: %w", openErr)
		return res, nil
	}
	res.RemoteErr = m.revokeTokens(ctx, c.Server, ts)
	return res, nil
}

// failAndRevoke moves c to failed and revokes the tokens a server issued
// under a response that did not pass the check. It always returns cause
// (joined with any store error): the caller must not proceed.
func (m *Manager) failAndRevoke(ctx context.Context, c Connection, issued TokenSet, reason string, cause error) (Connection, error) {
	_, terr := m.transition(ctx, c.Principal, c.ID, Transition{
		From: c.State, To: StateFailed, ExpectRevision: c.AuthorityRevision, Reason: reason,
	})
	rerr := m.revokeTokens(ctx, c.Server, issued)
	out, gerr := m.store.GetPAConnection(ctx, c.Principal, c.ID)
	if gerr != nil {
		out = Connection{}
	}
	return out, errors.Join(cause, terr, rerr)
}

func (m *Manager) revokeTokens(ctx context.Context, server Server, ts TokenSet) error {
	var errs []error
	if !ts.RefreshToken.Empty() {
		if err := m.revoker.Revoke(ctx, server, ts.RefreshToken, HintRefreshToken); err != nil {
			errs = append(errs, fmt.Errorf("pa connection: remote revoke refresh token: %w", err))
		}
	}
	if !ts.AccessToken.Empty() {
		if err := m.revoker.Revoke(ctx, server, ts.AccessToken, HintAccessToken); err != nil {
			errs = append(errs, fmt.Errorf("pa connection: remote revoke access token: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) unwrap(ctx context.Context, s Sealed) ([]byte, error) {
	if len(s.WrappedDEK) == 0 {
		return nil, fmt.Errorf("%w: no wrapped dek", ErrUnreadable)
	}
	if s.KEKID != m.kek.ID() {
		return nil, fmt.Errorf("%w: dek wrapped under another kek", ErrUnreadable)
	}
	dek, err := m.kek.Unwrap(ctx, s.WrappedDEK)
	if err != nil {
		return nil, readErr(err)
	}
	return dek, nil
}

func (m *Manager) sealTokens(dek []byte, c Connection, ts TokenSet) ([]byte, error) {
	pt, err := ts.marshal()
	if err != nil {
		return nil, fmt.Errorf("pa connection: marshal tokens: %w", err)
	}
	defer zero(pt)
	return sealWithDEK(dek, pt, aad(c.Principal, c.ID, purposeTokens))
}

func (m *Manager) openTokens(ctx context.Context, c Connection, s Sealed) (TokenSet, error) {
	if len(s.SealedTokens) == 0 {
		return TokenSet{}, fmt.Errorf("%w: no sealed tokens", ErrUnreadable)
	}
	dek, err := m.unwrap(ctx, s)
	if err != nil {
		return TokenSet{}, err
	}
	defer zero(dek)
	return openTokensWithDEK(dek, c, s)
}

func openTokensWithDEK(dek []byte, c Connection, s Sealed) (TokenSet, error) {
	if len(s.SealedTokens) == 0 {
		return TokenSet{}, fmt.Errorf("%w: no sealed tokens", ErrUnreadable)
	}
	pt, err := openWithDEK(dek, s.SealedTokens, aad(c.Principal, c.ID, purposeTokens))
	if err != nil {
		return TokenSet{}, err
	}
	defer zero(pt)
	return unmarshalTokenSet(pt)
}

// gate is the I4 check on a row already read: active and at the bound
// revision. Any other state, including an unknown one, refuses.
func gate(c Connection, boundRevision int64) error {
	if c.State == StateExpired {
		return ErrExpired
	}
	if c.State != StateActive {
		return fmt.Errorf("%w: state %s", ErrNotActive, c.State)
	}
	if c.AuthorityRevision != boundRevision {
		return ErrRevisionMismatch
	}
	return nil
}

// Authorize is the read gate the executor calls before every dispatch
// (threat model T2 step 1, I4). It re-reads the row and refuses every state
// but active (S1-C1), a revision other than the bound one (S1-C2), and an
// unreadable row (S1-C5). It never returns a Connection with a nil error
// unless that connection is active at boundRevision.
func (m *Manager) Authorize(ctx context.Context, principal int64, id string, boundRevision int64) (Connection, error) {
	c, err := m.store.GetPAConnection(ctx, principal, id)
	if err != nil {
		return Connection{}, readErr(err)
	}
	if err := gate(c, boundRevision); err != nil {
		return Connection{}, err
	}
	return c, nil
}

// AccessToken passes the gate and opens the connection's access token for
// one outbound call. A token rotation does not change the revision, so a
// run bound before a refresh keeps working after it (S1-C3).
//
// A token whose known expiry is less than RefreshAhead away is refreshed
// first (#1318 slice C2b), through Refresh: concurrent calls share one
// flight, and a flight is skipped when the generation it was asked for is
// already gone. A refresh ahead that fails transiently, or whose lease
// another replica holds, is not retried here; while the current token has
// not yet expired it is still handed out (re-read and re-gated), since
// the 401 path covers it if the server disagrees. Past its expiry, or on
// any other failure (invalid_grant included), the call fails. An unknown
// expiry is not refreshed ahead, and neither is a set without a refresh
// token: both are used until the server rejects them (RefreshAccess).
func (m *Manager) AccessToken(ctx context.Context, principal int64, id string, boundRevision int64) (Secret, Connection, error) {
	token, c, ts, err := m.openAccess(ctx, principal, id, boundRevision)
	if err != nil {
		return Secret{}, Connection{}, err
	}
	if m.grant == nil || ts.ExpiresAt.IsZero() || ts.RefreshToken.Empty() || m.now().Before(ts.ExpiresAt.Add(-RefreshAhead)) {
		return token, c, nil
	}
	if _, err := m.refreshFrom(ctx, principal, id, m.grant, c.TokenGeneration); err != nil {
		if !refreshAheadTransient(err) || !m.now().Before(ts.ExpiresAt) {
			return Secret{}, Connection{}, err
		}
		// Still valid: use it, as the store has it now.
		slog.Warn("pa connection: refresh ahead failed, using the unexpired token",
			"server", string(c.Server), "err", err)
	}
	token, c, _, err = m.openAccess(ctx, principal, id, boundRevision)
	if err != nil {
		return Secret{}, Connection{}, err
	}
	return token, c, nil
}

// refreshAheadTransient reports whether a failed refresh ahead left the
// connection as it was: another replica holds the lease, or the grant
// failed for a reason other than invalid_grant. An expiry that could not
// be recorded joins ErrRefreshFailed with ErrInvalidGrant and is not
// transient: the grant is dead.
func refreshAheadTransient(err error) bool {
	return (errors.Is(err, ErrRefreshInProgress) || errors.Is(err, ErrRefreshFailed)) &&
		!errors.Is(err, ErrInvalidGrant)
}

// openAccess is AccessToken without the refresh ahead.
func (m *Manager) openAccess(ctx context.Context, principal int64, id string, boundRevision int64) (Secret, Connection, TokenSet, error) {
	c, s, err := m.store.GetPAConnectionSealed(ctx, principal, id)
	if err != nil {
		return Secret{}, Connection{}, TokenSet{}, readErr(err)
	}
	if err := gate(c, boundRevision); err != nil {
		return Secret{}, Connection{}, TokenSet{}, err
	}
	ts, err := m.openTokens(ctx, c, s)
	if err != nil {
		return Secret{}, Connection{}, TokenSet{}, err
	}
	return ts.AccessToken, c, ts, nil
}

// RefreshAccess is the 401 path (#1318 slice C2b): the server rejected the
// access token of generation rejected, so the connection's tokens are
// refreshed and the new access token is returned for exactly one retry.
//
//   - If the connection already moved past rejected (another call
//     refreshed it meanwhile), its current token is returned and nothing
//     is refreshed: concurrent rejections do one refresh, not one each.
//   - A connection without a refresh token cannot recover: it moves to
//     expired (which queues the "link it again" notice) and the result
//     wraps ErrNoRefreshToken.
//   - invalid_grant moves it to expired the same way (Refresh); reported
//     reuse revokes it.
//   - Any other refresh failure, ErrRefreshInProgress included, fails
//     this call only. Nothing retries.
func (m *Manager) RefreshAccess(ctx context.Context, principal int64, id string, boundRevision, rejected int64) (Secret, Connection, error) {
	if m.grant == nil {
		return Secret{}, Connection{}, ErrRefreshUnavailable
	}
	token, c, ts, err := m.openAccess(ctx, principal, id, boundRevision)
	if err != nil {
		return Secret{}, Connection{}, err
	}
	if c.TokenGeneration != rejected {
		return token, c, nil
	}
	if ts.RefreshToken.Empty() {
		if _, terr := m.transition(ctx, principal, id, Transition{
			From: StateActive, To: StateExpired, ExpectRevision: c.AuthorityRevision, Reason: "access_token_rejected",
		}); terr != nil {
			// Not recorded as expired, so not reported as expired.
			return Secret{}, Connection{}, errors.Join(ErrRefreshFailed, terr)
		}
		return Secret{}, Connection{}, ErrNoRefreshToken
	}
	if _, err := m.refreshFrom(ctx, principal, id, m.grant, rejected); err != nil {
		return Secret{}, Connection{}, err
	}
	token, c, _, err = m.openAccess(ctx, principal, id, boundRevision)
	if err != nil {
		return Secret{}, Connection{}, err
	}
	return token, c, nil
}

// Refresh rotates an active connection's tokens (threat model T2 Refresh).
//
//   - Single-flight: concurrent calls in this process share one refresh,
//     and a store lease keeps other replicas from presenting the same
//     refresh token (ErrRefreshInProgress) (S1-C4).
//   - invalid_grant moves the connection to expired; reported reuse revokes
//     it. Neither falls back to an older token.
//   - The new response must carry exactly the allowed scope, the same as the
//     stored grant. A wider (or otherwise different) scope fails the
//     connection and revokes the new tokens (S1-T10).
//   - Only TokenGeneration moves; AuthorityRevision does not.
//   - If the connection changed while the refresh was on the wire, the new
//     tokens are revoked and discarded (ErrFenced).
//   - The flight is detached from every caller: once the server has rotated
//     the tokens, storing (or revoking) them must not depend on whether the
//     caller that started the flight is still waiting. A cancelled caller
//     stops waiting and gets its ctx error; the flight runs to the end.
//   - One clock (m.now) times the whole flight. fn runs under a deadline
//     that ends a quarter lease before the lease does, so another replica
//     cannot take the lease and present the same refresh token while this
//     one is still on the wire. The steps after fn reuse the DEK opened
//     before it (no second KEK round trip) and are bounded by the lease end:
//     the rotation is stored only while the lease is still held by that
//     clock, and the store re-checks the lease end in the same CAS. Past it,
//     the issued tokens are revoked and the result is ErrFenced.
func (m *Manager) Refresh(ctx context.Context, principal int64, id string, fn RefreshFunc) (Connection, error) {
	return m.refreshFrom(ctx, principal, id, fn, anyGeneration)
}

// anyGeneration asks refreshFrom to rotate whatever generation is stored.
const anyGeneration = -1

// refreshFrom is Refresh for the tokens of generation from: a flight that
// finds the connection already past from (another flight, here or on
// another replica, rotated it after the caller read it) returns the
// current row without calling fn. So a caller that read generation G
// never causes a second rotation once G is gone (#1318 C2b review).
func (m *Manager) refreshFrom(ctx context.Context, principal int64, id string, fn RefreshFunc, from int64) (Connection, error) {
	key := strconv.FormatInt(principal, 10) + "|" + id
	ch := m.refreshes.DoChan(key, func() (any, error) {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), flightBound*m.lease)
		defer cancel()
		return m.refresh(fctx, principal, id, fn, from)
	})
	select {
	case r := <-ch:
		if r.Err != nil {
			return Connection{}, r.Err
		}
		return r.Val.(Connection), nil
	case <-ctx.Done():
		return Connection{}, ctx.Err()
	}
}

// flightBound caps a whole refresh flight at this many leases: the call
// itself ends before one lease is up, the rest is store writes and remote
// revocation of what could not be stored.
const flightBound = 3

// callBudget is how long fn may take: the lease minus a margin left for
// storing the rotation before the lease runs out.
func (m *Manager) callBudget() time.Duration {
	return m.lease - m.lease/4
}

// untilByClock converts an instant on m.now's clock into a duration from
// m.now's present, so every deadline in a refresh flight comes from that one
// clock even though contexts count it down on the wall clock.
func (m *Manager) untilByClock(t time.Time) time.Duration {
	return t.Sub(m.now())
}

func (m *Manager) refresh(ctx context.Context, principal int64, id string, fn RefreshFunc, from int64) (Connection, error) {
	c, s, err := m.store.GetPAConnectionSealed(ctx, principal, id)
	if err != nil {
		return Connection{}, readErr(err)
	}
	if err := gate(c, c.AuthorityRevision); err != nil {
		return Connection{}, err
	}
	if from != anyGeneration && c.TokenGeneration != from {
		// Already rotated past the caller's tokens: nothing to do. The
		// lease claim below is a CAS on the generation read here, so a
		// rotation committed after this read is caught there instead.
		return c, nil
	}
	now := m.now().UTC()
	leaseEnd := now.Add(m.lease)
	ok, err := m.store.ClaimPAConnectionRefresh(ctx, principal, id, c.TokenGeneration, m.owner, now, leaseEnd)
	if err != nil {
		return Connection{}, readErr(err)
	}
	if !ok {
		return Connection{}, ErrRefreshInProgress
	}
	release := func() { _ = m.store.ReleasePAConnectionRefresh(context.WithoutCancel(ctx), principal, id, m.owner) }

	if len(s.SealedTokens) == 0 {
		release()
		return Connection{}, fmt.Errorf("%w: no sealed tokens", ErrUnreadable)
	}
	// The DEK is opened once, before the call, and reused to seal the
	// rotation: the post-call steps then need no KEK round trip that could
	// run past the lease.
	dek, err := m.unwrap(ctx, s)
	if err != nil {
		release()
		return Connection{}, err
	}
	defer zero(dek)
	old, err := openTokensWithDEK(dek, c, s)
	if err != nil {
		release()
		return Connection{}, err
	}
	if old.RefreshToken.Empty() {
		release()
		return Connection{}, fmt.Errorf("%w: no refresh token", ErrUnreadable)
	}
	callCtx, cancelCall := context.WithTimeout(ctx, m.untilByClock(now.Add(m.callBudget())))
	raw, err := fn(callCtx, c.Server, old.RefreshToken)
	cancelCall()
	// The response's expires_in counts from its receipt.
	received := m.now()
	switch {
	case errors.Is(err, ErrRefreshTokenReuse):
		_, _, _, rerr := m.store.RevokePAConnection(ctx, principal, id, "refresh_token_reuse")
		m.cancelInflight(id)
		return Connection{}, errors.Join(err, rerr, m.revokeTokens(ctx, c.Server, old))
	case errors.Is(err, ErrInvalidGrant):
		_, terr := m.transition(ctx, principal, id, Transition{
			From: StateActive, To: StateExpired, ExpectRevision: c.AuthorityRevision, Reason: "invalid_grant",
		})
		if terr != nil {
			// The connection could not be recorded as expired: it is
			// not reported as expired either (#1318 C2b). The next call
			// meets the same answer and records it then.
			return Connection{}, errors.Join(ErrRefreshFailed, err, terr)
		}
		return Connection{}, err
	case err != nil:
		release()
		return Connection{}, fmt.Errorf("%w: %w", ErrRefreshFailed, err)
	}

	check := VerifyTokenResponse(c.Server, raw)
	if check.Err == nil && check.Granted != c.GrantedScope {
		check.Err = fmt.Errorf("%w: refresh changed the granted scope", ErrScopeMismatch)
	}
	if check.Err != nil {
		// Both sets go: the new tokens carry the wrong grant, and the old ones
		// are wiped locally by the move to failed, so leaving them live at the
		// server would orphan them.
		_, ferr := m.failAndRevoke(ctx, c, check.Tokens, "refresh_scope_check", check.Err)
		return Connection{}, errors.Join(ferr, m.revokeTokens(ctx, c.Server, old))
	}
	next := check.Tokens.receivedAt(received)
	if next.RefreshToken.Empty() {
		next.RefreshToken = old.RefreshToken
	}
	blob, err := m.sealTokens(dek, c, next)
	if err != nil {
		release()
		return Connection{}, errors.Join(err, m.revokeTokens(ctx, c.Server, check.Tokens))
	}
	// Past the lease end (by the same clock that set it), another replica
	// may already hold the lease: storing now could race its refresh. The
	// store write itself is bounded by the lease end too, and its CAS
	// re-checks the lease end against the same clock.
	storeAt := m.now().UTC()
	var out Connection
	if !storeAt.Before(leaseEnd) {
		err = fmt.Errorf("%w: refresh lease ran out before the rotation was stored", ErrConflict)
	} else {
		sctx, cancelStore := context.WithTimeout(ctx, m.untilByClock(leaseEnd))
		out, err = m.store.RotatePAConnectionTokens(sctx, principal, id, Rotation{
			ExpectRevision: c.AuthorityRevision, ExpectGeneration: c.TokenGeneration,
			GrantedScope: c.GrantedScope, LeaseOwner: m.owner, SealedTokens: blob, Now: storeAt,
		})
		cancelStore()
	}
	if err != nil {
		// What the server just issued is never used unstored: it is revoked.
		// A CAS miss means the connection moved while the refresh was on the
		// wire (revoked, failed, expired, another rotation, or the lease ran
		// out): ErrFenced. Any other store error is reported as itself, not
		// as a fence.
		release()
		if errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) {
			err = errors.Join(ErrFenced, err)
		} else {
			err = fmt.Errorf("pa connection: store rotation: %w", err)
		}
		return Connection{}, errors.Join(err, m.revokeTokens(ctx, c.Server, check.Tokens))
	}
	return out, nil
}

// DisconnectResult reports the best-effort parts of Disconnect.
type DisconnectResult struct {
	Connection     Connection
	AlreadyRevoked bool
	// RemoteErr is the remote revocation failure, if any. The connection is
	// revoked locally either way.
	RemoteErr error
}

// Disconnect is /disconnect at the store level (threat model T2):
//
//  1. revoke locally first: state revoked, revision bumped, DEK wrapper and
//     every sealed secret destroyed, in one store transaction that waits for
//     nothing remote;
//  2. cancel in-flight calls on the connection;
//  3. (jobs, approvals and standing permissions bound to it are #1315 / S2);
//  4. call the server's revocation endpoint with the tokens read in step 1,
//     best-effort: a failure is reported in the result and changes nothing
//     locally (S1-C6).
//
// The error is non-nil only when step 1 did not happen.
func (m *Manager) Disconnect(ctx context.Context, principal int64, id string) (DisconnectResult, error) {
	c, before, already, err := m.store.RevokePAConnection(ctx, principal, id, "disconnect")
	if err != nil {
		return DisconnectResult{}, readErr(err)
	}
	m.cancelInflight(id)
	res := DisconnectResult{Connection: c, AlreadyRevoked: already}
	if already || len(before.SealedTokens) == 0 {
		return res, nil
	}
	ts, err := m.openTokens(ctx, c, before)
	if err != nil {
		res.RemoteErr = fmt.Errorf("pa connection: tokens for remote revocation: %w", err)
		return res, nil
	}
	res.RemoteErr = m.revokeTokens(ctx, c.Server, ts)
	return res, nil
}

// RevokeHeldTokens revokes every connection of principal that still holds
// provider tokens, for account deletion (#1338): at the provider first, and
// locally only once the provider has taken the revocation.
//
// The order is the reverse of Disconnect's, on purpose. Disconnect revokes
// locally first and calls the provider best-effort (S1-C6), which is right
// for a connection that stays: its row keeps saying revoked. Account
// deletion purges the row afterwards, so a token wiped locally before the
// provider took its revocation could never be revoked by anyone. Here a
// connection whose tokens cannot be read, or whose remote revocation fails,
// keeps its row and its sealed tokens, and the failure is returned: the
// caller refuses the deletion, which can be retried.
//
// The local revocation is a compare-and-set on the row's revision and token
// generation. A connection that changed in between (a refresh rotated its
// tokens, a confirm activated it) is read and revoked again, at most
// revokeHeldAttempts times; the new tokens are revoked at the provider before
// anything local changes. A connection without tokens is left as it is: the
// purge deletes it. A connection that is gone (ErrNotFound) holds nothing.
//
// The error joins one error per connection not revoked, and a failed listing
// is an error: nil means every connection the listing returned holds no
// tokens now. The purge checks again in its own transaction, so a
// connection that gains tokens after this returns still refuses the
// deletion.
//
// A nil *Manager refuses rather than panics: a typed nil stored in a
// db.PATokenRevoker passes the callers' nil checks, and the account
// deletion must then refuse (409 / tool error), not crash the handler.
func (m *Manager) RevokeHeldTokens(ctx context.Context, principal int64) error {
	if m == nil {
		return errors.New("pa connection: revoke held tokens: no manager")
	}
	if err := validPrincipal(principal); err != nil {
		return err
	}
	list, err := m.store.ListPAConnections(ctx, principal)
	if err != nil {
		return readErr(err)
	}
	var errs []error
	for _, c := range list {
		if err := m.revokeHeld(ctx, principal, c.ID); err != nil {
			errs = append(errs, fmt.Errorf("pa connection %s: %w", c.ID, err))
		}
	}
	return errors.Join(errs...)
}

// revokeHeldAttempts bounds RevokeHeldTokens' retries on one connection.
const revokeHeldAttempts = 3

func (m *Manager) revokeHeld(ctx context.Context, principal int64, id string) error {
	for range revokeHeldAttempts {
		c, s, err := m.store.GetPAConnectionSealed(ctx, principal, id)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return readErr(err)
		}
		if len(s.SealedTokens) == 0 {
			return nil
		}
		ts, err := m.openTokens(ctx, c, s)
		if err != nil {
			return fmt.Errorf("pa connection: tokens for remote revocation: %w", err)
		}
		if err := m.revokeTokens(ctx, c.Server, ts); err != nil {
			return err
		}
		_, err = m.store.RevokePAConnectionAt(ctx, principal, id, c.AuthorityRevision, c.TokenGeneration, "account_deleted")
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return fmt.Errorf("pa connection: local revoke: %w", err)
		}
		m.cancelInflight(id)
		return nil
	}
	return fmt.Errorf("%w: the connection kept changing while it was revoked", ErrConflict)
}

// Call is one outbound MCP call under the connection lease (threat model T2
// steps 1-3). Ctx is cancelled by Disconnect. The executor wiring is #1315's.
type Call struct {
	Ctx context.Context

	m             *Manager
	principal     int64
	id            string
	server        Server
	boundRevision int64
	cancel        context.CancelFunc
	once          sync.Once
}

// BeginCall registers a cancellable call context and then passes the gate.
// Registering first means a Disconnect that commits between the two still
// cancels this call; a refused call is deregistered.
func (m *Manager) BeginCall(ctx context.Context, principal int64, id string, boundRevision int64) (*Call, error) {
	cctx, cancel := context.WithCancel(ctx)
	call := &Call{Ctx: cctx, m: m, principal: principal, id: id, boundRevision: boundRevision, cancel: cancel}
	m.mu.Lock()
	if m.inflight[id] == nil {
		m.inflight[id] = map[*Call]context.CancelFunc{}
	}
	m.inflight[id][call] = cancel
	m.mu.Unlock()
	c, err := m.Authorize(cctx, principal, id, boundRevision)
	if err != nil {
		call.deregister()
		return nil, err
	}
	call.server = c.Server
	return call, nil
}

// deregister removes the call from the in-flight registry and cancels its
// context, once.
func (c *Call) deregister() {
	c.once.Do(func() {
		c.m.mu.Lock()
		if calls := c.m.inflight[c.id]; calls != nil {
			delete(calls, c)
			if len(calls) == 0 {
				delete(c.m.inflight, c.id)
			}
		}
		c.m.mu.Unlock()
		c.cancel()
	})
}

func (m *Manager) cancelInflight(id string) {
	m.mu.Lock()
	calls := m.inflight[id]
	delete(m.inflight, id)
	m.mu.Unlock()
	for _, cancel := range calls {
		cancel()
	}
}

// Abandon ends a call that never dispatched: the executor refused it
// before anything was sent. It only deregisters; there is no result to
// fence. A call that did dispatch must use Finish.
func (c *Call) Abandon() { c.deregister() }

// Finish is the post-dispatch check. It re-reads the connection; if the
// state left active, the revision moved, or the read failed, the result
// must be discarded: Finish records a fenced event and returns an error
// wrapping ErrFenced (S1-C7). A nil error means the result may be used.
func (c *Call) Finish(ctx context.Context) error {
	c.deregister()
	conn, err := c.m.store.GetPAConnection(ctx, c.principal, c.id)
	reason := ""
	switch {
	case err != nil:
		reason = "unreadable"
	case conn.State != StateActive:
		reason = "not_active"
	case conn.AuthorityRevision != c.boundRevision:
		reason = "revision_changed"
	}
	if reason == "" {
		return nil
	}
	aerr := c.m.auditor.RecordFenced(context.WithoutCancel(ctx), FenceEvent{
		Principal: c.principal, ConnectionID: c.id, Server: c.server,
		BoundRevision: c.boundRevision, Reason: reason,
	})
	return errors.Join(fmt.Errorf("%w: %s", ErrFenced, reason), aerr)
}

// transition stamps t with the Manager's clock and applies it.
func (m *Manager) transition(ctx context.Context, principal int64, id string, t Transition) (Connection, error) {
	t.At = m.now().UTC()
	return m.store.TransitionPAConnection(ctx, principal, id, t)
}
