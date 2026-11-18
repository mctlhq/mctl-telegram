package connection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Store is the persistent connection store. internal/db.Store implements it.
// Every method is keyed by (principal, id); a row of another principal is
// ErrNotFound. A failed read is an error, never a zero Connection.
type Store interface {
	CreatePAConnection(ctx context.Context, c Connection, s Sealed) error
	GetPAConnection(ctx context.Context, principal int64, id string) (Connection, error)
	GetPAConnectionSealed(ctx context.Context, principal int64, id string) (Connection, Sealed, error)
	ListPAConnections(ctx context.Context, principal int64) ([]Connection, error)
	// TransitionPAConnection applies t by compare-and-set and returns the
	// row after it. ErrNotFound, ErrConflict, ErrIllegalTransition and
	// ErrInvalidTransition as documented on Transition.
	TransitionPAConnection(ctx context.Context, principal int64, id string, t Transition) (Connection, error)
	// RevokePAConnection moves the row to revoked from whatever state it is
	// in, bumps the revision and destroys every sealed secret, in one
	// transaction. It returns the row after the change and the secret
	// material as it was just before, so the caller can still revoke the
	// token remotely. A row already revoked returns alreadyRevoked=true and
	// changes nothing.
	RevokePAConnection(ctx context.Context, principal int64, id, reason string) (c Connection, before Sealed, alreadyRevoked bool, err error)
	// ClaimPAConnectionRefresh takes the refresh lease of an active row at
	// generation for owner until until, if no unexpired lease is held. It
	// reports whether the lease was taken.
	ClaimPAConnectionRefresh(ctx context.Context, principal int64, id string, generation int64, owner string, now, until time.Time) (bool, error)
	// ReleasePAConnectionRefresh drops owner's lease, if it still holds it.
	ReleasePAConnectionRefresh(ctx context.Context, principal int64, id, owner string) error
	// RotatePAConnectionTokens applies r by compare-and-set.
	RotatePAConnectionTokens(ctx context.Context, principal int64, id string, r Rotation) (Connection, error)
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
}

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
		now: now, lease: lease, owner: owner,
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
func (m *Manager) Begin(ctx context.Context, principal int64, server Server) (Connection, error) {
	if err := validPrincipal(principal); err != nil {
		return Connection{}, err
	}
	if !server.Valid() {
		return Connection{}, errors.New("pa connection: unknown server")
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
	if err := m.store.CreatePAConnection(ctx, c, Sealed{KEKID: m.kek.ID(), WrappedDEK: wrapped}); err != nil {
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
	return m.store.TransitionPAConnection(ctx, principal, id, Transition{
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
	return m.store.TransitionPAConnection(ctx, principal, id, Transition{
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

// CompleteExchange records the result of the code exchange (threat model T1
// step 4): pending_return -> pending_confirm with the stable account id, the
// granted scope and the sealed tokens. Before anything is stored, the
// effective scope must equal the allowed set (T8, S1-T9). Any failure of
// that check moves the connection to failed and revokes what the server
// issued; the returned error wraps ErrScopeMismatch or ErrTokenResponse.
func (m *Manager) CompleteExchange(ctx context.Context, principal int64, id string, expectRevision int64, accountID string, tokenResponse []byte) (Connection, error) {
	c, s, err := m.store.GetPAConnectionSealed(ctx, principal, id)
	if err != nil {
		return Connection{}, readErr(err)
	}
	if c.State != StatePendingReturn || c.AuthorityRevision != expectRevision {
		return Connection{}, fmt.Errorf("%w: exchange needs pending_return at the expected revision", ErrConflict)
	}
	check := VerifyTokenResponse(c.Server, tokenResponse)
	if check.Err == nil && accountID == "" {
		check.Err = fmt.Errorf("%w: no stable account id", ErrTokenResponse)
	}
	if check.Err != nil {
		return m.failAndRevoke(ctx, c, check.Tokens, "exchange_scope_check", check.Err)
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
	return m.store.TransitionPAConnection(ctx, principal, id, Transition{
		From: StatePendingReturn, To: StatePendingConfirm, ExpectRevision: expectRevision,
		AccountID: accountID, GrantedScope: check.Granted, SealedTokens: blob,
	})
}

// Confirm moves pending_confirm -> active. The callback_query check (from.id
// == principal within 10 minutes) is the linking slice's; this is the store
// edge it ends in.
func (m *Manager) Confirm(ctx context.Context, principal int64, id string, expectRevision int64) (Connection, error) {
	return m.store.TransitionPAConnection(ctx, principal, id, Transition{
		From: StatePendingConfirm, To: StateActive, ExpectRevision: expectRevision,
	})
}

// Fail moves a non-terminal connection to failed.
func (m *Manager) Fail(ctx context.Context, principal int64, id string, expectRevision int64, reason string) (Connection, error) {
	c, err := m.store.GetPAConnection(ctx, principal, id)
	if err != nil {
		return Connection{}, readErr(err)
	}
	return m.store.TransitionPAConnection(ctx, principal, id, Transition{
		From: c.State, To: StateFailed, ExpectRevision: expectRevision, Reason: reason,
	})
}

// failAndRevoke moves c to failed and revokes the tokens a server issued
// under a response that did not pass the check. It always returns cause
// (joined with any store error): the caller must not proceed.
func (m *Manager) failAndRevoke(ctx context.Context, c Connection, issued TokenSet, reason string, cause error) (Connection, error) {
	_, terr := m.store.TransitionPAConnection(ctx, c.Principal, c.ID, Transition{
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
func (m *Manager) AccessToken(ctx context.Context, principal int64, id string, boundRevision int64) (Secret, Connection, error) {
	c, s, err := m.store.GetPAConnectionSealed(ctx, principal, id)
	if err != nil {
		return Secret{}, Connection{}, readErr(err)
	}
	if err := gate(c, boundRevision); err != nil {
		return Secret{}, Connection{}, err
	}
	ts, err := m.openTokens(ctx, c, s)
	if err != nil {
		return Secret{}, Connection{}, err
	}
	return ts.AccessToken, c, nil
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
func (m *Manager) Refresh(ctx context.Context, principal int64, id string, fn RefreshFunc) (Connection, error) {
	key := strconv.FormatInt(principal, 10) + "|" + id
	v, err, _ := m.refreshes.Do(key, func() (any, error) {
		return m.refresh(ctx, principal, id, fn)
	})
	if err != nil {
		return Connection{}, err
	}
	return v.(Connection), nil
}

func (m *Manager) refresh(ctx context.Context, principal int64, id string, fn RefreshFunc) (Connection, error) {
	c, s, err := m.store.GetPAConnectionSealed(ctx, principal, id)
	if err != nil {
		return Connection{}, readErr(err)
	}
	if err := gate(c, c.AuthorityRevision); err != nil {
		return Connection{}, err
	}
	now := m.now().UTC()
	ok, err := m.store.ClaimPAConnectionRefresh(ctx, principal, id, c.TokenGeneration, m.owner, now, now.Add(m.lease))
	if err != nil {
		return Connection{}, readErr(err)
	}
	if !ok {
		return Connection{}, ErrRefreshInProgress
	}
	release := func() { _ = m.store.ReleasePAConnectionRefresh(context.WithoutCancel(ctx), principal, id, m.owner) }

	old, err := m.openTokens(ctx, c, s)
	if err != nil {
		release()
		return Connection{}, err
	}
	if old.RefreshToken.Empty() {
		release()
		return Connection{}, fmt.Errorf("%w: no refresh token", ErrUnreadable)
	}
	raw, err := fn(ctx, c.Server, old.RefreshToken)
	switch {
	case errors.Is(err, ErrRefreshTokenReuse):
		_, _, _, rerr := m.store.RevokePAConnection(ctx, principal, id, "refresh_token_reuse")
		m.cancelInflight(id)
		return Connection{}, errors.Join(err, rerr, m.revokeTokens(ctx, c.Server, old))
	case errors.Is(err, ErrInvalidGrant):
		_, terr := m.store.TransitionPAConnection(ctx, principal, id, Transition{
			From: StateActive, To: StateExpired, ExpectRevision: c.AuthorityRevision, Reason: "invalid_grant",
		})
		return Connection{}, errors.Join(err, terr)
	case err != nil:
		release()
		return Connection{}, fmt.Errorf("pa connection: refresh: %w", err)
	}

	check := VerifyTokenResponse(c.Server, raw)
	if check.Err == nil && check.Granted != c.GrantedScope {
		check.Err = fmt.Errorf("%w: refresh changed the granted scope", ErrScopeMismatch)
	}
	if check.Err != nil {
		_, ferr := m.failAndRevoke(ctx, c, check.Tokens, "refresh_scope_check", check.Err)
		return Connection{}, ferr
	}
	next := check.Tokens
	if next.RefreshToken.Empty() {
		next.RefreshToken = old.RefreshToken
	}
	dek, err := m.unwrap(ctx, s)
	if err != nil {
		release()
		return Connection{}, errors.Join(err, m.revokeTokens(ctx, c.Server, check.Tokens))
	}
	defer zero(dek)
	blob, err := m.sealTokens(dek, c, next)
	if err != nil {
		release()
		return Connection{}, errors.Join(err, m.revokeTokens(ctx, c.Server, check.Tokens))
	}
	out, err := m.store.RotatePAConnectionTokens(ctx, principal, id, Rotation{
		ExpectRevision: c.AuthorityRevision, ExpectGeneration: c.TokenGeneration,
		GrantedScope: c.GrantedScope, LeaseOwner: m.owner, SealedTokens: blob,
	})
	if err != nil {
		// The connection moved while the refresh was on the wire (revoked,
		// failed, expired): what the server just issued is never stored or
		// used, and is revoked.
		release()
		return Connection{}, errors.Join(ErrFenced, err, m.revokeTokens(ctx, c.Server, check.Tokens))
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

// BeginCall passes the gate and registers a cancellable call context.
func (m *Manager) BeginCall(ctx context.Context, principal int64, id string, boundRevision int64) (*Call, error) {
	c, err := m.Authorize(ctx, principal, id, boundRevision)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithCancel(ctx)
	call := &Call{Ctx: cctx, m: m, principal: principal, id: id, server: c.Server, boundRevision: boundRevision, cancel: cancel}
	m.mu.Lock()
	if m.inflight[id] == nil {
		m.inflight[id] = map[*Call]context.CancelFunc{}
	}
	m.inflight[id][call] = cancel
	m.mu.Unlock()
	return call, nil
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

// Finish is the post-dispatch check. It re-reads the connection; if the
// state left active, the revision moved, or the read failed, the result
// must be discarded: Finish records a fenced event and returns an error
// wrapping ErrFenced (S1-C7). A nil error means the result may be used.
func (c *Call) Finish(ctx context.Context) error {
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
