package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrOAuthNotFound is returned by OAuth store methods when the requested row
// does not exist, has been consumed, or has exceeded its TTL.
var ErrOAuthNotFound = errors.New("oauth: not found or expired")

// ErrOAuthExpired is returned by ConsumeOAuthPending when the row existed but
// was older than the caller's ttl. It wraps ErrOAuthNotFound so every existing
// errors.Is(err, ErrOAuthNotFound) caller is unaffected; check ErrOAuthExpired
// FIRST when the two need distinguishing.
var ErrOAuthExpired = fmt.Errorf("oauth: expired: %w", ErrOAuthNotFound)

// ErrOAuthStateConflict is returned by InsertOAuthPending when the state token
// already exists in the table (duplicate PKCE state). The caller should abort
// the authorization flow — a collision is either a bug or an attack attempt.
var ErrOAuthStateConflict = errors.New("oauth: state already exists")

// OAuthPendingAuth is the persistent representation of a pending OAuth
// authorization flow, mirroring the in-memory pendingAuth struct in
// internal/oauth/server.go.
type OAuthPendingAuth struct {
	State           string
	ClientID        string
	RedirectURI     string
	ClientState     string
	CodeChallenge   string
	ChallengeMethod string
	Scope           string
	Nonce           string
	TGCodeVerifier  string
	CreatedAt       time.Time
}

// OAuthCode is the persistent representation of an issued authorization code.
type OAuthCode struct {
	Code             string
	ClientID         string
	RedirectURI      string
	CodeChallenge    string
	ChallengeMethod  string
	TelegramID       int64
	TelegramUsername string
	Scope            string
	CreatedAt        time.Time
}

// OAuthClientReg is the persistent representation of a dynamic client
// registration (RFC 7591), stored in oauth_client_registrations.
type OAuthClientReg struct {
	ClientID     string
	ClientName   string
	RedirectURIs []string
	CreatedAt    time.Time
}

// PinnedClientIDPrefix marks a client registration whose redirect_uris are all
// on the operator's exact DCR allowlist (OAUTH_DCR_REDIRECT_URIS). Such a
// client_id is derived from its redirect set rather than drawn at random, so
// the rows it can produce are bounded by the allowlist itself, and it is
// exempt from both the ClientRegistrationTTL sweep and the
// MaxRegisteredClients eviction: the Cloudflare MCP portal registers once and
// keeps authorizing its users with that client_id for as long as it runs, and
// a 24h sweep would silently break every portal login after the first day.
// Random registrations always start "tgmcp_", and internal/oauth refuses a
// preregistered client_id with this prefix, so no other row can carry it.
// The queries test it with starts_with, an exact prefix comparison, never a
// LIKE pattern in which '_' would be a wildcard.
const PinnedClientIDPrefix = "tgdcr_"

// PinnedClientName is the client_name every pinned registration is stored
// and answered with, whatever the caller sent. A pinned client_id is
// derivable from public callbacks, so a caller-supplied name could be set by
// anyone who registers the exact set first; it would then flow into
// oauth_refresh_tokens.client_name and broadcast audience selection. The
// only client the allowlist exists for is the Cloudflare MCP portal, so the
// server names it.
const PinnedClientName = "Cloudflare MCP portal"

// InsertOAuthPending persists a pending OAuth authorization-flow entry to
// oauth_pending_auth. Used by oauth.Server.handleAuthorize when useDB is true.
func (s *Store) InsertOAuthPending(ctx context.Context, p OAuthPendingAuth) error {
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO oauth_pending_auth
			(state, client_id, redirect_uri, client_state, code_challenge,
			 challenge_method, scope, nonce, tg_code_verifier, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 ON CONFLICT (state) DO NOTHING`,
		p.State, p.ClientID, p.RedirectURI, p.ClientState, p.CodeChallenge,
		p.ChallengeMethod, p.Scope, p.Nonce, p.TGCodeVerifier, p.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert oauth_pending_auth: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrOAuthStateConflict
	}
	return nil
}

// EvictOldestOAuthPendingIfOver deletes the oldest live (non-expired)
// pending-auth row when the live count is at or above max. No-op when max is
// zero. Both the candidate selection and the live-count check use the same
// cutoff so an expired row is never mistakenly evicted in place of a live one.
func (s *Store) EvictOldestOAuthPendingIfOver(ctx context.Context, max int, ttl time.Duration) error {
	if max <= 0 {
		return nil
	}
	cutoff := time.Now().UTC().Add(-ttl)
	_, err := s.DB.ExecContext(ctx,
		`DELETE FROM oauth_pending_auth
		  WHERE state = (
		    SELECT state FROM oauth_pending_auth
		     WHERE created_at >= $1
		     ORDER BY created_at ASC LIMIT 1
		  )
		  AND (SELECT COUNT(*) FROM oauth_pending_auth WHERE created_at >= $1) >= $2`,
		cutoff, int64(max),
	)
	if err != nil {
		return fmt.Errorf("evict oldest oauth_pending_auth: %w", err)
	}
	return nil
}

// EvictOldestOAuthCodeIfOver deletes the oldest live (non-expired) auth-code
// row when the live count is at or above max. No-op when max is zero. Both the
// candidate selection and the live-count check use the same cutoff.
func (s *Store) EvictOldestOAuthCodeIfOver(ctx context.Context, max int, ttl time.Duration) error {
	if max <= 0 {
		return nil
	}
	cutoff := time.Now().UTC().Add(-ttl)
	_, err := s.DB.ExecContext(ctx,
		`DELETE FROM oauth_auth_codes
		  WHERE code = (
		    SELECT code FROM oauth_auth_codes
		     WHERE created_at >= $1
		     ORDER BY created_at ASC LIMIT 1
		  )
		  AND (SELECT COUNT(*) FROM oauth_auth_codes WHERE created_at >= $1) >= $2`,
		cutoff, int64(max),
	)
	if err != nil {
		return fmt.Errorf("evict oldest oauth_auth_codes: %w", err)
	}
	return nil
}

// EvictOldestClientRegIfOver deletes the oldest client registration when the
// total count is at or above max. No-op when max is zero. Used by
// handleClientRegistration to enforce MaxRegisteredClients on the DB path.
// Pinned registrations (PinnedClientIDPrefix) are neither counted nor evicted.
func (s *Store) EvictOldestClientRegIfOver(ctx context.Context, max int) error {
	if max <= 0 {
		return nil
	}
	_, err := s.DB.ExecContext(ctx,
		`DELETE FROM oauth_client_registrations
		  WHERE client_id = (
		    SELECT client_id FROM oauth_client_registrations
		     WHERE NOT starts_with(client_id, $2)
		     ORDER BY created_at ASC LIMIT 1
		  )
		  AND (SELECT COUNT(*) FROM oauth_client_registrations WHERE NOT starts_with(client_id, $2)) >= $1`,
		int64(max), PinnedClientIDPrefix,
	)
	if err != nil {
		return fmt.Errorf("evict oldest oauth_client_registrations: %w", err)
	}
	return nil
}

// ConsumeOAuthPending atomically deletes and returns the pending entry for the
// given state. Returns ErrOAuthNotFound when the row is absent, and
// ErrOAuthExpired (which wraps ErrOAuthNotFound) when the row existed but its
// created_at is older than ttl — the TTL check runs in Go against the
// returned created_at rather than as a DELETE predicate, so a row that merely
// expired is now consumed on the attempt rather than left for the sweeper to
// find later; a second replay of the same expired state reports
// ErrOAuthNotFound. DELETE ... RETURNING stays atomic at the DB level
// regardless of isolation, eliminating the TOCTOU race that a SELECT + DELETE
// transaction at READ COMMITTED would have.
func (s *Store) ConsumeOAuthPending(ctx context.Context, state string, ttl time.Duration) (*OAuthPendingAuth, error) {
	cutoff := time.Now().UTC().Add(-ttl)
	var p OAuthPendingAuth
	var clientState, scope sql.NullString
	err := s.DB.QueryRowContext(ctx,
		`DELETE FROM oauth_pending_auth
		  WHERE state = $1
		RETURNING state, client_id, redirect_uri, client_state, code_challenge,
		          challenge_method, scope, nonce, tg_code_verifier, created_at`,
		state,
	).Scan(
		&p.State, &p.ClientID, &p.RedirectURI, &clientState, &p.CodeChallenge,
		&p.ChallengeMethod, &scope, &p.Nonce, &p.TGCodeVerifier, &p.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOAuthNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consume oauth_pending_auth: %w", err)
	}
	p.ClientState = clientState.String
	p.Scope = scope.String
	if p.CreatedAt.Before(cutoff) {
		return nil, ErrOAuthExpired
	}
	return &p, nil
}

// ErrOAuthCodeConflict is returned by InsertOAuthCode when the code token
// already exists. A collision with randomToken(32) is astronomically unlikely
// but the caller should treat it as an internal error and abort.
var ErrOAuthCodeConflict = errors.New("oauth: auth code already exists")

// InsertOAuthCode persists an issued authorization code to oauth_auth_codes
// for the sign-in of userID that started at signInStartedAt (the authorize
// request). It refuses with ErrAccountDeletedSinceGrant when the account was
// deleted at or after that moment, so a sign-in that raced a delete gets no
// code at all. On Postgres it takes the users-row lock in share mode, like
// SaveRefreshTokenForGrant: HardDeleteAccount holds that row for its whole
// transaction, so a code is either stored before the delete (and the
// exchange refuses it against the marker) or after the delete committed (and
// is refused here). Without the lock a code stamped between the delete's
// marker and its commit post-dates the marker and would mint a family the
// delete never saw (#817). A sign-in that starts after the marker is
// written counts as one made after the delete, like signing in again.
//
// signInStartedAt comes from the oauth server's clock; see
// SaveRefreshTokenForGrant for why it must stay near real time. A zero
// signInStartedAt or a missing users row is an error, not "never deleted".
func (s *Store) InsertOAuthCode(ctx context.Context, c OAuthCode, userID int64, signInStartedAt time.Time) error {
	if userID <= 0 {
		return errors.New("insert oauth_auth_codes: missing user id")
	}
	if signInStartedAt.IsZero() {
		return errors.New("insert oauth_auth_codes: missing sign-in start")
	}
	pg, err := s.postgresDialect(ctx)
	if err != nil {
		return fmt.Errorf("insert oauth_auth_codes: %w", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("insert oauth_auth_codes: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	lock := ""
	if pg {
		lock = " FOR SHARE"
	}
	deleted, err := accountDeletedSince(ctx, tx, userID, signInStartedAt, lock)
	if err != nil {
		return fmt.Errorf("insert oauth_auth_codes: %w", err)
	}
	if deleted {
		return ErrAccountDeletedSinceGrant
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO oauth_auth_codes
			(code, client_id, redirect_uri, code_challenge, challenge_method,
			 telegram_id, telegram_username, scope, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 ON CONFLICT (code) DO NOTHING`,
		c.Code, c.ClientID, c.RedirectURI, c.CodeChallenge, c.ChallengeMethod,
		c.TelegramID, c.TelegramUsername, c.Scope, c.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert oauth_auth_codes: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrOAuthCodeConflict
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("insert oauth_auth_codes: commit: %w", err)
	}
	return nil
}

// AccountDeletedSince reports whether userID's account was deleted at or
// after at. It is the unlocked check for the in-memory code store, used only
// with SQLite; the database-backed path checks inside InsertOAuthCode under
// the users-row lock instead. Without the lock it cannot see a delete that
// has written its marker but not yet committed (see HardDeleteAccount).
func (s *Store) AccountDeletedSince(ctx context.Context, userID int64, at time.Time) (bool, error) {
	if userID <= 0 {
		return false, errors.New("account deleted since: missing user id")
	}
	if at.IsZero() {
		return false, errors.New("account deleted since: missing time")
	}
	return accountDeletedSince(ctx, s.DB, userID, at, "")
}

// accountDeletedSince reads userID's deletion marker through q, appending
// lock (empty or a row-lock clause) to the read. A missing users row is an
// error, not "never deleted".
func accountDeletedSince(ctx context.Context, q interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}, userID int64, at time.Time, lock string) (bool, error) {
	var deletedAt sql.NullTime
	if err := q.QueryRowContext(ctx,
		`SELECT account_deleted_at FROM users WHERE id = $1`+lock, userID,
	).Scan(&deletedAt); err != nil {
		return false, fmt.Errorf("read account deletion: %w", err)
	}
	return deletedAt.Valid && !deletedAt.Time.Before(at), nil
}

// ConsumeOAuthCode atomically deletes and returns the authorization code
// entry. Returns ErrOAuthNotFound when the row is absent, expired, or already
// consumed. DELETE ... RETURNING is atomic regardless of isolation, eliminating
// the TOCTOU race where two concurrent /oauth/token requests for the same code
// could both succeed and receive separate access tokens.
func (s *Store) ConsumeOAuthCode(ctx context.Context, code string, ttl time.Duration) (*OAuthCode, error) {
	cutoff := time.Now().UTC().Add(-ttl)
	var c OAuthCode
	var tgUsername, scope sql.NullString
	err := s.DB.QueryRowContext(ctx,
		`DELETE FROM oauth_auth_codes
		  WHERE code = $1 AND created_at >= $2
		RETURNING code, client_id, redirect_uri, code_challenge, challenge_method,
		          telegram_id, telegram_username, scope, created_at`,
		code, cutoff,
	).Scan(
		&c.Code, &c.ClientID, &c.RedirectURI, &c.CodeChallenge, &c.ChallengeMethod,
		&c.TelegramID, &tgUsername, &scope, &c.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOAuthNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consume oauth_auth_codes: %w", err)
	}
	c.TelegramUsername = tgUsername.String
	c.Scope = scope.String
	return &c, nil
}

// InsertClientReg persists a dynamic client registration to
// oauth_client_registrations. redirect_uris is stored as a JSON array.
func (s *Store) InsertClientReg(ctx context.Context, reg OAuthClientReg) error {
	urisJSON, err := json.Marshal(reg.RedirectURIs)
	if err != nil {
		return fmt.Errorf("insert client_reg: marshal redirect_uris: %w", err)
	}
	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO oauth_client_registrations (client_id, client_name, redirect_uris, created_at)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (client_id) DO UPDATE
		   SET client_name = EXCLUDED.client_name,
		       redirect_uris = EXCLUDED.redirect_uris`,
		reg.ClientID, reg.ClientName, string(urisJSON), reg.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert client_reg: %w", err)
	}
	return nil
}

// InsertPinnedClientReg persists a pinned registration (PinnedClientIDPrefix)
// write-once: an existing row is left exactly as it is and the stored
// registration is returned. The caller passes PinnedClientName as the name,
// so there is nothing to update; the redirect set never needs updating
// either, since it is what the client_id is derived from. Write-once keeps
// that true even for a row written by an older build.
func (s *Store) InsertPinnedClientReg(ctx context.Context, reg OAuthClientReg) (*OAuthClientReg, error) {
	if !strings.HasPrefix(reg.ClientID, PinnedClientIDPrefix) {
		return nil, fmt.Errorf("insert pinned client_reg: client_id %q lacks the pinned prefix", reg.ClientID)
	}
	urisJSON, err := json.Marshal(reg.RedirectURIs)
	if err != nil {
		return nil, fmt.Errorf("insert pinned client_reg: marshal redirect_uris: %w", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO oauth_client_registrations (client_id, client_name, redirect_uris, created_at)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (client_id) DO NOTHING`,
		reg.ClientID, reg.ClientName, string(urisJSON), reg.CreatedAt.UTC(),
	); err != nil {
		return nil, fmt.Errorf("insert pinned client_reg: %w", err)
	}
	return s.GetClientReg(ctx, reg.ClientID)
}

// GetClientReg returns the dynamic client registration for the given clientID.
// Returns ErrOAuthNotFound when the row is absent.
func (s *Store) GetClientReg(ctx context.Context, clientID string) (*OAuthClientReg, error) {
	var reg OAuthClientReg
	var urisJSON string
	err := s.DB.QueryRowContext(ctx,
		`SELECT client_id, client_name, redirect_uris, created_at
		   FROM oauth_client_registrations
		  WHERE client_id = $1`,
		clientID,
	).Scan(&reg.ClientID, &reg.ClientName, &urisJSON, &reg.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOAuthNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get client_reg: %w", err)
	}
	if err := json.Unmarshal([]byte(urisJSON), &reg.RedirectURIs); err != nil {
		return nil, fmt.Errorf("get client_reg: unmarshal redirect_uris: %w", err)
	}
	return &reg, nil
}

// DeleteClientReg removes a client registration. Used by the sweeper when the
// ClientRegistrationTTL elapses.
func (s *Store) DeleteClientReg(ctx context.Context, clientID string) error {
	_, err := s.DB.ExecContext(ctx,
		`DELETE FROM oauth_client_registrations WHERE client_id = $1`, clientID,
	)
	if err != nil {
		return fmt.Errorf("delete client_reg: %w", err)
	}
	return nil
}

// DeleteExpiredOAuthRows removes pending-auth and auth-code rows whose
// created_at is older than ttl. Intended to run from the sweeper goroutine.
// Returns the number of pending and code rows deleted.
func (s *Store) DeleteExpiredOAuthRows(ctx context.Context, ttl time.Duration) (pending, codes int64, err error) {
	cutoff := time.Now().UTC().Add(-ttl)

	resPending, err := s.DB.ExecContext(ctx,
		`DELETE FROM oauth_pending_auth WHERE created_at < $1`, cutoff,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("sweep oauth_pending_auth: %w", err)
	}
	pendingN, _ := resPending.RowsAffected()

	resCodes, err := s.DB.ExecContext(ctx,
		`DELETE FROM oauth_auth_codes WHERE created_at < $1`, cutoff,
	)
	if err != nil {
		return pendingN, 0, fmt.Errorf("sweep oauth_auth_codes: %w", err)
	}
	codesN, _ := resCodes.RowsAffected()

	return pendingN, codesN, nil
}

// DeleteExpiredClientRegs removes client registration rows older than ttl.
// Pinned registrations (PinnedClientIDPrefix) are never swept.
func (s *Store) DeleteExpiredClientRegs(ctx context.Context, ttl time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-ttl)
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM oauth_client_registrations WHERE created_at < $1 AND NOT starts_with(client_id, $2)`,
		cutoff, PinnedClientIDPrefix,
	)
	if err != nil {
		return 0, fmt.Errorf("sweep oauth_client_registrations: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// CountOAuthPending returns the number of non-expired pending-auth rows (i.e.
// created within the last ttl). Used to sample the OAuthPendingAuthSize gauge.
func (s *Store) CountOAuthPending(ctx context.Context, ttl time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-ttl)
	var n int64
	err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oauth_pending_auth WHERE created_at >= $1`, cutoff,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count oauth_pending_auth: %w", err)
	}
	return n, nil
}

// RecordClientAssertionJTI records the jti of a client assertion from
// clientID for ttl and reports whether it was fresh. false means the
// jti was already used by a live assertion: the caller must refuse the
// request. A row whose expiry has passed is reused in place, so a jti is
// never refused for a stale record. Any error is a failed read, never a
// pass: the caller answers server_error.
//
// The expiry is computed from the database clock, the same clock the
// conflict check and the sweep compare against, so app/database clock skew
// cannot make a fresh row look expired and let a replay through.
func (s *Store) RecordClientAssertionJTI(ctx context.Context, clientID, jti string, ttl time.Duration) (bool, error) {
	sum := sha256.Sum256([]byte(clientID + "\x00" + jti))
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO oauth_client_assertion_jtis (jti_hash, expires_at)
		 VALUES ($1, NOW() + $2 * INTERVAL '1 millisecond')
		 ON CONFLICT (jti_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at
		 WHERE oauth_client_assertion_jtis.expires_at < NOW()`,
		sum[:], ttl.Milliseconds(),
	)
	if err != nil {
		return false, fmt.Errorf("record client assertion jti: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("record client assertion jti: rows affected: %w", err)
	}
	return n == 1, nil
}

// DeleteExpiredClientAssertionJTIs removes jti records whose assertion has
// expired. Intended to run from the sweeper goroutine.
func (s *Store) DeleteExpiredClientAssertionJTIs(ctx context.Context) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM oauth_client_assertion_jtis WHERE expires_at < NOW()`)
	if err != nil {
		return 0, fmt.Errorf("sweep oauth_client_assertion_jtis: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
