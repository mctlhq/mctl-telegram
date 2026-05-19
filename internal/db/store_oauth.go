package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// ErrOAuthNotFound is returned by OAuth store methods when the requested row
// does not exist, has been consumed, or has exceeded its TTL.
var ErrOAuthNotFound = errors.New("oauth: not found or expired")

// OAuthPendingAuth is the persistent representation of a pending OAuth
// authorization flow, mirroring the in-memory pendingAuth struct in
// internal/oauth/server.go.
type OAuthPendingAuth struct {
	State               string
	ClientID            string
	RedirectURI         string
	ClientState         string
	CodeChallenge       string
	ChallengeMethod     string
	Scope               string
	Nonce               string
	TGCodeVerifier      string
	CreatedAt           time.Time
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

// InsertOAuthPending persists a pending OAuth authorization-flow entry to
// oauth_pending_auth. Used by oauth.Server.handleAuthorize when useDB is true.
func (s *Store) InsertOAuthPending(ctx context.Context, p OAuthPendingAuth) error {
	_, err := s.DB.ExecContext(ctx,
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
	return nil
}

// ConsumeOAuthPending deletes and returns the pending entry for the given
// state. Returns ErrOAuthNotFound when the row is absent or expired (older
// than ttl). Expiry is checked on read so callers are not subject to sweeper
// timing.
func (s *Store) ConsumeOAuthPending(ctx context.Context, state string, ttl time.Duration) (*OAuthPendingAuth, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("consume oauth_pending_auth: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var p OAuthPendingAuth
	var clientState, scope sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT state, client_id, redirect_uri, client_state, code_challenge,
		        challenge_method, scope, nonce, tg_code_verifier, created_at
		   FROM oauth_pending_auth
		  WHERE state = $1`,
		state,
	).Scan(
		&p.State, &p.ClientID, &p.RedirectURI, &clientState, &p.CodeChallenge,
		&p.ChallengeMethod, &scope, &p.Nonce, &p.TGCodeVerifier, &p.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOAuthNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consume oauth_pending_auth: query: %w", err)
	}
	p.ClientState = clientState.String
	p.Scope = scope.String

	// Defensive TTL check on read — the sweeper may not have run yet.
	if time.Since(p.CreatedAt) > ttl {
		// Delete the expired row and report not-found.
		_, _ = tx.ExecContext(ctx, `DELETE FROM oauth_pending_auth WHERE state = $1`, state)
		_ = tx.Commit()
		return nil, ErrOAuthNotFound
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM oauth_pending_auth WHERE state = $1`, state); err != nil {
		return nil, fmt.Errorf("consume oauth_pending_auth: delete: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("consume oauth_pending_auth: commit: %w", err)
	}
	return &p, nil
}

// InsertOAuthCode persists an issued authorization code to oauth_auth_codes.
func (s *Store) InsertOAuthCode(ctx context.Context, c OAuthCode) error {
	_, err := s.DB.ExecContext(ctx,
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
	return nil
}

// ConsumeOAuthCode deletes and returns the authorization code entry. Returns
// ErrOAuthNotFound when the row is absent, expired, or already consumed.
// Expiry is checked on read against ttl so callers are not subject to sweeper
// timing.
func (s *Store) ConsumeOAuthCode(ctx context.Context, code string, ttl time.Duration) (*OAuthCode, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("consume oauth_auth_codes: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var c OAuthCode
	var tgUsername, scope sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT code, client_id, redirect_uri, code_challenge, challenge_method,
		        telegram_id, telegram_username, scope, created_at
		   FROM oauth_auth_codes
		  WHERE code = $1`,
		code,
	).Scan(
		&c.Code, &c.ClientID, &c.RedirectURI, &c.CodeChallenge, &c.ChallengeMethod,
		&c.TelegramID, &tgUsername, &scope, &c.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrOAuthNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consume oauth_auth_codes: query: %w", err)
	}
	c.TelegramUsername = tgUsername.String
	c.Scope = scope.String

	// Defensive TTL check on read.
	if time.Since(c.CreatedAt) > ttl {
		_, _ = tx.ExecContext(ctx, `DELETE FROM oauth_auth_codes WHERE code = $1`, code)
		_ = tx.Commit()
		return nil, ErrOAuthNotFound
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM oauth_auth_codes WHERE code = $1`, code); err != nil {
		return nil, fmt.Errorf("consume oauth_auth_codes: delete: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("consume oauth_auth_codes: commit: %w", err)
	}
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
func (s *Store) DeleteExpiredClientRegs(ctx context.Context, ttl time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-ttl)
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM oauth_client_registrations WHERE created_at < $1`, cutoff,
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
