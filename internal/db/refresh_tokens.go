package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrRefreshTokenNotFound is returned by LookupRefreshToken and
// RotateRefreshToken when no row matches the presented opaque token.
var ErrRefreshTokenNotFound = errors.New("refresh token not found")

// RefreshToken is a persisted OAuth refresh token. The opaque token string is
// never stored — only its SHA-256 digest (token_hash). FamilyID ties a token
// to its rotation lineage: every rotation keeps the same FamilyID, so a
// replayed (already-rotated) token can be traced back to the whole family and
// revoke it. Persisting refresh tokens — unlike the in-memory authorization
// codes — is what lets an MCP client survive a pod restart without re-running
// the Telegram Login Widget flow.
type RefreshToken struct {
	FamilyID         string
	UserID           int64
	ClientID         string
	ClientName       string // display name of the OAuth client, e.g. "Claude", "ChatGPT"
	TelegramID       int64
	TelegramUsername string
	Scope            string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	RevokedAt        time.Time // zero value ⇒ still active
	// RevokedReason distinguishes why RevokedAt was set: "rotated" (normal
	// rotation superseded this row — the only case eligible for grace-window
	// replay recovery), "reuse_detected", or "explicit_revoke". Empty when
	// the row is still active.
	RevokedReason string
	// ParentTokenHash is the SHA-256 hash of the predecessor token this row
	// was rotated from, or nil for a family's first-issued token. Lets a
	// grace-window replay of the predecessor be verified against its live
	// successor with one indexed lookup (see LookupRefreshTokenByHashPair).
	ParentTokenHash []byte
}

// Revoked reports whether the token has been revoked — by rotation, by a
// family-revoke after reuse detection, or by an operator action.
func (rt *RefreshToken) Revoked() bool { return !rt.RevokedAt.IsZero() }

// Expired reports whether the token is past its absolute expiry as of now.
func (rt *RefreshToken) Expired(now time.Time) bool { return now.After(rt.ExpiresAt) }

// execer is the subset of *sql.DB / *sql.Tx that saveRefreshToken needs, so
// the INSERT can run either standalone or inside the rotation transaction.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// hashRefreshToken returns the SHA-256 digest of an opaque refresh token. The
// digest is what we persist and index on; the plaintext never reaches the DB.
// SHA-256 (no HMAC) is sufficient because the token is a 256-bit random value
// — there is no low-entropy input to defend against. Matches the audit-chain
// and PKCE hashing already used in this codebase.
func hashRefreshToken(plaintext string) []byte {
	sum := sha256.Sum256([]byte(plaintext))
	return sum[:]
}

// SaveRefreshToken inserts a new refresh-token row. plaintext is hashed before
// storage; rt.ExpiresAt must already be set by the caller.
func (s *Store) SaveRefreshToken(ctx context.Context, plaintext string, rt RefreshToken) error {
	return saveRefreshToken(ctx, s.DB, plaintext, rt)
}

func saveRefreshToken(ctx context.Context, ex execer, plaintext string, rt RefreshToken) error {
	if plaintext == "" {
		return errors.New("refresh token plaintext required")
	}
	if rt.FamilyID == "" {
		return errors.New("refresh token family id required")
	}
	if _, err := ex.ExecContext(ctx,
		`INSERT INTO oauth_refresh_tokens
		   (family_id, token_hash, user_id, client_id, telegram_id, telegram_username, scope, client_name, expires_at, parent_token_hash)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		rt.FamilyID, hashRefreshToken(plaintext), rt.UserID, rt.ClientID,
		rt.TelegramID, nullable(rt.TelegramUsername), nullable(rt.Scope), rt.ClientName, rt.ExpiresAt.UTC(),
		nullableBytes(rt.ParentTokenHash),
	); err != nil {
		return fmt.Errorf("insert refresh token: %w", err)
	}
	return nil
}

// nullableBytes converts a nil/empty byte slice to a driver NULL, since a
// zero-length []byte would otherwise be written as an empty BYTEA/BLOB
// instead of SQL NULL.
func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// LookupRefreshToken returns the row matching the presented opaque token,
// including its revoked/expiry state so the caller can tell a replayed
// (already-rotated) token apart from an expired one — the two demand different
// responses. Returns ErrRefreshTokenNotFound when no row matches.
func (s *Store) LookupRefreshToken(ctx context.Context, plaintext string) (*RefreshToken, error) {
	if plaintext == "" {
		return nil, ErrRefreshTokenNotFound
	}
	var (
		rt       RefreshToken
		username sql.NullString
		scope    sql.NullString
		revoked  sql.NullTime
		reason   sql.NullString
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT family_id, user_id, client_id, telegram_id, telegram_username,
		        scope, client_name, created_at, expires_at, revoked_at, revoked_reason
		   FROM oauth_refresh_tokens WHERE token_hash = $1`,
		hashRefreshToken(plaintext),
	).Scan(&rt.FamilyID, &rt.UserID, &rt.ClientID, &rt.TelegramID, &username,
		&scope, &rt.ClientName, &rt.CreatedAt, &rt.ExpiresAt, &revoked, &reason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lookup refresh token: %w", err)
	}
	rt.TelegramUsername = username.String
	rt.Scope = scope.String
	if revoked.Valid {
		rt.RevokedAt = revoked.Time
	}
	rt.RevokedReason = reason.String
	return &rt, nil
}

// LookupRefreshTokenByHashPair verifies whether newPlaintext is the live,
// unrevoked successor of oldPlaintext within the given family/client — the
// exact check a grace-window replay needs before re-issuing an existing
// successor instead of failing the caller. Returns ErrRefreshTokenNotFound
// if no such row exists (wrong client, successor itself already superseded,
// or the row is missing) — callers must treat that as "not eligible for
// grace recovery", not as evidence of anything about oldPlaintext itself.
func (s *Store) LookupRefreshTokenByHashPair(ctx context.Context, oldPlaintext, newPlaintext, familyID, clientID string) (*RefreshToken, error) {
	var (
		rt       RefreshToken
		username sql.NullString
		scope    sql.NullString
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT user_id, telegram_id, telegram_username, scope, client_name, created_at, expires_at
		   FROM oauth_refresh_tokens
		  WHERE token_hash = $1 AND parent_token_hash = $2
		    AND family_id = $3 AND client_id = $4
		    AND revoked_at IS NULL`,
		hashRefreshToken(newPlaintext), hashRefreshToken(oldPlaintext), familyID, clientID,
	).Scan(&rt.UserID, &rt.TelegramID, &username, &scope, &rt.ClientName, &rt.CreatedAt, &rt.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lookup refresh token by hash pair: %w", err)
	}
	rt.FamilyID = familyID
	rt.ClientID = clientID
	rt.TelegramUsername = username.String
	rt.Scope = scope.String
	return &rt, nil
}

// RotateRefreshToken atomically revokes the presented (old) token and inserts
// its replacement. Both share a transaction: a crash between the two writes
// must not leave the old token spent with no replacement, nor a new token
// alongside a still-live old one. The new row carries the same FamilyID so the
// rotation lineage — and therefore reuse detection — is preserved.
//
// Returns ErrRefreshTokenNotFound when the old token is already gone or
// revoked (a lost race against a concurrent rotation): the caller must then
// not hand out the new token.
func (s *Store) RotateRefreshToken(ctx context.Context, oldPlaintext, newPlaintext string, newRT RefreshToken) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin rotate tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	oldHash := hashRefreshToken(oldPlaintext)
	res, err := tx.ExecContext(ctx,
		`UPDATE oauth_refresh_tokens SET revoked_at = $1, revoked_reason = 'rotated'
		 WHERE token_hash = $2 AND revoked_at IS NULL`,
		time.Now().UTC(), oldHash,
	)
	if err != nil {
		return fmt.Errorf("revoke old refresh token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrRefreshTokenNotFound
	}
	newRT.ParentTokenHash = oldHash
	if err := saveRefreshToken(ctx, tx, newPlaintext, newRT); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit rotate tx: %w", err)
	}
	return nil
}

// RevokeRefreshTokenFamily revokes every still-active token in a family with
// the given reason (e.g. "reuse_detected", "explicit_revoke"). It is the
// response to a reuse-detection event: an already-rotated token is presented
// again outside its grace window, meaning either an honest client's retry
// arrived too late or a stolen token is in play. In both cases the safe move
// is to kill the lineage and force a fresh login. Returns the number of rows
// revoked.
func (s *Store) RevokeRefreshTokenFamily(ctx context.Context, familyID, reason string) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE oauth_refresh_tokens SET revoked_at = $1, revoked_reason = $2
		 WHERE family_id = $3 AND revoked_at IS NULL`,
		time.Now().UTC(), reason, familyID,
	)
	if err != nil {
		return 0, fmt.Errorf("revoke refresh token family: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// SweepExpiredRefreshTokens hard-deletes refresh-token rows that are past their
// absolute expiry. Rotated-but-not-yet-expired rows are deliberately kept: a
// revoked row still inside its original TTL is what makes reuse detection
// work, and once a row is past expiry a replayed token would be rejected as
// expired anyway, so deleting it loses nothing. The per-request
// LookupRefreshToken check stays authoritative; this sweep only bounds table
// growth. Returns the number of rows removed.
func (s *Store) SweepExpiredRefreshTokens(ctx context.Context) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM oauth_refresh_tokens WHERE expires_at < $1`,
		time.Now().UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("sweep refresh tokens: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
