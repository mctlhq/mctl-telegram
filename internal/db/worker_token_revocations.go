package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// WorkerTokenRevocation is one row of worker_token_revocations. Jti == ""
// (a NULL column) marks a blanket revocation for TelegramID; a non-empty Jti
// marks a single-token revocation, in which case TelegramID is recorded for
// audit purposes only — the revocation lookup never consults it for a
// jti-scoped row, only the blanket branch does.
type WorkerTokenRevocation struct {
	Jti        string
	TelegramID int64
	RevokedAt  time.Time
}

// RevokeWorkerToken records a jti-scoped revocation. Any worker token
// carrying this jti — including every renewal of it, since renewal carries
// the jti forward unchanged (internal/workertoken/renewhandler.go) — is
// rejected by localjwt.Provider.Authenticate once the revocation cache next
// refreshes (bounded by localjwt.MaxRevocationCacheTTL). telegramID is stored
// for audit/debugging only. Re-revoking the same jti is a no-op, not an
// error.
func (s *Store) RevokeWorkerToken(ctx context.Context, jti string, telegramID int64, reason string, revokedBy int64) error {
	if jti == "" {
		return errors.New("revoke worker token: jti required")
	}
	// revoked_at is set explicitly from Go's clock rather than left to the
	// column's DEFAULT CURRENT_TIMESTAMP: IsWorkerTokenRevoked compares
	// revoked_at against a Go time.Time parameter (a token's orig_iat/iat),
	// and SQLite stores DATETIME as TEXT — CURRENT_TIMESTAMP's
	// "YYYY-MM-DD HH:MM:SS" format and the driver's own time.Time parameter
	// formatting are not guaranteed to agree byte-for-byte at the second
	// boundary, which broke exact-equality comparisons in testing. Sourcing
	// both sides from the same marshaling path avoids that entirely.
	now := time.Now().UTC()
	if s.isPostgres(ctx) {
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO worker_token_revocations (jti, telegram_id, revoked_at, reason, revoked_by)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (jti) DO NOTHING`,
			jti, telegramID, now, nullable(reason), nullableInt(revokedBy),
		); err != nil {
			return fmt.Errorf("revoke worker token: %w", err)
		}
		return nil
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT OR IGNORE INTO worker_token_revocations (jti, telegram_id, revoked_at, reason, revoked_by)
		 VALUES ($1, $2, $3, $4, $5)`,
		jti, telegramID, now, nullable(reason), nullableInt(revokedBy),
	); err != nil {
		return fmt.Errorf("revoke worker token: %w", err)
	}
	return nil
}

// RevokeWorkerTokensForTelegramID records a blanket revocation for
// telegramID: every worker token for that id whose OriginalIssuedAt (falling
// back to IssuedAt) is at or before this moment is rejected, including ones
// whose jti the operator never learned. A token minted for this id AFTER the
// revocation timestamp is unaffected — see IsWorkerTokenRevoked.
func (s *Store) RevokeWorkerTokensForTelegramID(ctx context.Context, telegramID int64, reason string, revokedBy int64) error {
	if telegramID <= 0 {
		return errors.New("revoke worker tokens: telegram_id required")
	}
	// See RevokeWorkerToken's comment on why revoked_at is set explicitly
	// from Go's clock rather than the column's DEFAULT CURRENT_TIMESTAMP —
	// this row's revoked_at is compared directly against a token's
	// orig_iat/iat in IsWorkerTokenRevoked, so format consistency matters
	// here more than in the jti-scoped path.
	now := time.Now().UTC()
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO worker_token_revocations (jti, telegram_id, revoked_at, reason, revoked_by)
		 VALUES (NULL, $1, $2, $3, $4)`,
		telegramID, now, nullable(reason), nullableInt(revokedBy),
	); err != nil {
		return fmt.Errorf("revoke worker tokens for telegram id: %w", err)
	}
	return nil
}

// IsWorkerTokenRevoked reports whether jti is individually denylisted, or
// telegramID carries a blanket revocation recorded at or after issuedAt --
// that is, a revocation that postdates the token covers it.
//
// Request-path verification does not come through here: localjwt's
// RevocationCache loads whole rows via ListWorkerTokenRevocations and compares
// instants in Go, so a jti-bearing request never pays a DB round trip on the
// cache-warm path. This method exists for callers that want a direct answer.
//
// issuedAt is normalised to UTC before the comparison. SQLite compares
// DATETIME values as text, and the stored revoked_at is written in UTC, so a
// caller passing a local-zone time would have its offset compared as if it
// were part of the clock reading: a +02:00 instant reads as two hours later
// than the same moment in UTC and a genuine revocation silently answers
// false. Failing open on a timezone is not an acceptable mode for this
// question.
func (s *Store) IsWorkerTokenRevoked(ctx context.Context, jti string, telegramID int64, issuedAt time.Time) (bool, error) {
	var exists bool
	if err := s.DB.QueryRowContext(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM worker_token_revocations
			WHERE jti = $1
			   OR (jti IS NULL AND telegram_id = $2 AND revoked_at >= $3)
		 )`,
		jti, telegramID, issuedAt.UTC(),
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("check worker token revocation: %w", err)
	}
	return exists, nil
}

// ListWorkerTokenRevocations returns every revocation row, jti-scoped and
// blanket alike. Expected to hold single-digit rows: this backs
// localjwt.RevocationCache's periodic refresh, not a per-request query.
func (s *Store) ListWorkerTokenRevocations(ctx context.Context) ([]WorkerTokenRevocation, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT jti, telegram_id, revoked_at FROM worker_token_revocations`,
	)
	if err != nil {
		return nil, fmt.Errorf("list worker token revocations: %w", err)
	}
	defer rows.Close()
	var out []WorkerTokenRevocation
	for rows.Next() {
		var jti sql.NullString
		var tgID int64
		var revokedAt time.Time
		if err := rows.Scan(&jti, &tgID, &revokedAt); err != nil {
			return nil, fmt.Errorf("scan worker token revocation: %w", err)
		}
		out = append(out, WorkerTokenRevocation{Jti: jti.String, TelegramID: tgID, RevokedAt: revokedAt})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list worker token revocations: %w", err)
	}
	return out, nil
}
