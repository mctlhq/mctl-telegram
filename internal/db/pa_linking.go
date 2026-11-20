package db

// pa_linking.go holds the single-use secrets of the Personal Assistant
// linking flow (issue #1314, threat model T1) and the users row a PA
// principal gets on its first connection (owner decision 2026-11-19 on
// #1312).
//
// Every secret is stored as the SHA-256 of its value only: a database reader
// learns no link token, state, handoff or completion code it could replay.
// Each row is consumed at most once, by compare-and-set, and only while it
// has not expired.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// PAProvider is users.provider for a row created by the Personal Assistant:
// a principal whose first contact with MCTL is a PA connection, not a tg-mcp
// login. A later tg-mcp login promotes the row to "tg-mcp".
const PAProvider = "pa"

// PALinkKind names the purpose of a linking secret. A secret of one kind is
// never accepted as another.
type PALinkKind string

const (
	// PALinkToken: the single-use link token behind /connect (T1 step 1),
	// 10-minute TTL, bound to the principal.
	PALinkToken PALinkKind = "link"
	// PALinkState: the OAuth state (T1 step 1-3), 10-minute TTL, bound to
	// principal, server, connection and redirect URI, carrying the PKCE
	// verifier.
	PALinkState PALinkKind = "state"
	// PALinkHandoff: the callback page's "this is my Telegram account"
	// button (T1 step 6), 5-minute TTL.
	PALinkHandoff PALinkKind = "handoff"
	// PALinkCompletion: the completion code in the Mini App start_param (T1
	// step 3-4), 5-minute TTL.
	PALinkCompletion PALinkKind = "completion"
	// PALinkConfirm: the confirm card's callback (T1 step 5), 10-minute TTL,
	// bound to the connection's revision.
	PALinkConfirm PALinkKind = "confirm"
)

func (k PALinkKind) valid() bool {
	switch k {
	case PALinkToken, PALinkState, PALinkHandoff, PALinkCompletion, PALinkConfirm:
		return true
	}
	return false
}

// PALinkSecret is one linking secret row. Hash is the hex SHA-256 of the
// secret value; the value itself is never stored.
type PALinkSecret struct {
	Hash         string
	Kind         PALinkKind
	Principal    int64
	Server       string
	ConnectionID string
	// Revision is the connection's authority revision the secret was minted
	// at (0 when not bound to one).
	Revision int64
	// Verifier is the PKCE code verifier (state rows only). It is useless
	// without the authorization code, which is sealed under the connection
	// DEK.
	Verifier string
	// RedirectURI is the exact redirect URI the state was issued for.
	RedirectURI string
	// AccountHint is the masked Telegram account the callback page names.
	AccountHint string
	ExpiresAt   time.Time
	ConsumedAt  time.Time
}

// Errors of ConsumePALinkSecret. ErrPALinkUnknown also covers a hash of
// another kind: a secret is never reported as existing under a kind it was
// not minted for.
var (
	ErrPALinkUnknown  = errors.New("pa link: unknown secret")
	ErrPALinkConsumed = errors.New("pa link: secret already used")
	ErrPALinkExpired  = errors.New("pa link: secret expired")
)

func paLinkingSchema(pg bool) []string {
	intT := "INTEGER"
	if pg {
		intT = "BIGINT"
	}
	return []string{
		`CREATE TABLE IF NOT EXISTS pa_link_secrets (
			hash TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			principal ` + intT + ` NOT NULL,
			server TEXT NOT NULL,
			connection_id TEXT NOT NULL DEFAULT '',
			revision ` + intT + ` NOT NULL DEFAULT 0,
			verifier TEXT NOT NULL DEFAULT '',
			redirect_uri TEXT NOT NULL DEFAULT '',
			account_hint TEXT NOT NULL DEFAULT '',
			expires_at_ms ` + intT + ` NOT NULL,
			consumed_at_ms ` + intT + ` NOT NULL DEFAULT 0,
			created_at_ms ` + intT + ` NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_pa_link_secrets_expiry ON pa_link_secrets(kind, consumed_at_ms, expires_at_ms)`,
	}
}

func migratePALinking(ctx context.Context, dbConn migrateDB, pg bool) error {
	for _, s := range paLinkingSchema(pg) {
		if _, err := dbConn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate pa_link_secrets: %w", err)
		}
	}
	return nil
}

const paLinkCols = `hash, kind, principal, server, connection_id, revision, verifier, redirect_uri,
	account_hint, expires_at_ms, consumed_at_ms`

func scanPALink(r paRowScanner) (PALinkSecret, error) {
	var (
		l             PALinkSecret
		kind          string
		expMS, consMS int64
	)
	if err := r.Scan(&l.Hash, &kind, &l.Principal, &l.Server, &l.ConnectionID, &l.Revision, &l.Verifier,
		&l.RedirectURI, &l.AccountHint, &expMS, &consMS); err != nil {
		return PALinkSecret{}, err
	}
	l.Kind = PALinkKind(kind)
	l.ExpiresAt = time.UnixMilli(expMS).UTC()
	if consMS > 0 {
		l.ConsumedAt = time.UnixMilli(consMS).UTC()
	}
	return l, nil
}

// paConsumeAfterRead is a test seam: it runs between the read and the
// compare-and-set of ConsumePALinkSecret. Always nil outside tests.
var paConsumeAfterRead func(ctx context.Context, hash string)

// CreatePALinkSecret inserts a new, unconsumed linking secret.
func (s *Store) CreatePALinkSecret(ctx context.Context, l PALinkSecret, now time.Time) error {
	if len(l.Hash) != 64 || !l.Kind.valid() || l.Principal <= 0 || l.Server == "" || !l.ExpiresAt.After(now) {
		return errors.New("pa link: a secret needs a sha256 hash, a kind, a principal, a server and a future expiry")
	}
	_, err := s.DB.ExecContext(ctx, `INSERT INTO pa_link_secrets(`+paLinkCols+`, created_at_ms)
		VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 0, $11)`,
		l.Hash, string(l.Kind), l.Principal, l.Server, l.ConnectionID, l.Revision, l.Verifier,
		l.RedirectURI, l.AccountHint, l.ExpiresAt.UnixMilli(), now.UnixMilli())
	if err != nil {
		return fmt.Errorf("pa link: create: %w", err)
	}
	return nil
}

// ConsumePALinkSecret consumes the secret of kind with hash, once.
//
// The row is read in a transaction; check, when non-nil, runs on it before
// anything changes, and an error from check is returned with the secret
// left unconsumed (a different Telegram user opening a principal's link must
// not burn it, S1-L3, S1-L6). The consume itself is a compare-and-set on
// consumed_at_ms = 0 and expires_at_ms > now, so two concurrent consumers
// get one success.
//
// Errors: ErrPALinkUnknown, ErrPALinkConsumed, ErrPALinkExpired (returned
// together with the row, minus its verifier, so the caller can fail the
// connection it was bound to), check's error, or a wrapped store error. A
// failed read is never "unknown".
func (s *Store) ConsumePALinkSecret(ctx context.Context, kind PALinkKind, hash string, now time.Time, check func(PALinkSecret) error) (PALinkSecret, error) {
	if !kind.valid() {
		return PALinkSecret{}, errors.New("pa link: unknown kind")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return PALinkSecret{}, fmt.Errorf("pa link: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	l, err := scanPALink(tx.QueryRowContext(ctx,
		`SELECT `+paLinkCols+` FROM pa_link_secrets WHERE hash = $1 AND kind = $2`, hash, string(kind)))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return PALinkSecret{}, ErrPALinkUnknown
	case err != nil:
		return PALinkSecret{}, fmt.Errorf("pa link: read: %w", err)
	}
	if !l.ConsumedAt.IsZero() {
		return PALinkSecret{}, ErrPALinkConsumed
	}
	if !l.ExpiresAt.After(now) {
		// The row comes back with the error so the caller can fail the
		// connection it was bound to; it stays unconsumed for the sweeper.
		l.Verifier = ""
		return l, ErrPALinkExpired
	}
	if check != nil {
		if err := check(l); err != nil {
			return PALinkSecret{}, err
		}
	}
	if paConsumeAfterRead != nil {
		paConsumeAfterRead(ctx, hash)
	}
	// The PKCE verifier is cleared as the row is consumed; the caller gets
	// it once, from this read.
	res, err := tx.ExecContext(ctx, `UPDATE pa_link_secrets SET consumed_at_ms = $1, verifier = ''
		WHERE hash = $2 AND kind = $3 AND consumed_at_ms = 0 AND expires_at_ms > $4`,
		now.UnixMilli(), hash, string(kind), now.UnixMilli())
	if err != nil {
		return PALinkSecret{}, fmt.Errorf("pa link: consume: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return PALinkSecret{}, fmt.Errorf("pa link: consume: rows affected: %w", err)
	}
	if n != 1 {
		return PALinkSecret{}, ErrPALinkConsumed
	}
	if err := tx.Commit(); err != nil {
		return PALinkSecret{}, fmt.Errorf("pa link: commit: %w", err)
	}
	l.ConsumedAt = now.UTC()
	return l, nil
}

// ExpiredPALinkSecrets lists up to limit unconsumed secrets of kind that
// expired at or before now, oldest first. The linking sweeper uses it to
// fail connections whose confirm card was never answered.
func (s *Store) ExpiredPALinkSecrets(ctx context.Context, kind PALinkKind, now time.Time, limit int) ([]PALinkSecret, error) {
	if !kind.valid() || limit <= 0 {
		return nil, errors.New("pa link: list expired needs a kind and a positive limit")
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT `+paLinkCols+` FROM pa_link_secrets
		WHERE kind = $1 AND consumed_at_ms = 0 AND expires_at_ms <= $2
		ORDER BY expires_at_ms, hash LIMIT $3`, string(kind), now.UnixMilli(), limit)
	if err != nil {
		return nil, fmt.Errorf("pa link: list expired: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []PALinkSecret{}
	for rows.Next() {
		l, err := scanPALink(rows)
		if err != nil {
			return nil, fmt.Errorf("pa link: list expired: scan: %w", err)
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pa link: list expired: %w", err)
	}
	return out, nil
}

// RetirePALinkSecret marks an expired secret consumed, so the sweeper does
// not list it again. It refuses a secret that has not expired at now.
func (s *Store) RetirePALinkSecret(ctx context.Context, kind PALinkKind, hash string, now time.Time) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE pa_link_secrets SET consumed_at_ms = $1, verifier = ''
		WHERE hash = $2 AND kind = $3 AND consumed_at_ms = 0 AND expires_at_ms <= $1`,
		now.UnixMilli(), hash, string(kind))
	if err != nil {
		return fmt.Errorf("pa link: retire: %w", err)
	}
	return nil
}

// paEnsureAfterResolve is a test seam: it runs inside EnsurePAUser's
// transaction right after the first lookup, so a test can make a failed
// lookup transient and prove the failure alone stops the insert.
var paEnsureAfterResolve func(ctx context.Context, tx *sql.Tx)

// EnsurePAUser returns the users.id of a PA principal, creating the row on
// its first PA connection (owner decision 2026-11-19, #1312 decision 2) so
// the ADR 0003 audit chain has a user to append to.
//
// It resolves first, with the same lookup the audit sink uses, and inserts
// only when that lookup positively finds no user. An existing user of any
// provider, including one known only through telegram_accounts, is returned
// unchanged: inserting a second row for it would make every later lookup of
// that Telegram id ambiguous. A legacy "tg:<id>" row without
// telegram_login_id is backfilled and returned, not duplicated. A failed lookup is an error, never "no user".
// A row created here has provider "pa", which tells PA-only principals apart
// from tg-mcp logins. No display name or username is stored.
func (s *Store) EnsurePAUser(ctx context.Context, tgID int64) (int64, error) {
	if tgID <= 0 {
		return 0, errors.New("telegram id must be positive")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("pa user: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	id, err := userIDByTelegramID(ctx, tx, tgID)
	if paEnsureAfterResolve != nil {
		paEnsureAfterResolve(ctx, tx)
	}
	switch {
	case err == nil:
		return id, nil
	case !errors.Is(err, ErrUserNotFound):
		return 0, fmt.Errorf("pa user: resolve: %w", err)
	}
	// A legacy tg-mcp row may carry the synthetic login without having been
	// backfilled with telegram_login_id (the shape EnsureUserByTelegramID
	// falls back to). Backfill it so it is this principal's row; the INSERT
	// below would otherwise hit its github_login and do nothing.
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET telegram_login_id = $1 WHERE github_login = $2 AND telegram_login_id IS NULL`,
		tgID, fmt.Sprintf("tg:%d", tgID),
	); err != nil {
		return 0, fmt.Errorf("pa user: backfill legacy row: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO users(github_login, provider, telegram_login_id)
		 VALUES($1, $2, $3)
		 ON CONFLICT DO NOTHING`,
		fmt.Sprintf("tg:%d", tgID), PAProvider, tgID,
	); err != nil {
		return 0, fmt.Errorf("insert pa user: %w", err)
	}
	if id, err = userIDByTelegramID(ctx, tx, tgID); err != nil {
		return 0, fmt.Errorf("pa user: resolve after insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("pa user: commit: %w", err)
	}
	return id, nil
}

// promotePAUserTx marks the PA-created row of tgID as a tg-mcp login, inside
// the sign-in transaction, and reports whether it did. It runs under a
// savepoint so a failure leaves the sign-in intact: the marker is a label
// for reporting and broadcast eligibility.
//
// promotePAUser is the same outside a transaction, for sign-in paths that
// have none (EnsureUserByTelegramID: localjwt, worker tokens, k8ssa,
// provision_local_account).
func (s *Store) promotePAUser(ctx context.Context, tgID int64) {
	_, _ = s.DB.ExecContext(ctx, `UPDATE users SET provider = $1 WHERE telegram_login_id = $2 AND provider = $3`,
		"tg-mcp", tgID, PAProvider)
}

func (s *Store) promotePAUserTx(ctx context.Context, tx *sql.Tx, tgID int64) bool {
	if _, err := tx.ExecContext(ctx, `SAVEPOINT pa_promote`); err != nil {
		return false
	}
	res, err := tx.ExecContext(ctx, `UPDATE users SET provider = $1 WHERE telegram_login_id = $2 AND provider = $3`,
		"tg-mcp", tgID, PAProvider)
	if err != nil {
		_, _ = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT pa_promote`)
		return false
	}
	n, err := res.RowsAffected()
	if err != nil {
		_, _ = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT pa_promote`)
		return false
	}
	_, _ = tx.ExecContext(ctx, `RELEASE SAVEPOINT pa_promote`)
	return n == 1
}
