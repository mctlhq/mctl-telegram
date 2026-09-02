package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// Store wraps the DB with high-level accessors used by the MCP tool layer and
// the Telegram session store.
type Store struct {
	DB      *sql.DB
	Crypt   *crypto.AESGCM
	metrics *metrics.Registry

	// ttlExempt holds Telegram ids whose sessions never hit the absolute or
	// idle TTL. Read-only after construction; see WithAbsoluteTTLExempt.
	ttlExempt map[int64]bool

	// Cached dialect probe (see isPostgres in agent_jobs.go). Only the job
	// claim query needs the distinction (FOR UPDATE SKIP LOCKED). pgResolved
	// is set only once the probe returns a definitive answer, so a transient
	// probe failure does not permanently poison the cache.
	pgMu       sync.Mutex
	pgResolved bool
	pgFlag     bool
}

// AccountInfo is the user-visible projection of a telegram_accounts row,
// suitable for GET /api/account responses. PII like telegram_user_id stays
// hidden; only connection-state fields are surfaced.
type AccountInfo struct {
	Connected   bool      `json:"connected"`
	DisplayName string    `json:"display_name,omitempty"`
	Username    string    `json:"username,omitempty"`
	SendEnabled bool      `json:"send_enabled"`
	ConnectedAt time.Time `json:"connected_at,omitempty"`
}

func NewStore(db *sql.DB, c *crypto.AESGCM) *Store {
	return &Store{DB: db, Crypt: c}
}

// WithAbsoluteTTLExempt marks Telegram ids whose sessions are not subject to
// the absolute TTL or the idle TTL. Returns the receiver for chaining.
//
// The absolute-TTL exemption is expressed as expires_at IS NULL on the row
// rather than as an extra predicate in every query: "no absolute expiry" is
// already what NULL means to CheckSessionValid, SweepAbsoluteSessions and
// ListIdentities alike, so nothing downstream has to learn about exempt
// identities. The idle-TTL exemption cannot use the same trick (last_used_at
// is overwritten on every use, see MarkLastUsed), so CheckSessionValid,
// SweepIdleSessions and ListIdentities instead evaluate this map (via
// ttlExemptClause for the set-based queries) as a real predicate on every
// check.
func (s *Store) WithAbsoluteTTLExempt(ids []int64) *Store {
	if len(ids) == 0 {
		s.ttlExempt = nil
		return s
	}
	s.ttlExempt = make(map[int64]bool, len(ids))
	for _, id := range ids {
		s.ttlExempt[id] = true
	}
	return s
}

// ReconcileTTLExemptions converges existing rows onto the current exemption
// list. Call it after Migrate: the migration backfills expires_at on every
// run, which deliberately re-arms the TTL for an identity that has been
// removed from the list, and this clears it again for the ones still on it.
// Returns the number of rows cleared.
func (s *Store) ReconcileTTLExemptions(ctx context.Context) (int64, error) {
	if len(s.ttlExempt) == 0 {
		return 0, nil
	}
	ids := make([]int64, 0, len(s.ttlExempt))
	for id := range s.ttlExempt {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	var total int64
	for _, id := range ids {
		res, err := s.DB.ExecContext(ctx,
			`UPDATE telegram_accounts SET expires_at = NULL
			 WHERE telegram_user_id = $1 AND expires_at IS NOT NULL`,
			id,
		)
		if err != nil {
			return total, fmt.Errorf("clear absolute ttl for %d: %w", id, err)
		}
		n, _ := res.RowsAffected()
		total += n
	}
	return total, nil
}

// ttlExemptClause returns a SQL fragment ("" if no ids are exempt) plus its
// bind args, so callers can splice "AND telegram_user_id NOT IN (...)" (or
// the inverted "OR telegram_user_id IN (...)" form for ListIdentities) into
// a query that already has argIdx-1 placeholders bound. Placeholders start
// at argIdx and count up by one per exempt id. Ids are sorted so the
// generated SQL text (and therefore the prepared-statement cache key) is
// stable across calls, mirroring ReconcileTTLExemptions.
func (s *Store) ttlExemptClause(argIdx int) (fragment string, args []any) {
	if len(s.ttlExempt) == 0 {
		return "", nil
	}
	ids := make([]int64, 0, len(s.ttlExempt))
	for id := range s.ttlExempt {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	placeholders := make([]string, len(ids))
	args = make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", argIdx+i)
		args[i] = id
	}
	return "(" + strings.Join(placeholders, ",") + ")", args
}

// WithMetrics wires a *metrics.Registry so session lifecycle events are
// counted. Returns the receiver for chaining.
func (s *Store) WithMetrics(m *metrics.Registry) *Store {
	s.metrics = m
	return s
}

// EnsureUser creates a user row by github_login if absent and returns the user id.
func (s *Store) EnsureUser(ctx context.Context, login, email, provider string) (int64, error) {
	if login == "" {
		return 0, errors.New("login required")
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO users(github_login, email, provider) VALUES($1,$2,$3)
		 ON CONFLICT (github_login) DO NOTHING`,
		login, nullable(email), provider,
	); err != nil {
		return 0, fmt.Errorf("insert user: %w", err)
	}
	var id int64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT id FROM users WHERE github_login=$1`, login,
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("select user: %w", err)
	}
	return id, nil
}

// EnsureUserByTelegramID is the Telegram-native counterpart of EnsureUser.
// It is the canonical identity-binding call for the localjwt provider and
// the OAuth Login Widget callback: given a Telegram user id (and optional
// username/displayName), it returns the internal users.id row, creating one
// if absent.
//
// SQLite still requires github_login NOT NULL — we satisfy the constraint by
// stamping a synthetic "tg:<id>" string so legacy code that joins on
// github_login keeps working. New code should always prefer telegram_login_id.
// On Postgres the column has been dropped to nullable, but we still stamp
// the synthetic value for cross-dialect consistency.
//
// The optional username/displayName are refreshed on every call so the row
// stays current when Telegram returns newer values during widget reauth.
//
// Race safety: this function is called concurrently from /oauth/* and the
// localjwt middleware on bearer auth. A naive read-then-insert pattern would
// allow two callers to both observe sql.ErrNoRows and then race on the
// UNIQUE index — one would succeed, the other would surface a 500. We use
// INSERT ... ON CONFLICT DO NOTHING followed by a SELECT, which is safe
// under SERIALIZABLE/RC isolation on both Postgres and SQLite (the loser of
// the race simply observes the winner's row on the SELECT).
func (s *Store) EnsureUserByTelegramID(ctx context.Context, tgID int64, username, displayName string) (int64, error) {
	if tgID <= 0 {
		return 0, errors.New("telegram id must be positive")
	}
	syntheticLogin := fmt.Sprintf("tg:%d", tgID)
	effectiveUsername := username
	if effectiveUsername == "" {
		effectiveUsername = displayName
	}
	// Insert-or-no-op. ON CONFLICT covers both the telegram_login_id unique
	// partial index and the legacy github_login UNIQUE constraint — we use
	// the unqualified DO NOTHING form which fires on any conflict.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO users(github_login, provider, telegram_login_id, telegram_username, telegram_display_name)
		 VALUES($1,$2,$3,$4,$5)
		 ON CONFLICT DO NOTHING`,
		syntheticLogin, "tg-mcp", tgID, nullable(effectiveUsername), nullable(displayName),
	); err != nil {
		return 0, fmt.Errorf("insert user by tg_id: %w", err)
	}
	var id int64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT id FROM users WHERE telegram_login_id=$1`, tgID,
	).Scan(&id); err != nil {
		// Fall back to the synthetic github_login lookup in the unlikely
		// case that an older row already carries the synthetic login but
		// has not been backfilled with telegram_login_id yet.
		if errors.Is(err, sql.ErrNoRows) {
			if err2 := s.DB.QueryRowContext(ctx,
				`SELECT id FROM users WHERE github_login=$1`, syntheticLogin,
			).Scan(&id); err2 != nil {
				return 0, fmt.Errorf("select user by tg_id (fallback): %w", err2)
			}
		} else {
			return 0, fmt.Errorf("select user by tg_id: %w", err)
		}
	}
	// Best-effort refresh of metadata. Idempotent and safe to skip on error
	// because the next call will retry; surfacing it would block auth.
	if username != "" || displayName != "" {
		_, _ = s.DB.ExecContext(ctx,
			`UPDATE users SET telegram_username = COALESCE(NULLIF($1,''), telegram_username),
			                  telegram_display_name = COALESCE(NULLIF($2,''), telegram_display_name)
			 WHERE id = $3`,
			effectiveUsername, displayName, id,
		)
	}
	return id, nil
}

// UserIDByTelegramID resolves a Telegram user id to the internal users.id
// WITHOUT creating a row — the read-only counterpart of
// EnsureUserByTelegramID. It accepts both login identities and finalised
// connected accounts so local-dev/shared-HMAC users can be administered too.
// Multiple distinct owners fail closed instead of choosing one tenant.
func (s *Store) UserIDByTelegramID(ctx context.Context, tgID int64) (int64, error) {
	if tgID <= 0 {
		return 0, errors.New("telegram id must be positive")
	}
	var (
		id    sql.NullInt64
		count int
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT MIN(user_id), COUNT(DISTINCT user_id)
		   FROM (
		         SELECT id AS user_id FROM users WHERE telegram_login_id = $1
		         UNION ALL
		         SELECT user_id FROM telegram_accounts WHERE telegram_user_id = $1
		        ) AS candidates`,
		tgID,
	).Scan(&id, &count)
	if err != nil {
		return 0, fmt.Errorf("select user by tg_id: %w", err)
	}
	if count == 0 || !id.Valid {
		return 0, ErrUserNotFound
	}
	if count > 1 {
		return 0, fmt.Errorf("%w: telegram id maps to %d users", ErrTelegramIdentityAmbiguous, count)
	}
	return id.Int64, nil
}

// Access tiers stored in users.access_tier. NULL is treated as TierNone.
// Admins are governed by the TG_LOGIN_ADMINS env allowlist, not this column.
const (
	TierNone   = "none"
	TierClient = "client"
)

// Account modes stored in telegram_accounts.mode. ModeHosted is the default:
// the server holds the MTProto session. ModeLocal routes calls to a Local
// Bridge daemon on the user's own machine instead.
const (
	ModeLocal  = "local"
	ModeHosted = "hosted"
)

// IdentityRow is the admin-facing projection of a users row: who has
// authenticated, their access tier, and whether they hold an active session.
type IdentityRow struct {
	TelegramID  int64     `json:"telegram_id"`
	Username    string    `json:"username,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	AccessTier  string    `json:"access_tier"`
	HasSession  bool      `json:"has_session"`
	CreatedAt   time.Time `json:"created_at"`
	// ConnectedVia lists distinct OAuth client names (e.g. "Claude", "ChatGPT")
	// for which this user holds a non-expired, non-revoked refresh token. Empty
	// when the user has never completed an OAuth flow or all tokens predate
	// dynamic client registration.
	ConnectedVia []string `json:"connected_via,omitempty"`
}

// SetAccessTier sets users.access_tier for the user with the given Telegram
// id. Returns an error when no such row exists — the user must have signed in
// through the widget at least once before a tier can be granted.
func (s *Store) SetAccessTier(ctx context.Context, tgID int64, tier string) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE users SET access_tier = $2 WHERE telegram_login_id = $1`,
		tgID, tier,
	)
	if err != nil {
		return fmt.Errorf("set access_tier: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("no user with telegram id %d — they must sign in once first", tgID)
	}
	return nil
}

// GetAccessTier returns the explicit users.access_tier value for a Telegram
// id: "" when the user has no row or a NULL tier (unset — the caller should
// fall back to the env bootstrap allowlist), or "client"/"none" when the tool
// has set it explicitly. An explicit value is authoritative over the env.
func (s *Store) GetAccessTier(ctx context.Context, tgID int64) (string, error) {
	var tier sql.NullString
	err := s.DB.QueryRowContext(ctx,
		`SELECT access_tier FROM users WHERE telegram_login_id = $1`, tgID,
	).Scan(&tier)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("query access_tier: %w", err)
	}
	if !tier.Valid {
		return "", nil
	}
	return tier.String, nil
}

// ListIdentities returns every widget-authenticated user with their raw
// access tier, join time, and whether they currently hold a *usable* MTProto
// session — non-revoked, finalised (telegram_user_id set), AND within both the
// absolute and idle TTLs, matching what CheckSessionValid would accept.
// Newest first.
//
// AccessTier is the raw users.access_tier value: "" (unset), "client", or
// "none". Callers that care about the effective tier must apply the
// auto-approve rule themselves — see ResolveScopes / the digest.
func (s *Store) ListIdentities(ctx context.Context) ([]IdentityRow, error) {
	now := time.Now().UTC()
	idleCutoff := now.Add(-idleSessionTTL)
	query := `SELECT u.telegram_login_id, u.telegram_username, u.telegram_display_name,
	        u.access_tier, u.created_at,
	        EXISTS(SELECT 1 FROM telegram_accounts ta
	               WHERE ta.user_id = u.id AND ta.revoked_at IS NULL
	                 AND ta.telegram_user_id IS NOT NULL
	                 AND (ta.expires_at IS NULL OR ta.expires_at > $1)
	                 AND (ta.last_used_at IS NULL OR ta.last_used_at > $2`
	args := []any{now, idleCutoff}
	if clause, exemptArgs := s.ttlExemptClause(3); clause != "" {
		query += " OR ta.telegram_user_id IN " + clause
		args = append(args, exemptArgs...)
	}
	query += `))
	   FROM users u
	  WHERE u.telegram_login_id IS NOT NULL
	  ORDER BY u.id DESC`
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list identities: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []IdentityRow
	for rows.Next() {
		var (
			r        IdentityRow
			username sql.NullString
			display  sql.NullString
			tier     sql.NullString
		)
		if err := rows.Scan(&r.TelegramID, &username, &display, &tier, &r.CreatedAt, &r.HasSession); err != nil {
			return nil, fmt.Errorf("scan identity: %w", err)
		}
		r.Username = username.String
		r.DisplayName = display.String
		r.AccessTier = tier.String // "" when the column is NULL (unset)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Fetch connected_via: distinct non-empty client names denormalized onto
	// oauth_refresh_tokens at issue time, so the field survives oauth_client_registrations TTL sweeps.
	clientRows, err := s.DB.QueryContext(ctx,
		`SELECT u.telegram_login_id, rt.client_name
		   FROM users u
		   JOIN oauth_refresh_tokens rt ON rt.user_id = u.id
		  WHERE u.telegram_login_id IS NOT NULL
		    AND rt.revoked_at IS NULL
		    AND rt.expires_at > $1
		    AND rt.client_name <> ''
		  GROUP BY u.telegram_login_id, rt.client_name
		  ORDER BY u.telegram_login_id, rt.client_name`,
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("list identities client names: %w", err)
	}
	defer func() { _ = clientRows.Close() }()

	// Build index by TelegramID for O(n) merge.
	idx := make(map[int64]int, len(out))
	for i, r := range out {
		idx[r.TelegramID] = i
	}
	for clientRows.Next() {
		var tgID int64
		var clientName string
		if err := clientRows.Scan(&tgID, &clientName); err != nil {
			return nil, fmt.Errorf("scan client name: %w", err)
		}
		if i, ok := idx[tgID]; ok {
			out[i].ConnectedVia = append(out[i].ConnectedVia, clientName)
		}
	}
	return out, clientRows.Err()
}

// SaveSession upserts (logically) the active telegram account for a user, encrypting the blob.
// Any prior active row for the user is marked revoked. Writes always use
// SealForUser (VersionPerUser, 0x02); legacy v1 rows are migrated on read
// by LoadSession.
func (s *Store) SaveSession(ctx context.Context, userID int64, plaintext []byte, telegramUserID int64, displayName, username string) error {
	blob, err := s.Crypt.SealForUser(plaintext, userID)
	if err != nil {
		return fmt.Errorf("encrypt session: %w", err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`UPDATE telegram_accounts SET revoked_at = CURRENT_TIMESTAMP
		 WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	); err != nil {
		return fmt.Errorf("revoke prior: %w", err)
	}
	now := time.Now().UTC()
	// An exempt identity gets a NULL expires_at, which every absolute-TTL
	// reader already treats as "never expires" — see WithAbsoluteTTLExempt.
	var expires any = now.Add(absoluteSessionTTL)
	if s.ttlExempt[telegramUserID] {
		expires = nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, display_name, username, session_encrypted, last_used_at, expires_at, send_enabled)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		userID, telegramUserID, nullable(displayName), nullable(username), blob, now, expires, false,
	); err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if s.metrics != nil {
		s.metrics.SessionsConnectedTotal.Inc()
	}
	return nil
}

// Session TTL policy. Borrow refuses a session whose last_used_at is older
// than idleSessionTTL OR whose expires_at is in the past. Sessions are
// stamped expires_at = connected_at + absoluteSessionTTL on insert and the
// Migrate backfill applies the same delta to legacy rows.
const (
	idleSessionTTL     = 30 * 24 * time.Hour
	absoluteSessionTTL = 90 * 24 * time.Hour
)

// LoadSession returns the decrypted session blob for the active telegram
// account of the user. Returns (nil, nil) when no active session.
//
// Performs lazy migration from VersionMaster (v1, single global key) to
// VersionPerUser (v2, HKDF-derived per-user subkey): when an old row is
// successfully decrypted, the plaintext is re-sealed under the v2 scheme
// and the column is rewritten in-place. The migration is silent and best
// effort — a failure to write the new blob does not surface to the caller
// (the next read will retry).
func (s *Store) LoadSession(ctx context.Context, userID int64) ([]byte, error) {
	pt, _, err := s.LoadSessionWithID(ctx, userID)
	return pt, err
}

// LoadSessionWithID returns the decrypted active session and the immutable
// database row id that supplied it. The id lets a long-lived runtime revoke
// exactly the rejected auth key without racing a later OAuth reconnect.
func (s *Store) LoadSessionWithID(ctx context.Context, userID int64) ([]byte, int64, error) {
	var (
		rowID int64
		blob  []byte
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, session_encrypted FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY connected_at DESC LIMIT 1`,
		userID,
	).Scan(&rowID, &blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("query session: %w", err)
	}
	// An account provisioned directly as local-only has no server-held
	// session: session_encrypted is NULL. Its row is not revoked, so it
	// matches the query above and reaches here with an empty blob. Report
	// that the same way as "this user has no row at all" — attempting to
	// decrypt it makes an account that never had a session look like one
	// whose session is corrupt, which is a different and alarming thing.
	// SaveSession always writes a sealed blob, so empty means absent.
	if len(blob) == 0 {
		return nil, 0, nil
	}
	pt, err := s.Crypt.OpenForUser(blob, userID)
	if err != nil {
		return nil, 0, fmt.Errorf("decrypt session: %w", err)
	}
	// Lazy migration: only rewrap when we are running with real encryption.
	// Local-dev (VersionPlaintext) rows stay as-is to avoid surprising
	// developers who deleted ENCRYPTION_KEY.
	//
	// The UPDATE is CAS-bound to (row id, original ciphertext): if anyone
	// rotated the blob between our SELECT and this UPDATE (concurrent
	// SaveSession, UpdateSessionBlob, or a parallel migration write), the
	// WHERE clause won't match and the migration becomes a no-op. The next
	// LoadSession on whatever the row currently holds will retry. This
	// prevents the lost-update scenario flagged by codex on PR #3 where a
	// stale v1 plaintext could overwrite a newer v2 blob.
	if s.Crypt.Enabled() && s.Crypt.BlobVersion(blob) == crypto.VersionMaster {
		if newBlob, sealErr := s.Crypt.SealForUser(pt, userID); sealErr == nil {
			_, _ = s.DB.ExecContext(ctx,
				`UPDATE telegram_accounts SET session_encrypted = $1
				 WHERE id = $2 AND session_encrypted = $3`,
				newBlob, rowID, blob,
			)
		}
	}
	return pt, rowID, nil
}

// UpdateSessionBlob is called by the gotd SessionStorage when MTProto rotates
// session bytes. Creates a row if no active session exists yet (rare —
// usually login created one first). Always writes VersionPerUser.
func (s *Store) UpdateSessionBlob(ctx context.Context, userID int64, plaintext []byte) error {
	blob, err := s.Crypt.SealForUser(plaintext, userID)
	if err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET session_encrypted = $1
		 WHERE user_id = $2 AND revoked_at IS NULL`,
		blob, userID,
	)
	if err != nil {
		return fmt.Errorf("update session blob: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		_, err = s.DB.ExecContext(ctx,
			`INSERT INTO telegram_accounts(user_id, session_encrypted) VALUES($1,$2)`,
			userID, blob,
		)
		if err != nil {
			return fmt.Errorf("insert fresh session: %w", err)
		}
	}
	return nil
}

// UpdateSessionBlobByID rotates the bytes of the exact session row loaded by
// a long-lived gotd client. A replacement OAuth session may already be active;
// binding the write to the immutable row id prevents the old client from
// overwriting the replacement's auth key.
func (s *Store) UpdateSessionBlobByID(ctx context.Context, userID, sessionID int64, plaintext []byte) error {
	if sessionID <= 0 {
		return fmt.Errorf("update session blob by id: invalid session id")
	}
	blob, err := s.Crypt.SealForUser(plaintext, userID)
	if err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET session_encrypted = $1
		 WHERE id = $2 AND user_id = $3 AND revoked_at IS NULL`,
		blob, sessionID, userID,
	)
	if err != nil {
		return fmt.Errorf("update session blob by id: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return ErrNoActiveSession
	}
	return nil
}

// RevokeActiveSession marks the active telegram_accounts row for a user as
// revoked. Returns true if a row was actually flipped. Idempotent: calling
// it twice in a row only flips the first time.
//
// reason is recorded in mctl_sessions_revoked_total{reason} when a metrics
// registry is wired. Callers should pass one of: "disconnect" (self-service
// disconnect MCP tool / HTTP endpoint), "idle_expiry" (CheckSessionValid idle
// TTL gate), "absolute_expiry" (CheckSessionValid absolute TTL gate).
func (s *Store) RevokeActiveSession(ctx context.Context, userID int64, reason string) (bool, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET revoked_at = CURRENT_TIMESTAMP
		 WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	)
	if err != nil {
		return false, fmt.Errorf("revoke session: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows > 0 && s.metrics != nil && reason != "" {
		s.metrics.SessionsRevokedTotal.WithLabelValues(reason).Inc()
	}
	return rows > 0, nil
}

// RevokeSessionByID revokes one specific active session row. Runtime clients
// use this after Telegram rejects the auth key they loaded: a concurrent OAuth
// reconnect may already have inserted a newer active row for the same user, so
// revoking by user_id alone could invalidate the replacement session.
func (s *Store) RevokeSessionByID(ctx context.Context, userID, sessionID int64, reason string) (bool, error) {
	if sessionID <= 0 {
		return false, nil
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET revoked_at = CURRENT_TIMESTAMP
		 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		sessionID, userID,
	)
	if err != nil {
		return false, fmt.Errorf("revoke session by id: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows > 0 && s.metrics != nil && reason != "" {
		s.metrics.SessionsRevokedTotal.WithLabelValues(reason).Inc()
	}
	return rows > 0, nil
}

// HardDeleteAccount removes every telegram_accounts row for the user
// regardless of revoked state. Audit rows (FK ON DELETE no action, user_id
// nullable) survive — they reference the user, not the account. Returns the
// number of rows removed.
func (s *Store) HardDeleteAccount(ctx context.Context, userID int64) (int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("delete account: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Count rows that are still active BEFORE the delete. Only those count as
	// "revoked by delete" for the metric — rows already carrying a revoked_at
	// were revoked earlier for another reason and must not inflate
	// mctl_sessions_revoked_total{reason="delete"}. Doing the count and the
	// delete in one transaction keeps them race-free.
	var activeRows int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	).Scan(&activeRows); err != nil {
		return 0, fmt.Errorf("delete account: count active: %w", err)
	}

	res, err := tx.ExecContext(ctx,
		`DELETE FROM telegram_accounts WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return 0, fmt.Errorf("delete account: %w", err)
	}
	rows, _ := res.RowsAffected()

	// Purge communication-agent data in the same transaction. The agent
	// tables cascade on users(id), but account deletion removes only the
	// telegram_accounts row (the users identity row survives), so the agent
	// rows must be deleted explicitly or a deleted account's recruiter
	// conversations, events, leads, actions, and notifications would persist.
	if err := purgeAgentData(ctx, tx, userID); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("delete account: commit: %w", err)
	}
	if activeRows > 0 && s.metrics != nil {
		s.metrics.SessionsRevokedTotal.WithLabelValues("delete").Add(float64(activeRows))
	}
	return rows, nil
}

// GetActiveAccount returns the active telegram account for a user, or
// Connected=false if none. Used by GET /api/account.
func (s *Store) GetActiveAccount(ctx context.Context, userID int64) (*AccountInfo, error) {
	var (
		displayName sql.NullString
		username    sql.NullString
		sendEnabled bool
		connectedAt time.Time
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT display_name, username, send_enabled, connected_at FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY connected_at DESC LIMIT 1`,
		userID,
	).Scan(&displayName, &username, &sendEnabled, &connectedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return &AccountInfo{Connected: false}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query account: %w", err)
	}
	return &AccountInfo{
		Connected:   true,
		DisplayName: displayName.String,
		Username:    username.String,
		SendEnabled: sendEnabled,
		ConnectedAt: connectedAt,
	}, nil
}

// IsSendEnabled reads telegram_accounts.send_enabled for the user's active
// session. Returns false (no error) when there is no active session — the
// caller will already reject for a different reason in that case.
func (s *Store) IsSendEnabled(ctx context.Context, userID int64) (bool, error) {
	var enabled bool
	err := s.DB.QueryRowContext(ctx,
		`SELECT send_enabled FROM telegram_accounts WHERE `+actionableAccount,
		userID,
	).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("query send_enabled: %w", err)
	}
	return enabled, nil
}

// SetSendEnabled flips telegram_accounts.send_enabled on the user's active
// session row. Used by the in-browser enable_access flow when the user opts
// into real message sending during onboarding, so the operator no longer has
// to run a manual UPDATE. Returns the number of rows affected (0 when the user
// has no active session) so callers that act on behalf of an operator can tell
// a real update from a silent no-op; the enable_access flow ignores it because
// it provisions the session first.
func (s *Store) SetSendEnabled(ctx context.Context, userID int64, enabled bool) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET send_enabled = $2 WHERE `+actionableAccount,
		userID, enabled,
	)
	if err != nil {
		return 0, fmt.Errorf("set send_enabled: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// SetAccountMode flips telegram_accounts.mode ('hosted' or 'local') on the
// user's active session row. Used by the set_account_mode admin tool so
// enabling Local Bridge for an account is a runtime call instead of a
// one-shot gitops Job. Returns the number of rows affected (0 when the
// user has no active session) so the caller can distinguish a real update
// from a silent no-op, matching SetSendEnabled.
func (s *Store) SetAccountMode(ctx context.Context, userID int64, mode string) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET mode = $2 WHERE `+actionableAccount,
		userID, mode,
	)
	if err != nil {
		return 0, fmt.Errorf("set account mode: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// currentAccountRow selects the row GetAccountMode answers about: the user's
// most recent account row, revoked or not. The predicate that follows decides
// whether it may be acted on -- a revoked hosted row may not (its session is
// gone), a local row may (its vestigial hosted session is irrelevant to a
// bridge account, which is the whole point of mode surviving revocation).
//
// The id DESC tiebreaker is not cosmetic. connected_at defaults to
// CURRENT_TIMESTAMP, which SQLite resolves to whole seconds, so two rows
// written in the same second compare equal and LIMIT 1 picks arbitrarily.
// The design this implements rests on "a fresh hosted login always inserts a
// newer connected_at and therefore wins", which is false without a tiebreaker
// -- an account could read as local right after reconnecting to hosted. id is
// monotonic per insert, so it orders what the timestamp cannot.
//
// Selecting by id rather than repeating ORDER BY ... LIMIT 1 in each WHERE
// matters: filtering first and ordering second can land on an OLDER row than
// GetAccountMode chose, which is how these queries silently disagree about
// which account they are talking about.
const currentAccountRow = `SELECT id FROM telegram_accounts WHERE user_id = $1 ORDER BY connected_at DESC, id DESC LIMIT 1`

// actionableAccount is currentAccountRow plus the legitimacy test.
const actionableAccount = `id = (` + currentAccountRow + `) AND (revoked_at IS NULL OR mode = 'local')`

// ErrAccountAlreadyActive is returned by ProvisionLocalAccount when the
// target user already has an active (non-revoked) telegram_accounts row.
// Provisioning is only for brand-new accounts; migrating an existing one
// (hosted or local) to local mode is SetAccountMode's job.
var ErrAccountAlreadyActive = errors.New("account already active")

// ProvisionLocalAccount creates a local-only telegram_accounts row for a
// user who has never completed a hosted login: session_encrypted is left
// NULL (there is no server-held session to store), mode is 'local' from
// insert, and last_used_at/expires_at stay NULL since there is no session
// for the idle/absolute TTL sweepers to measure -- the sweepers instead
// exclude mode = 'local' rows outright (see SweepIdleSessions).
//
// Refuses with ErrAccountAlreadyActive if the user already has an active
// row, so an existing hosted account is not silently duplicated -- the
// caller should point the operator at set_account_mode for migrating an
// existing account instead.
//
// The check and the insert are one statement rather than a SELECT followed
// by an INSERT, so there is no window between them inside this call. That is
// not the same as being safe against two concurrent calls: under READ
// COMMITTED both can still evaluate NOT EXISTS as true and both insert. A
// transaction does not close that either, which an earlier version of this
// comment wrongly claimed. Closing it properly needs a partial unique index
// on (user_id) WHERE revoked_at IS NULL, which cannot be added blind because
// it would fail to build if any user already has two active rows. Provisioning
// is an operator action taken once per account, so the residual race is
// accepted and named here rather than papered over.
func (s *Store) ProvisionLocalAccount(ctx context.Context, userID, tgID int64, displayName, username string) error {
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, display_name, username, session_encrypted, mode, send_enabled)
		 SELECT $1,$2,$3,$4,NULL,$5,$6
		 WHERE NOT EXISTS (SELECT 1 FROM telegram_accounts WHERE user_id = $1 AND revoked_at IS NULL)`,
		userID, tgID, nullable(displayName), nullable(username), ModeLocal, false,
	)
	if err != nil {
		return fmt.Errorf("insert local account: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("insert local account: %w", err)
	}
	if n == 0 {
		return ErrAccountAlreadyActive
	}
	return nil
}

// ToggleSendEnabled atomically inverts send_enabled on the user's active
// session row. Using a single UPDATE avoids the read-modify-write race that
// exists when callers read IsSendEnabled and then call SetSendEnabled in two
// separate round-trips. Returns the new value of send_enabled.
func (s *Store) ToggleSendEnabled(ctx context.Context, userID int64) (bool, error) {
	var newVal bool
	err := s.DB.QueryRowContext(ctx,
		`UPDATE telegram_accounts SET send_enabled = NOT send_enabled WHERE `+actionableAccount+`
		 RETURNING send_enabled`,
		userID,
	).Scan(&newVal)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("toggle send_enabled: %w", err)
	}
	return newVal, nil
}

// MarkLastUsed updates last_used_at on the active session for the user. Best
// effort — a failure does not surface to the caller; the next call will
// retry. Called from Pool.Borrow on every successful tool dispatch so the
// idle-TTL clock resets while the user is active.
func (s *Store) MarkLastUsed(ctx context.Context, userID int64) {
	_, _ = s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET last_used_at = $1
		 WHERE user_id = $2 AND revoked_at IS NULL`,
		time.Now().UTC(), userID,
	)
}

// ErrSessionExpired is returned by CheckSessionValid when the user's active
// session has tripped either the idle or the absolute TTL. Callers translate
// this into a user-visible message and force a fresh login.
var ErrSessionExpired = errors.New("session expired")

// ErrNoActiveSession means there is no row at all — used to distinguish
// "expired" from "never connected" so the surface error matches reality.
var ErrNoActiveSession = errors.New("no active session")

// ErrSessionUnauthorized is returned when the user's most-recent session row
// holds MTProto session bytes but never completed authorization: the gotd
// SessionStore persisted bytes mid-login (UpdateSessionBlob) but the
// enable_access flow never completed SaveSession (telegram_user_id stays
// NULL), or a runtime RPC failed with SESSION_PASSWORD_NEEDED. The fix is for
// the user to finish the in-browser setup. CheckSessionValid and
// ClientPool.Borrow revoke the row before returning this so the next
// reconnect re-runs enable_access instead of reloading a dead session.
var ErrSessionUnauthorized = errors.New("session not authorized")

// ErrSessionRevoked is returned when a previously-good MTProto session was
// killed server-side — the user signed it out from another device, or
// Telegram expired/deactivated/banned the account. Unlike ErrSessionUnauthorized
// this is not a half-finished setup, so the user-facing message must not tell
// the user to "finish 2FA". The row is revoked before this is returned.
var ErrSessionRevoked = errors.New("session revoked")

// ErrUserNotFound means no login identity or connected account carries the
// requested Telegram id.
var ErrUserNotFound = errors.New("user not found")

// ErrTelegramIdentityAmbiguous means one Telegram id is attached to multiple
// internal users. Cross-tenant admin/profile operations must fail closed until
// the identity rows are reconciled.
var ErrTelegramIdentityAmbiguous = errors.New("telegram identity is ambiguous")

// SessionExpiryReason captures why CheckSessionValid rejected a session, so
// the caller can include the reason in the audit row / user response. It is
// safe to log unredacted.
type SessionExpiryReason string

const (
	ReasonIdle     SessionExpiryReason = "idle-expiry"     // last_used_at older than idleSessionTTL
	ReasonAbsolute SessionExpiryReason = "absolute-expiry" // expires_at in the past
)

// CheckSessionValid returns nil when the user's active session is fresh
// enough to use. When expired it BOTH marks the row revoked (so a
// subsequent Borrow won't keep loading it) AND returns ErrSessionExpired
// wrapped with the human-readable reason. Returns ErrNoActiveSession when
// there is no row at all.
//
// Called by Pool.Borrow before allocating or reusing a client. Holding the
// pool mutex around this check is the caller's responsibility — see
// telegram.ClientPool.Borrow.
func (s *Store) CheckSessionValid(ctx context.Context, userID int64) (SessionExpiryReason, error) {
	var (
		lastUsed sql.NullTime
		expires  sql.NullTime
		tgUserID sql.NullInt64
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT last_used_at, expires_at, telegram_user_id FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY connected_at DESC LIMIT 1`,
		userID,
	).Scan(&lastUsed, &expires, &tgUserID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoActiveSession
	}
	if err != nil {
		return "", fmt.Errorf("check session: %w", err)
	}
	now := time.Now().UTC()
	// telegram_user_id is NULL only on rows the gotd SessionStore inserted
	// mid-login that enable_access never finalised with SaveSession. Such a
	// session carries MTProto bytes but no completed user authorization, so
	// every RPC fails with SESSION_PASSWORD_NEEDED. Revoke it so the next
	// reconnect re-runs enable_access instead of reloading a dead session.
	if !tgUserID.Valid {
		// Use a cancel-free context so the revoke still commits if the
		// request context is already done — mirrors ClientPool.Borrow.
		// If the revoke fails, surface that error instead of
		// ErrSessionUnauthorized: the caller must not route the user
		// into enable_access while the dead partial row is still the
		// newest loadable session, or reauth just reloads it.
		if _, rErr := s.RevokeActiveSession(context.WithoutCancel(ctx), userID, "unauthorized"); rErr != nil {
			return "", fmt.Errorf("revoke unauthorized session: %w", rErr)
		}
		return "", ErrSessionUnauthorized
	}
	if expires.Valid && expires.Time.Before(now) {
		_, _ = s.RevokeActiveSession(ctx, userID, "absolute_expiry")
		return ReasonAbsolute, fmt.Errorf("%w: %s", ErrSessionExpired, ReasonAbsolute)
	}
	if lastUsed.Valid && !s.ttlExempt[tgUserID.Int64] && now.Sub(lastUsed.Time) > idleSessionTTL {
		_, _ = s.RevokeActiveSession(ctx, userID, "idle_expiry")
		return ReasonIdle, fmt.Errorf("%w: %s", ErrSessionExpired, ReasonIdle)
	}
	return "", nil
}

// SweepExpiredSessions revokes every active row whose TTL has elapsed.
// Returns the number of rows flipped. Intended to run on an interval from
// the sweeper goroutine; safe to call concurrently with Borrow because
// CheckSessionValid would have caught the same rows on the next Borrow
// anyway — the sweep just bounds how long an idle row sits in storage
// before being marked revoked.
//
// Deprecated: prefer calling SweepIdleSessions and SweepAbsoluteSessions
// separately so the sweeper can label revoked rows by reason.
func (s *Store) SweepExpiredSessions(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	idleCutoff := now.Add(-idleSessionTTL)
	idlePredicate := `(last_used_at IS NOT NULL AND last_used_at < $2)`
	args := []any{now, idleCutoff}
	if clause, exemptArgs := s.ttlExemptClause(3); clause != "" {
		idlePredicate = `(last_used_at IS NOT NULL AND last_used_at < $2 AND telegram_user_id NOT IN ` + clause + `)`
		args = append(args, exemptArgs...)
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts
		 SET revoked_at = $1
		 WHERE revoked_at IS NULL
		   AND mode <> 'local'
		   AND (
		     (expires_at IS NOT NULL AND expires_at < $1)
		     OR `+idlePredicate+`
		   )`,
		args...,
	)
	if err != nil {
		return 0, fmt.Errorf("sweep sessions: %w", err)
	}
	rows, _ := res.RowsAffected()
	return rows, nil
}

// SweepIdleSessions revokes active rows whose last_used_at is older than the
// idle TTL (30 days). Returns the number of rows flipped. Increments
// mctl_sessions_revoked_total{reason="idle_expiry"} if a metrics registry is
// wired.
func (s *Store) SweepIdleSessions(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	idleCutoff := now.Add(-idleSessionTTL)
	query := `UPDATE telegram_accounts
		 SET revoked_at = $1
		 WHERE revoked_at IS NULL
		   AND mode <> 'local'
		   AND last_used_at IS NOT NULL
		   AND last_used_at < $2`
	args := []any{now, idleCutoff}
	if clause, exemptArgs := s.ttlExemptClause(3); clause != "" {
		query += " AND telegram_user_id NOT IN " + clause
		args = append(args, exemptArgs...)
	}
	res, err := s.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("sweep idle sessions: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows > 0 && s.metrics != nil {
		s.metrics.SessionsRevokedTotal.WithLabelValues("idle_expiry").Add(float64(rows))
	}
	return rows, nil
}

// SweepAbsoluteSessions revokes active rows whose expires_at is in the past
// (absolute TTL 90 days). Returns the number of rows flipped. Increments
// mctl_sessions_revoked_total{reason="absolute_expiry"} if a metrics registry
// is wired.
func (s *Store) SweepAbsoluteSessions(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	res, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts
		 SET revoked_at = $1
		 WHERE revoked_at IS NULL
		   AND mode <> 'local'
		   AND expires_at IS NOT NULL
		   AND expires_at < $1`,
		now,
	)
	if err != nil {
		return 0, fmt.Errorf("sweep absolute sessions: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows > 0 && s.metrics != nil {
		s.metrics.SessionsRevokedTotal.WithLabelValues("absolute_expiry").Add(float64(rows))
	}
	return rows, nil
}

// CountActiveSessions returns the number of non-revoked telegram_accounts rows
// that were last used within the last hour. Freshly created sessions whose
// last_used_at is still NULL are also counted as active. Used by the
// active-session gauge sampler in main(). A nil or query error returns
// (0, err) so the caller can log and skip the gauge update.
//
// This runs once a minute; on a large telegram_accounts table a partial
// index on (revoked_at, last_used_at) WHERE revoked_at IS NULL keeps it
// cheap. Negligible at current scale.
func (s *Store) CountActiveSessions(ctx context.Context) (int64, error) {
	cutoff := time.Now().UTC().Add(-time.Hour)
	var n int64
	err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM telegram_accounts
		 WHERE revoked_at IS NULL
		   AND (last_used_at IS NULL OR last_used_at > $1)`,
		cutoff,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count active sessions: %w", err)
	}
	return n, nil
}

// AuditEntry is the user-visible projection of an audit_logs row. It mirrors
// the schema 1:1 except for the JSON tag names, which match the response
// shape exposed at GET /api/audit and the get_my_audit_log MCP tool.
type AuditEntry struct {
	Ts            time.Time `json:"ts"`
	ToolName      string    `json:"tool_name"`
	PeerRedacted  string    `json:"peer_redacted,omitempty"`
	Status        string    `json:"status"`
	ErrorRedacted string    `json:"error,omitempty"`
	CallPath      string    `json:"call_path,omitempty"`
}

// ListAuditFor returns the user's most recent audit-log rows, newest first.
// limit is clamped to [1, 500]; non-positive limits collapse to 50. before
// is optional — when zero, no upper time bound is applied; when set, only
// rows strictly older than before are returned (useful for keyset pagination
// driven by the client). Returns an empty slice when there is nothing.
//
// The query only ever returns rows owned by userID, so this is safe to call
// directly from an MCP tool or HTTP handler that has already authenticated
// the caller — there is no cross-user leakage path.
func (s *Store) ListAuditFor(ctx context.Context, userID int64, limit int, before time.Time) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	var rows *sql.Rows
	var err error
	if before.IsZero() {
		rows, err = s.DB.QueryContext(ctx,
			`SELECT created_at, tool_name, peer_redacted, status, error, call_path FROM audit_logs
			 WHERE user_id = $1
			 ORDER BY id DESC LIMIT $2`,
			userID, limit,
		)
	} else {
		rows, err = s.DB.QueryContext(ctx,
			`SELECT created_at, tool_name, peer_redacted, status, error, call_path FROM audit_logs
			 WHERE user_id = $1 AND created_at < $2
			 ORDER BY id DESC LIMIT $3`,
			userID, before, limit,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("query audit: %w", err)
	}
	defer rows.Close()
	out := make([]AuditEntry, 0, limit)
	for rows.Next() {
		var (
			ts       time.Time
			tool     string
			peer     sql.NullString
			status   string
			errCol   sql.NullString
			callPath sql.NullString
		)
		if err := rows.Scan(&ts, &tool, &peer, &status, &errCol, &callPath); err != nil {
			return nil, fmt.Errorf("scan audit: %w", err)
		}
		out = append(out, AuditEntry{
			Ts:            ts,
			ToolName:      tool,
			PeerRedacted:  peer.String,
			Status:        status,
			ErrorRedacted: errCol.String,
			CallPath:      callPath.String,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return out, nil
}

// GetAccountMode returns the mode ('hosted' or 'local') for the user's most
// recent account row. Returns "hosted" and no error when the user has no
// account row at all (safe default that keeps the existing hosted-mode
// behaviour for users who haven't been migrated to Local Bridge).
//
// Deliberately does not filter on revoked_at IS NULL: mode is a property of
// the account row, not of whether its embedded hosted session is still
// considered fresh. Revoking a hosted session (idle/absolute TTL sweep,
// explicit disconnect) must not make a local-mode account look hosted again
// -- see the mctl-telegram issue-468 proposal. connected_at DESC LIMIT 1
// still means a fresh hosted SaveSession (which always inserts a new row)
// wins over any older revoked row for the same user.
func (s *Store) GetAccountMode(ctx context.Context, userID int64) (string, error) {
	var mode string
	err := s.DB.QueryRowContext(ctx,
		`SELECT mode FROM telegram_accounts
		 WHERE user_id = $1
		 ORDER BY connected_at DESC, id DESC LIMIT 1`,
		userID,
	).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) {
		return "hosted", nil
	}
	if err != nil {
		return "hosted", fmt.Errorf("query account mode: %w", err)
	}
	return mode, nil
}

// SweepAuditLog removes audit rows older than `retention`. Returns the
// number of rows removed. Called from the audit-retention sweeper.
// retention <= 0 is treated as a no-op so an operator who sets
// AUDIT_RETENTION_DAYS=0 to "keep forever" doesn't have to disable the
// goroutine entirely.
func (s *Store) SweepAuditLog(ctx context.Context, retention time.Duration) (int64, error) {
	if retention <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-retention)
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM audit_logs WHERE created_at < $1`,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("sweep audit: %w", err)
	}
	rows, _ := res.RowsAffected()
	return rows, nil
}

// LogToolCall writes one audit row. Errors are non-fatal to the caller —
// audit must never block a user request — but a write that fails leaves a
// gap in the per-user hash chain that VerifyAuditChain will report.
//
// callPath distinguishes relay-forwarded calls ("local") from server-side
// hosted calls (""). Every M4+ row stores a non-NULL call_path (the empty
// string for hosted calls) so it is distinguishable from pre-M4 rows, whose
// call_path is NULL. Both the stored value and its hash contribution are the
// raw string — see hashAuditEntry, which only folds call_path into the hash
// when it is non-NULL.
//
// Hash-chain semantics (M3.1):
//   - prev_hash = the entry_hash of this user's most recent prior row, or
//     32 bytes of zero when this is the first row for the user.
//   - entry_hash = SHA-256 over the canonical encoding of THIS row's
//     fields (see hashAuditEntry).
//
// The SELECT + INSERT runs in a single transaction with SELECT … FOR
// UPDATE on Postgres so concurrent LogToolCalls for the same user_id
// serialise. SQLite uses BEGIN IMMEDIATE which acquires a write lock for
// the same effect on a single-writer connection. Without this, two
// concurrent writes would race on prev_hash and break the chain.
func (s *Store) LogToolCall(ctx context.Context, userID int64, tool, peerRedacted, status, errMsg, callPath string) {
	createdAt := time.Now().UTC()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()

	var prev []byte
	if err := tx.QueryRowContext(ctx,
		`SELECT entry_hash FROM audit_logs
		 WHERE user_id = $1 AND entry_hash IS NOT NULL
		 ORDER BY id DESC LIMIT 1`,
		userID,
	).Scan(&prev); err != nil {
		// No prior row (sql.ErrNoRows) or a real error — either way we
		// fall back to a zero prev_hash. A zero hash chained at the
		// start of a user's history is acceptable; VerifyAuditChain
		// treats it as the genesis sentinel.
		prev = make([]byte, sha256.Size)
	}
	if len(prev) == 0 {
		prev = make([]byte, sha256.Size)
	}
	entry := hashAuditEntry(prev, userID, tool, peerRedacted, status, errMsg, sql.NullString{String: callPath, Valid: true}, createdAt)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_logs(user_id, tool_name, peer_redacted, status, error, created_at, prev_hash, entry_hash, call_path)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		userID, tool, nullable(peerRedacted), status, nullable(errMsg), createdAt, prev, entry, callPath,
	); err != nil {
		return
	}
	_ = tx.Commit()
}

// AuditChainVerification is the result of recomputing a user's chain.
// When OK is true, every recorded entry_hash matched the recomputed value
// and the chain is contiguous from the first row's prev_hash (= zero) to
// the last. When OK is false, FirstBadID identifies the row whose stored
// entry_hash diverges from the recomputed value (or whose prev_hash
// breaks the chain).
type AuditChainVerification struct {
	OK         bool   `json:"ok"`
	Verified   int64  `json:"verified"`
	FirstBadID int64  `json:"first_bad_id,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// VerifyAuditChain walks the user's audit_logs rows in id-ascending order
// and confirms that each entry_hash equals hashAuditEntry(prev, …) and
// that each prev_hash equals the previous row's entry_hash.
//
// Rows that pre-date the M3.1 columns (prev_hash IS NULL OR entry_hash
// IS NULL) are skipped — they are legacy rows from the pre-chain era and
// cannot be retroactively verified. The walk continues past them so a
// post-M3.1 chain is still checked, but the audit page should make the
// pre-M3.1 gap visible to the user.
func (s *Store) VerifyAuditChain(ctx context.Context, userID int64) (AuditChainVerification, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, tool_name, peer_redacted, status, error, created_at, prev_hash, entry_hash, call_path
		 FROM audit_logs
		 WHERE user_id = $1
		 ORDER BY id ASC`,
		userID,
	)
	if err != nil {
		return AuditChainVerification{}, fmt.Errorf("verify audit: %w", err)
	}
	defer rows.Close()

	var lastEntry []byte
	var verified int64
	for rows.Next() {
		var (
			id        int64
			tool      string
			peer      sql.NullString
			status    string
			errCol    sql.NullString
			createdAt time.Time
			prevHash  []byte
			entryHash []byte
			callPath  sql.NullString
		)
		if err := rows.Scan(&id, &tool, &peer, &status, &errCol, &createdAt, &prevHash, &entryHash, &callPath); err != nil {
			return AuditChainVerification{}, fmt.Errorf("scan audit: %w", err)
		}
		if entryHash == nil || prevHash == nil {
			// Legacy pre-M3.1 row — cannot verify, but reset the chain
			// anchor so a following post-M3.1 row is still checked
			// against its actual prev.
			lastEntry = nil
			continue
		}
		expectedPrev := lastEntry
		if expectedPrev == nil {
			expectedPrev = make([]byte, sha256.Size)
		}
		if !bytesEqual(prevHash, expectedPrev) {
			return AuditChainVerification{
				OK:         false,
				Verified:   verified,
				FirstBadID: id,
				Reason:     "prev_hash does not chain to the previous entry's entry_hash",
			}, nil
		}
		recomputed := hashAuditEntry(prevHash, userID, tool, peer.String, status, errCol.String, callPath, createdAt)
		if !bytesEqual(recomputed, entryHash) {
			return AuditChainVerification{
				OK:         false,
				Verified:   verified,
				FirstBadID: id,
				Reason:     "entry_hash does not match recomputed canonical hash — row may have been tampered with",
			}, nil
		}
		lastEntry = entryHash
		verified++
	}
	if err := rows.Err(); err != nil {
		return AuditChainVerification{}, fmt.Errorf("rows: %w", err)
	}
	return AuditChainVerification{OK: true, Verified: verified}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func nullable(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
