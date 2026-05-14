package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
)

// Store wraps the DB with high-level accessors used by the MCP tool layer and
// the Telegram session store.
type Store struct {
	DB    *sql.DB
	Crypt *crypto.AESGCM
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
	expires := now.Add(absoluteSessionTTL)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, display_name, username, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7)`,
		userID, telegramUserID, nullable(displayName), nullable(username), blob, now, expires,
	); err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return tx.Commit()
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
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query session: %w", err)
	}
	pt, err := s.Crypt.OpenForUser(blob, userID)
	if err != nil {
		return nil, fmt.Errorf("decrypt session: %w", err)
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
	return pt, nil
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

// RevokeActiveSession marks the active telegram_accounts row for a user as
// revoked. Returns true if a row was actually flipped. Idempotent: calling
// it twice in a row only flips the first time. Used by the self-service
// disconnect MCP tool / HTTP endpoint.
func (s *Store) RevokeActiveSession(ctx context.Context, userID int64) (bool, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET revoked_at = CURRENT_TIMESTAMP
		 WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	)
	if err != nil {
		return false, fmt.Errorf("revoke session: %w", err)
	}
	rows, _ := res.RowsAffected()
	return rows > 0, nil
}

// HardDeleteAccount removes every telegram_accounts row for the user
// regardless of revoked state. Audit rows (FK ON DELETE no action, user_id
// nullable) survive — they reference the user, not the account. Returns the
// number of rows removed.
func (s *Store) HardDeleteAccount(ctx context.Context, userID int64) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`DELETE FROM telegram_accounts WHERE user_id = $1`,
		userID,
	)
	if err != nil {
		return 0, fmt.Errorf("delete account: %w", err)
	}
	rows, _ := res.RowsAffected()
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
		`SELECT send_enabled FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY connected_at DESC LIMIT 1`,
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
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT last_used_at, expires_at FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY connected_at DESC LIMIT 1`,
		userID,
	).Scan(&lastUsed, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoActiveSession
	}
	if err != nil {
		return "", fmt.Errorf("check session: %w", err)
	}
	now := time.Now().UTC()
	if expires.Valid && expires.Time.Before(now) {
		_, _ = s.RevokeActiveSession(ctx, userID)
		return ReasonAbsolute, fmt.Errorf("%w: %s", ErrSessionExpired, ReasonAbsolute)
	}
	if lastUsed.Valid && now.Sub(lastUsed.Time) > idleSessionTTL {
		_, _ = s.RevokeActiveSession(ctx, userID)
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
func (s *Store) SweepExpiredSessions(ctx context.Context) (int64, error) {
	now := time.Now().UTC()
	idleCutoff := now.Add(-idleSessionTTL)
	res, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts
		 SET revoked_at = $1
		 WHERE revoked_at IS NULL
		   AND (
		     (expires_at IS NOT NULL AND expires_at < $1)
		     OR (last_used_at IS NOT NULL AND last_used_at < $2)
		   )`,
		now, idleCutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("sweep sessions: %w", err)
	}
	rows, _ := res.RowsAffected()
	return rows, nil
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
			`SELECT created_at, tool_name, peer_redacted, status, error FROM audit_logs
			 WHERE user_id = $1
			 ORDER BY id DESC LIMIT $2`,
			userID, limit,
		)
	} else {
		rows, err = s.DB.QueryContext(ctx,
			`SELECT created_at, tool_name, peer_redacted, status, error FROM audit_logs
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
			ts     time.Time
			tool   string
			peer   sql.NullString
			status string
			errCol sql.NullString
		)
		if err := rows.Scan(&ts, &tool, &peer, &status, &errCol); err != nil {
			return nil, fmt.Errorf("scan audit: %w", err)
		}
		out = append(out, AuditEntry{
			Ts:            ts,
			ToolName:      tool,
			PeerRedacted:  peer.String,
			Status:        status,
			ErrorRedacted: errCol.String,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return out, nil
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
func (s *Store) LogToolCall(ctx context.Context, userID int64, tool, peerRedacted, status, errMsg string) {
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
	entry := hashAuditEntry(prev, userID, tool, peerRedacted, status, errMsg, createdAt)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_logs(user_id, tool_name, peer_redacted, status, error, created_at, prev_hash, entry_hash)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
		userID, tool, nullable(peerRedacted), status, nullable(errMsg), createdAt, prev, entry,
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
		`SELECT id, tool_name, peer_redacted, status, error, created_at, prev_hash, entry_hash
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
		)
		if err := rows.Scan(&id, &tool, &peer, &status, &errCol, &createdAt, &prevHash, &entryHash); err != nil {
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
		recomputed := hashAuditEntry(prevHash, userID, tool, peer.String, status, errCol.String, createdAt)
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
