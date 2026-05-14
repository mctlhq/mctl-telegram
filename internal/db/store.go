package db

import (
	"context"
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
// Any prior active row for the user is marked revoked.
func (s *Store) SaveSession(ctx context.Context, userID int64, plaintext []byte, telegramUserID int64, displayName, username string) error {
	blob, err := s.Crypt.Seal(plaintext)
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
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, display_name, username, session_encrypted)
		 VALUES($1,$2,$3,$4,$5)`,
		userID, telegramUserID, nullable(displayName), nullable(username), blob,
	); err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return tx.Commit()
}

// LoadSession returns the decrypted session blob for the active telegram account of the user.
// Returns (nil, nil) when no active session.
func (s *Store) LoadSession(ctx context.Context, userID int64) ([]byte, error) {
	var blob []byte
	err := s.DB.QueryRowContext(ctx,
		`SELECT session_encrypted FROM telegram_accounts
		 WHERE user_id = $1 AND revoked_at IS NULL
		 ORDER BY connected_at DESC LIMIT 1`,
		userID,
	).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query session: %w", err)
	}
	pt, err := s.Crypt.Open(blob)
	if err != nil {
		return nil, fmt.Errorf("decrypt session: %w", err)
	}
	return pt, nil
}

// UpdateSessionBlob is called by the gotd SessionStorage when MTProto rotates session bytes.
// Creates a row if no active session exists yet (rare — usually login created one first).
func (s *Store) UpdateSessionBlob(ctx context.Context, userID int64, plaintext []byte) error {
	blob, err := s.Crypt.Seal(plaintext)
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

// LogToolCall writes one audit row. Errors are non-fatal to the caller.
func (s *Store) LogToolCall(ctx context.Context, userID int64, tool, peerRedacted, status, errMsg string) {
	_, _ = s.DB.ExecContext(ctx,
		`INSERT INTO audit_logs(user_id, tool_name, peer_redacted, status, error)
		 VALUES($1,$2,$3,$4,$5)`,
		userID, tool, nullable(peerRedacted), status, nullable(errMsg),
	)
}

func nullable(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
