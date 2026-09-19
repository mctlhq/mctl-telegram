package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TelegramIdentityCapture is the input to EnsureUserByTelegramCapture: a
// Telegram-native identity observation with explicit source attribution, as
// opposed to EnsureUserByTelegramID's bare username/displayName pair.
type TelegramIdentityCapture struct {
	TelegramID int64
	Username   string
	FirstName  string
	LastName   string
	// Source identifies the surface that captured this identity, e.g.
	// "telegram_oidc" or "local_bridge_activation". Stamped into
	// users.identity_source.
	Source string
	// CapturedAt is stamped into users.identity_captured_at. Callers should
	// pass time.Now().UTC().
	CapturedAt time.Time
}

// EnsureUserByTelegramCapture is EnsureUserByTelegramID's sibling for call
// sites that already hold split first/last name claims from a verified
// source (Telegram OIDC, Local Bridge activation). It exists instead of
// growing EnsureUserByTelegramID's parameter list because the two have
// different, deliberately incompatible username semantics:
//
//   - EnsureUserByTelegramID falls back to the display name when username is
//     empty (effectiveUsername), which is exactly the behaviour that made
//     users.telegram_username unreliable — see design.md. Its three existing
//     callers (internal/auth/localjwt/issuer.go, internal/oauth/server.go's
//     worker-token path, internal/mcp/tools.go) depend on that fallback and
//     are left untouched.
//   - EnsureUserByTelegramCapture writes telegram_username with NO fallback:
//     an empty username stays empty, so its provenance reads as
//     "not_supplied" rather than silently holding a display name.
//
// It reuses EnsureUserByTelegramID's race-safe INSERT ... ON CONFLICT DO
// NOTHING + SELECT shape and the COALESCE(NULLIF($1,''), col) refresh
// pattern, and additionally always stamps identity_captured_at,
// identity_source and last_seen_at (a capture is definitionally an
// authentication event).
func (s *Store) EnsureUserByTelegramCapture(ctx context.Context, c TelegramIdentityCapture) (int64, error) {
	if c.TelegramID <= 0 {
		return 0, errors.New("telegram id must be positive")
	}
	if c.Source == "" {
		return 0, errors.New("identity source is required")
	}
	capturedAt := c.CapturedAt
	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}
	displayName := strings.TrimSpace(c.FirstName + " " + c.LastName)
	syntheticLogin := fmt.Sprintf("tg:%d", c.TelegramID)

	// Insert-or-no-op, same ON CONFLICT DO NOTHING shape as
	// EnsureUserByTelegramID: covers both the telegram_login_id unique
	// partial index and the legacy github_login UNIQUE constraint.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO users(
		     github_login, provider, telegram_login_id, telegram_username, telegram_display_name,
		     telegram_first_name, telegram_last_name, identity_source, identity_captured_at, last_seen_at
		 )
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)
		 ON CONFLICT DO NOTHING`,
		syntheticLogin, "tg-mcp", c.TelegramID, nullable(c.Username), nullable(displayName),
		nullable(c.FirstName), nullable(c.LastName), c.Source, capturedAt,
	); err != nil {
		return 0, fmt.Errorf("insert user by tg_id capture: %w", err)
	}
	var id int64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT id FROM users WHERE telegram_login_id=$1`, c.TelegramID,
	).Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			if err2 := s.DB.QueryRowContext(ctx,
				`SELECT id FROM users WHERE github_login=$1`, syntheticLogin,
			).Scan(&id); err2 != nil {
				return 0, fmt.Errorf("select user by tg_id capture (fallback): %w", err2)
			}
		} else {
			return 0, fmt.Errorf("select user by tg_id capture: %w", err)
		}
	}
	// Refresh on every call — a client re-authenticating always advances
	// last_seen_at and re-stamps identity_source/identity_captured_at, and
	// COALESCE(NULLIF($n,''), col) means an attribute Telegram no longer
	// supplies is NOT clobbered back to empty by a later call that omits it
	// (mirrors EnsureUserByTelegramID's refresh). telegram_username and
	// telegram_first_name/telegram_last_name deliberately have NO
	// display-name fallback: an empty capture writes/leaves them empty
	// rather than substituting displayName.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE users SET
		     telegram_username = COALESCE(NULLIF($1,''), telegram_username),
		     telegram_display_name = COALESCE(NULLIF($2,''), telegram_display_name),
		     telegram_first_name = COALESCE(NULLIF($3,''), telegram_first_name),
		     telegram_last_name = COALESCE(NULLIF($4,''), telegram_last_name),
		     identity_source = $5,
		     identity_captured_at = $6,
		     last_seen_at = $6
		 WHERE id = $7`,
		c.Username, displayName, c.FirstName, c.LastName, c.Source, capturedAt, id,
	); err != nil {
		return 0, fmt.Errorf("refresh identity capture: %w", err)
	}
	return id, nil
}
