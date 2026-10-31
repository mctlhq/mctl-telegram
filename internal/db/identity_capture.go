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
	// last_seen_at, and COALESCE(NULLIF($n,''), col) means an attribute
	// Telegram no longer supplies is NOT clobbered back to empty by a later
	// call that omits it (mirrors EnsureUserByTelegramID's refresh).
	// telegram_username and telegram_first_name/telegram_last_name
	// deliberately have NO display-name fallback: an empty capture
	// writes/leaves them empty rather than substituting displayName.
	//
	// identity_source/identity_captured_at are advanced when this call
	// supplies a claim (hasClaim) OR when the row has no pre-existing
	// identity attribute for a claim-less capture to misattribute. A
	// claim-less capture on a row that already holds a legacy value —
	// e.g. a display-name fallback written by EnsureUserByTelegramID —
	// must NOT stamp, or provenance would falsely attribute that
	// pre-existing value to this capture's source. But a claim-less
	// capture on a row with nothing in those columns (a brand-new row, or
	// one seeded with no username/display name at all) has nothing to
	// misattribute: capture genuinely ran and genuinely found nothing, so
	// it must still stamp — that "not_supplied" provenance is the whole
	// point of identity_captured_at, per design.md.
	hasClaim := c.Username != "" || c.FirstName != "" || c.LastName != ""
	var existingUsername, existingFirstName, existingLastName sql.NullString
	if err := s.DB.QueryRowContext(ctx,
		`SELECT telegram_username, telegram_first_name, telegram_last_name FROM users WHERE id = $1`, id,
	).Scan(&existingUsername, &existingFirstName, &existingLastName); err != nil {
		return 0, fmt.Errorf("read existing identity attrs: %w", err)
	}
	hasExistingAttr := existingUsername.String != "" || existingFirstName.String != "" || existingLastName.String != ""
	shouldStamp := hasClaim || !hasExistingAttr

	// telegram_login_id is backfilled here, not only on INSERT. The lookup
	// above falls back to the synthetic github_login precisely because a
	// legacy row can carry "tg:<id>" with telegram_login_id still NULL, and
	// without this COALESCE that row kept the NULL forever: the fallback
	// refreshed its attributes and returned its id, but nothing ever wrote
	// the column. Every projection and lookup keyed on telegram_login_id --
	// ListIdentities, UserIDByTelegramID, SetAccessTier,
	// AccessTierByTelegramID, and the reachability and notification-preference
	// projections added by issue-438 -- filters on it, so the user stayed
	// invisible to all of them, and re-authenticating never repaired it
	// because each capture took the same fallback again.
	//
	// COALESCE and not a plain assignment: a row that already has the column
	// set must not be rewritten, so a non-legacy row sees no change at all.
	// The partial unique index on telegram_login_id can still reject this
	// UPDATE if another row claimed the same id between the SELECT above and
	// here; that surfaces as an error rather than a silent second identity,
	// which is the safer failure for an authentication path.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE users SET
		     telegram_login_id = COALESCE(telegram_login_id, $9),
		     telegram_username = COALESCE(NULLIF($1,''), telegram_username),
		     telegram_display_name = COALESCE(NULLIF($2,''), telegram_display_name),
		     telegram_first_name = COALESCE(NULLIF($3,''), telegram_first_name),
		     telegram_last_name = COALESCE(NULLIF($4,''), telegram_last_name),
		     identity_source = CASE WHEN $7 THEN $5 ELSE identity_source END,
		     identity_captured_at = CASE WHEN $7 THEN $6 ELSE identity_captured_at END,
		     last_seen_at = $6
		 WHERE id = $8`,
		c.Username, displayName, c.FirstName, c.LastName, c.Source, capturedAt, shouldStamp, id, c.TelegramID,
	); err != nil {
		return 0, fmt.Errorf("refresh identity capture: %w", err)
	}
	return id, nil
}
