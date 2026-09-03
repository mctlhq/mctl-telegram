package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ErrDeviceNotFound is returned by GetDevice when no row matches the given
// device id.
var ErrDeviceNotFound = errors.New("local bridge device not found")

// Device is one row of local_bridge_devices: a durable record of a single
// Local Bridge daemon installation, distinct from the account-wide
// telegram_accounts.mode flag. Nothing in this issue reads or writes it from
// internal/bridge, internal/mcp, or internal/workertoken -- it exists so a
// follow-up sub-issue (activation endpoints, consent, credential issuance)
// has a stable Store surface to build on.
type Device struct {
	ID             int64
	UserID         int64
	DeviceID       string
	DeviceLabel    string
	IdempotencyKey string
	RegisteredAt   time.Time
	LastSeenAt     *time.Time
	RevokedAt      *time.Time
	RevokedReason  string
}

// RegisterDevice inserts a new local_bridge_devices row for userID and
// returns its server-generated device id (128 bits of crypto/rand,
// hex-encoded -- no UUID library is imported by this repo today). label is
// an optional human-readable name; idempotencyKey, when non-empty, lets a
// retried registration call (e.g. a daemon retrying after a network
// timeout) be answered with the existing row instead of creating a
// duplicate: a second call with the same idempotencyKey returns the
// device_id from the first call.
func (s *Store) RegisterDevice(ctx context.Context, userID int64, label, idempotencyKey string) (string, error) {
	if userID <= 0 {
		return "", errors.New("register device: user_id required")
	}
	deviceID, err := generateDeviceID()
	if err != nil {
		return "", fmt.Errorf("register device: %w", err)
	}
	if s.isPostgres(ctx) {
		if _, err := s.DB.ExecContext(ctx,
			// The ON CONFLICT target repeats the index predicate because the
			// backing index is partial (idempotency_key IS NOT NULL) -- see
			// RevokeWorkerToken's comment on the same pitfall. A bare
			// ON CONFLICT (user_id, idempotency_key) matches no index and
			// fails at runtime on Postgres; SQLite's INSERT OR IGNORE branch
			// below never exercises this statement. The conflict target is
			// the pair, not the key alone — see the index comment in db.go.
			`INSERT INTO local_bridge_devices (user_id, device_id, device_label, idempotency_key)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (user_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING`,
			userID, deviceID, nullable(label), nullable(idempotencyKey),
		); err != nil {
			return "", fmt.Errorf("register device: %w", err)
		}
	} else {
		if _, err := s.DB.ExecContext(ctx,
			`INSERT OR IGNORE INTO local_bridge_devices (user_id, device_id, device_label, idempotency_key)
			 VALUES ($1, $2, $3, $4)`,
			userID, deviceID, nullable(label), nullable(idempotencyKey),
		); err != nil {
			return "", fmt.Errorf("register device: %w", err)
		}
	}
	if idempotencyKey == "" {
		// No idempotency key was supplied, so the INSERT above always
		// created the row above: the id we generated is the row's id.
		return deviceID, nil
	}
	// The insert may have been a no-op (idempotency_key conflict): read back
	// whichever row actually owns this idempotency_key, which is the
	// caller's original registration when this is a retry. Filtered by
	// user_id as well as the key, so this can only ever return a row
	// belonging to the caller — a second layer behind the scoped unique
	// index, not a substitute for it.
	var existing string
	if err := s.DB.QueryRowContext(ctx,
		`SELECT device_id FROM local_bridge_devices WHERE user_id = $1 AND idempotency_key = $2`,
		userID, idempotencyKey,
	).Scan(&existing); err != nil {
		return "", fmt.Errorf("register device: read back: %w", err)
	}
	return existing, nil
}

// GetDevice looks up a device by its public device id. Returns
// ErrDeviceNotFound (checkable via errors.Is) when no row matches.
func (s *Store) GetDevice(ctx context.Context, deviceID string) (*Device, error) {
	var d Device
	var label, idempotencyKey, revokedReason sql.NullString
	var lastSeenAt, revokedAt sql.NullTime
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, user_id, device_id, device_label, idempotency_key,
		        registered_at, last_seen_at, revoked_at, revoked_reason
		 FROM local_bridge_devices WHERE device_id = $1`,
		deviceID,
	).Scan(&d.ID, &d.UserID, &d.DeviceID, &label, &idempotencyKey,
		&d.RegisteredAt, &lastSeenAt, &revokedAt, &revokedReason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDeviceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}
	d.DeviceLabel = label.String
	d.IdempotencyKey = idempotencyKey.String
	d.RevokedReason = revokedReason.String
	if lastSeenAt.Valid {
		t := lastSeenAt.Time
		d.LastSeenAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		d.RevokedAt = &t
	}
	return &d, nil
}

// RevokeDevice records a revocation timestamp and reason without deleting
// the row. Re-revoking an already-revoked device is a no-op, not an error --
// the original revoked_at/revoked_reason are left untouched, mirroring
// RevokeWorkerToken's "re-revoking the same jti is a no-op" contract.
func (s *Store) RevokeDevice(ctx context.Context, deviceID, reason string) error {
	if deviceID == "" {
		return errors.New("revoke device: device_id required")
	}
	now := time.Now().UTC()
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE local_bridge_devices
		 SET revoked_at = $1, revoked_reason = $2
		 WHERE device_id = $3 AND revoked_at IS NULL`,
		now, nullable(reason), deviceID,
	); err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	return nil
}

// TouchDeviceLastSeen updates a device's last-seen timestamp so a future
// sub-issue can build staleness/idle logic on top of it. A call against an
// unknown or already-revoked device_id affects zero rows and is not treated
// as an error at this layer -- callers that care about existence use
// GetDevice first; this keeps TouchDeviceLastSeen a cheap, fire-and-forget
// heartbeat primitive for a future daemon keep-alive path.
func (s *Store) TouchDeviceLastSeen(ctx context.Context, deviceID string) error {
	if deviceID == "" {
		return errors.New("touch device last seen: device_id required")
	}
	now := time.Now().UTC()
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE local_bridge_devices SET last_seen_at = $1 WHERE device_id = $2 AND revoked_at IS NULL`,
		now, deviceID,
	); err != nil {
		return fmt.Errorf("touch device last seen: %w", err)
	}
	return nil
}

// generateDeviceID returns a collision-resistant, server-generated device
// identifier: 128 bits of crypto/rand, hex-encoded. No UUID library is
// imported by this repo today, so this avoids adding one for a single id
// format.
func generateDeviceID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate device id: %w", err)
	}
	return "dev_" + hex.EncodeToString(b), nil
}
