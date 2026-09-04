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

// ErrDeviceRevokedConcurrently is returned by RegisterDevice when the row
// owning the supplied idempotency key was revoked between the insert and the
// read-back. It is a distinct condition from any other read-back failure:
// nothing is wrong with the request, and retrying with a fresh idempotency
// key succeeds.
var ErrDeviceRevokedConcurrently = errors.New("local bridge device revoked concurrently with registration")

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
	// DevicePubkey is the Ed25519 public key registered at activation
	// (issue-483 task 1/2/3/4), used to verify PoP signatures at issuance
	// and refresh. Nil for a row that predates this column or that was
	// registered by a client build that did not submit one -- such a row can
	// never complete issuance/refresh (see internal/oauth's PoP handlers).
	DevicePubkey []byte
	// DevicePubkeyAlgo names the algorithm DevicePubkey is verified under.
	// Defaults to "ed25519" at the schema level; future-proofs "or an
	// equivalent reviewed primitive" without a second migration.
	DevicePubkeyAlgo string
	// CurrentJti is the ONE credential lineage jti claimed atomically at
	// first issuance and carried forward unchanged by every later PoP
	// refresh. Empty until first issuance claims it.
	CurrentJti string
	// CredentialIssuedAt is the OriginalIssuedAt anchor for CurrentJti's
	// lineage, written once at first issuance alongside CurrentJti and read
	// by every refresh. Nil until first issuance.
	CredentialIssuedAt *time.Time
}

// RegisterDevice inserts a new local_bridge_devices row for userID and
// returns its server-generated device id (128 bits of crypto/rand,
// hex-encoded -- no UUID library is imported by this repo today). label is
// an optional human-readable name; idempotencyKey, when non-empty, lets a
// retried registration call (e.g. a daemon retrying after a network
// timeout) be answered with the existing row instead of creating a
// duplicate: a second call with the same idempotencyKey returns the
// device_id from the first call. pubkey, when non-empty, is the device's
// Ed25519 public key (issue-483); it is only written on the INSERT branch
// -- an idempotent retry that resolves to an existing row does not rewrite
// its pubkey, matching every other field's "first registration wins"
// behavior. device_pubkey_algo is always 'ed25519' today (the column
// default); no caller sets a different algorithm yet.
func (s *Store) RegisterDevice(ctx context.Context, userID int64, label, idempotencyKey string, pubkey []byte) (string, error) {
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
			`INSERT INTO local_bridge_devices (user_id, device_id, device_label, idempotency_key, device_pubkey)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (user_id, idempotency_key) WHERE idempotency_key IS NOT NULL AND revoked_at IS NULL DO NOTHING`,
			userID, deviceID, nullable(label), nullable(idempotencyKey), nullableBytes(pubkey),
		); err != nil {
			return "", fmt.Errorf("register device: %w", err)
		}
	} else {
		if _, err := s.DB.ExecContext(ctx,
			`INSERT OR IGNORE INTO local_bridge_devices (user_id, device_id, device_label, idempotency_key, device_pubkey)
			 VALUES ($1, $2, $3, $4, $5)`,
			userID, deviceID, nullable(label), nullable(idempotencyKey), nullableBytes(pubkey),
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
	//
	// revoked_at IS NULL matters as much as user_id: without it, re-running
	// activation after a revoke returned the REVOKED device_id, and the
	// unique index (then unscoped) refused to insert a replacement -- so a
	// revoked device could never be re-registered with the same key, and the
	// caller was handed a dead id it would go on to request credentials for.
	// The index predicate above must stay in step with this WHERE clause.
	var existing string
	if err := s.DB.QueryRowContext(ctx,
		`SELECT device_id FROM local_bridge_devices
		 WHERE user_id = $1 AND idempotency_key = $2 AND revoked_at IS NULL`,
		userID, idempotencyKey,
	).Scan(&existing); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// The key had a live row when the statement above ran and has
			// none now: a revoke landed in between. Wrapping the insert and
			// this read-back in one transaction does NOT close that window
			// -- under READ COMMITTED each statement takes a fresh snapshot,
			// and on the retry path the insert is a conflict no-op that
			// leaves the pre-existing row unlocked, so a revoke committed
			// between the two is still visible here. Name the condition
			// instead of surfacing a bare "sql: no rows in result set", so
			// the caller can retry with a fresh key rather than treating a
			// benign race as a database fault.
			return "", ErrDeviceRevokedConcurrently
		}
		return "", fmt.Errorf("register device: read back: %w", err)
	}
	return existing, nil
}

// GetDevice looks up a device by its public device id. Returns
// ErrDeviceNotFound (checkable via errors.Is) when no row matches.
func (s *Store) GetDevice(ctx context.Context, deviceID string) (*Device, error) {
	var d Device
	var label, idempotencyKey, revokedReason, currentJti, pubkeyAlgo sql.NullString
	var lastSeenAt, revokedAt, credentialIssuedAt sql.NullTime
	var pubkey []byte
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, user_id, device_id, device_label, idempotency_key,
		        registered_at, last_seen_at, revoked_at, revoked_reason,
		        device_pubkey, device_pubkey_algo, current_jti, credential_issued_at
		 FROM local_bridge_devices WHERE device_id = $1`,
		deviceID,
	).Scan(&d.ID, &d.UserID, &d.DeviceID, &label, &idempotencyKey,
		&d.RegisteredAt, &lastSeenAt, &revokedAt, &revokedReason,
		&pubkey, &pubkeyAlgo, &currentJti, &credentialIssuedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrDeviceNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get device: %w", err)
	}
	d.DeviceLabel = label.String
	d.IdempotencyKey = idempotencyKey.String
	d.RevokedReason = revokedReason.String
	d.DevicePubkey = pubkey
	d.DevicePubkeyAlgo = pubkeyAlgo.String
	d.CurrentJti = currentJti.String
	if lastSeenAt.Valid {
		t := lastSeenAt.Time
		d.LastSeenAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		d.RevokedAt = &t
	}
	if credentialIssuedAt.Valid {
		t := credentialIssuedAt.Time
		d.CredentialIssuedAt = &t
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

// RevokeDeviceAndDenylist marks deviceID revoked and, in the SAME
// transaction, denylists its credential lineage (current_jti) when it has
// one -- see design.md's "the jti to denylist is read INSIDE that
// transaction, not before it": reading current_jti from an earlier,
// separate SELECT would race a concurrent first issuance that claims the
// lineage slot between the read and the revoke, denylisting a value that
// was NULL at read time while the freshly minted credential goes unlisted.
// The RETURNING clause here reads current_jti from the very row this
// UPDATE just locked, closing that window.
//
// telegramID is recorded on the denylist row for audit only (mirroring
// RevokeWorkerToken's own contract) -- pass the caller's own
// auth.Identity.TelegramID, since local_bridge_devices.user_id is the
// internal user id, not a Telegram id.
//
// Idempotent and safe to re-run: the UPDATE's SET clause uses
// COALESCE(revoked_at, ...) so a device already revoked keeps its original
// revoked_at/revoked_reason (matching RevokeDevice's no-op contract) while
// STILL matching the row and returning its current_jti every time --
// unlike a "WHERE revoked_at IS NULL" predicate, which would make a second
// call match zero rows and silently skip the RETURNING (and therefore the
// denylist) on retry. RevokeWorkerToken's own INSERT ... ON CONFLICT DO
// NOTHING makes the denylist insert itself idempotent too, so a retry after
// a partial failure (crash between the two writes) repairs the state
// instead of erroring or duplicating.
//
// Returns ErrDeviceNotFound if deviceID does not exist. Returns the jti that
// was (re-)denylisted, or "" if the device has never completed first
// issuance -- callers must not treat an empty jti as a failure: "the
// revoked device holds no credential lineage" is an expected, successful
// outcome (T6e), and inserting an empty jti would either write a
// meaningless row or violate the denylist table's constraints.
func (s *Store) RevokeDeviceAndDenylist(ctx context.Context, deviceID string, telegramID int64, reason string, revokedBy int64) (jti string, err error) {
	if deviceID == "" {
		return "", errors.New("revoke device: device_id required")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin revoke device tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	var currentJti sql.NullString
	err = tx.QueryRowContext(ctx,
		`UPDATE local_bridge_devices
		 SET revoked_at = COALESCE(revoked_at, $1), revoked_reason = COALESCE(revoked_reason, $2)
		 WHERE device_id = $3
		 RETURNING current_jti`,
		now, nullable(reason), deviceID,
	).Scan(&currentJti)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrDeviceNotFound
	}
	if err != nil {
		return "", fmt.Errorf("revoke device: %w", err)
	}

	jti = currentJti.String
	if jti != "" {
		if s.isPostgres(ctx) {
			if _, err := tx.ExecContext(ctx,
				// Same partial-index arbiter pitfall as RevokeWorkerToken's
				// top-level statement -- see that comment. Repeated here
				// because this insert must run inside THIS transaction, not
				// via a call to RevokeWorkerToken (which opens its own
				// implicit, separate write and would defeat the whole point
				// of the shared transaction).
				`INSERT INTO worker_token_revocations (jti, telegram_id, revoked_at, reason, revoked_by)
				 VALUES ($1, $2, $3, $4, $5)
				 ON CONFLICT (jti) WHERE jti IS NOT NULL DO NOTHING`,
				jti, telegramID, now, nullable(reason), nullableInt(revokedBy),
			); err != nil {
				return "", fmt.Errorf("denylist device credential: %w", err)
			}
		} else {
			if _, err := tx.ExecContext(ctx,
				`INSERT OR IGNORE INTO worker_token_revocations (jti, telegram_id, revoked_at, reason, revoked_by)
				 VALUES ($1, $2, $3, $4, $5)`,
				jti, telegramID, now, nullable(reason), nullableInt(revokedBy),
			); err != nil {
				return "", fmt.Errorf("denylist device credential: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit revoke device tx: %w", err)
	}
	return jti, nil
}

// ClaimDeviceCredentialLineage atomically claims deviceID's ONE credential
// lineage slot at first issuance: writes jti/issuedAt to current_jti/
// credential_issued_at if and only if the slot is still unclaimed AND the
// device is not revoked, in a single conditional UPDATE. This is the row
// acting as the lock design.md calls for -- not a SELECT-then-UPDATE, which
// would let two concurrent first-issuance requests both observe an empty
// current_jti and both mint, orphaning whichever write lands second for the
// rest of its TTL.
//
// Returns (true, nil) when this call won the claim. Returns (false, nil) --
// NOT an error -- when zero rows were affected: either the slot was already
// claimed by an earlier issuance (a concurrent request lost the race, T5d)
// or the device was revoked in the meantime (T5e; the same predicate closes
// both races at once). The caller maps false to a 409 with nothing minted.
func (s *Store) ClaimDeviceCredentialLineage(ctx context.Context, deviceID, jti string, issuedAt time.Time) (bool, error) {
	if deviceID == "" {
		return false, errors.New("claim device credential lineage: device_id required")
	}
	if jti == "" {
		return false, errors.New("claim device credential lineage: jti required")
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE local_bridge_devices
		 SET current_jti = $1, credential_issued_at = $2
		 WHERE device_id = $3 AND current_jti IS NULL AND revoked_at IS NULL`,
		jti, issuedAt.UTC(), deviceID,
	)
	if err != nil {
		return false, fmt.Errorf("claim device credential lineage: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("claim device credential lineage: %w", err)
	}
	return n > 0, nil
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
