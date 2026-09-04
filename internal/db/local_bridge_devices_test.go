package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// T1: RegisterDevice with a fresh idempotency key inserts exactly one row
// and returns a non-empty device_id.
func TestRegisterDevice_Insert(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 1001, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	deviceID, err := s.RegisterDevice(ctx, uid, "alice-laptop", "idem-1", nil)
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	if deviceID == "" {
		t.Fatal("RegisterDevice returned empty device_id")
	}
	var count int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM local_bridge_devices WHERE device_id = $1`, deviceID,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row, got %d", count)
	}
}

// T2: calling RegisterDevice twice with the same (userID, idempotencyKey)
// returns the same device_id both times and leaves exactly one row in the
// table.
func TestRegisterDevice_IdempotentRetry(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 1002, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	first, err := s.RegisterDevice(ctx, uid, "bob-desktop", "idem-retry", nil)
	if err != nil {
		t.Fatalf("first RegisterDevice: %v", err)
	}
	second, err := s.RegisterDevice(ctx, uid, "bob-desktop", "idem-retry", nil)
	if err != nil {
		t.Fatalf("second RegisterDevice: %v", err)
	}
	if first != second {
		t.Fatalf("device_id mismatch on retry: first=%q second=%q", first, second)
	}
	var count int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM local_bridge_devices WHERE idempotency_key = $1`, "idem-retry",
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 row after idempotent retry, got %d", count)
	}
}

// RegisterDevice without an idempotency key never collides: two calls with
// no key each create their own row.
func TestRegisterDevice_NoIdempotencyKeyAlwaysInserts(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 1003, "carol", "Carol")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	first, err := s.RegisterDevice(ctx, uid, "", "", nil)
	if err != nil {
		t.Fatalf("first RegisterDevice: %v", err)
	}
	second, err := s.RegisterDevice(ctx, uid, "", "", nil)
	if err != nil {
		t.Fatalf("second RegisterDevice: %v", err)
	}
	if first == second {
		t.Fatalf("expected distinct device ids without an idempotency key, got %q twice", first)
	}
}

// T3: GetDevice on a registered id returns a Device with the expected
// user_id/device_label/registered_at and revoked_at == nil.
func TestGetDevice_Lookup(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 1004, "dave", "Dave")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	deviceID, err := s.RegisterDevice(ctx, uid, "dave-phone", "idem-lookup", nil)
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	d, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if d.UserID != uid {
		t.Errorf("UserID = %d, want %d", d.UserID, uid)
	}
	if d.DeviceLabel != "dave-phone" {
		t.Errorf("DeviceLabel = %q, want %q", d.DeviceLabel, "dave-phone")
	}
	if d.RegisteredAt.IsZero() {
		t.Error("RegisteredAt is zero")
	}
	if d.RevokedAt != nil {
		t.Errorf("RevokedAt = %v, want nil", d.RevokedAt)
	}
}

// T4: GetDevice on an unknown id returns ErrDeviceNotFound (via errors.Is).
func TestGetDevice_NotFound(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	_, err := s.GetDevice(ctx, "dev_does_not_exist")
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("GetDevice error = %v, want ErrDeviceNotFound", err)
	}
}

// T5: RevokeDevice sets revoked_at/revoked_reason; a subsequent GetDevice
// reflects the revoked state.
func TestRevokeDevice(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 1005, "erin", "Erin")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	deviceID, err := s.RegisterDevice(ctx, uid, "erin-desktop", "idem-revoke", nil)
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	if err := s.RevokeDevice(ctx, deviceID, "lost device"); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	d, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if d.RevokedAt == nil {
		t.Fatal("RevokedAt is nil after revocation")
	}
	if d.RevokedReason != "lost device" {
		t.Errorf("RevokedReason = %q, want %q", d.RevokedReason, "lost device")
	}
}

// T6: revoking an already-revoked device twice does not error and does not
// change the original revoked_at (mirrors RevokeWorkerToken's "re-revoking
// is a no-op" contract).
func TestRevokeDevice_Idempotent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 1006, "frank", "Frank")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	deviceID, err := s.RegisterDevice(ctx, uid, "frank-tablet", "idem-double-revoke", nil)
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	if err := s.RevokeDevice(ctx, deviceID, "first reason"); err != nil {
		t.Fatalf("first RevokeDevice: %v", err)
	}
	first, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetDevice after first revoke: %v", err)
	}
	if err := s.RevokeDevice(ctx, deviceID, "second reason"); err != nil {
		t.Fatalf("second RevokeDevice should be a no-op, not an error: %v", err)
	}
	second, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetDevice after second revoke: %v", err)
	}
	if second.RevokedReason != "first reason" {
		t.Errorf("RevokedReason changed on re-revoke: got %q, want %q (unchanged)", second.RevokedReason, "first reason")
	}
	if !first.RevokedAt.Equal(*second.RevokedAt) {
		t.Errorf("RevokedAt changed on re-revoke: first=%v second=%v", first.RevokedAt, second.RevokedAt)
	}
}

// T7: TouchDeviceLastSeen updates last_seen_at on an existing device; a call
// against an unknown device_id returns no error (0 rows affected is not a
// failure at this layer, per design.md).
func TestTouchDeviceLastSeen(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 1007, "grace", "Grace")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	deviceID, err := s.RegisterDevice(ctx, uid, "grace-nuc", "idem-touch", nil)
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	before, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetDevice before touch: %v", err)
	}
	if before.LastSeenAt != nil {
		t.Fatalf("expected nil LastSeenAt before first touch, got %v", before.LastSeenAt)
	}
	if err := s.TouchDeviceLastSeen(ctx, deviceID); err != nil {
		t.Fatalf("TouchDeviceLastSeen: %v", err)
	}
	after, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetDevice after touch: %v", err)
	}
	if after.LastSeenAt == nil {
		t.Fatal("expected non-nil LastSeenAt after touch")
	}
	if err := s.TouchDeviceLastSeen(ctx, "dev_unknown"); err != nil {
		t.Errorf("TouchDeviceLastSeen on unknown device_id should not error: %v", err)
	}
}

// TestRegisterDevice_PostgresUpsert exercises the Postgres branch of
// RegisterDevice against a real server. Its ON CONFLICT arbiter index is
// partial, which Postgres will not infer from a bare
// ON CONFLICT (idempotency_key) -- see RevokeWorkerToken's analogous test
// and comment. Skipped unless TEST_DATABASE_URL points at a Postgres
// instance.
func TestRegisterDevice_PostgresUpsert(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := Open(ctx, dsn, 0, 0)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	defer conn.Close()
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := &Store{DB: conn}
	uid, err := s.EnsureUserByTelegramID(ctx, 700000401, "pgtest", "PG Test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(ctx, `DELETE FROM local_bridge_devices WHERE idempotency_key LIKE 'pgtest-%'`)
	})

	const key = "pgtest-idem-1"
	first, err := s.RegisterDevice(ctx, uid, "pg-device", key, nil)
	if err != nil {
		t.Fatalf("first RegisterDevice: %v", err)
	}
	second, err := s.RegisterDevice(ctx, uid, "pg-device", key, nil)
	if err != nil {
		t.Fatalf("second RegisterDevice (idempotent retry): %v", err)
	}
	if first != second {
		t.Errorf("device_id mismatch on Postgres idempotent retry: first=%q second=%q", first, second)
	}
	if !strings.HasPrefix(first, "dev_") {
		t.Errorf("device_id %q does not have the expected dev_ prefix", first)
	}

	// Re-registration after a revoke is the path this fix opened, and it is
	// the half the arbiter check above cannot reach: it depends on the index
	// predicate excluding revoked rows AND on the ON CONFLICT target naming
	// that same predicate, character for character. Drift between the two
	// compiles, passes every SQLite test in this file -- SQLite's branch never
	// runs the ON CONFLICT statement at all -- and then fails here, which is
	// the only place it can be caught before production.
	if err := s.RevokeDevice(ctx, first, "test revoke"); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	replacement, err := s.RegisterDevice(ctx, uid, "pg-device", key, nil)
	if err != nil {
		// A predicate mismatch surfaces as "there is no unique or exclusion
		// constraint matching the ON CONFLICT specification"; a revoked row
		// still occupying the index surfaces as a unique violation the
		// ON CONFLICT no longer absorbs.
		t.Fatalf("re-register after revoke on Postgres: %v", err)
	}
	if replacement == first {
		t.Fatalf("re-registration returned the revoked device_id %q", replacement)
	}
	var revoked sql.NullTime
	if err := conn.QueryRowContext(ctx,
		`SELECT revoked_at FROM local_bridge_devices WHERE device_id = $1`, replacement,
	).Scan(&revoked); err != nil {
		t.Fatalf("read replacement: %v", err)
	}
	if revoked.Valid {
		t.Fatalf("replacement device %q is already revoked", replacement)
	}
}

// Two DIFFERENT users supplying the same idempotency key must each get their
// own device. The key is client-supplied (a daemon generates it and retries
// with it after a network timeout), so nothing stops two accounts from
// choosing the same string. Before the (user_id, idempotency_key) scoping,
// the unique index was global: the second user's INSERT was silently dropped
// and the read-back handed them the FIRST user's device_id, misattributing
// device identity across accounts with a nil error.
func TestRegisterDevice_IdempotencyKeyIsScopedPerUser(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	alice, err := s.EnsureUserByTelegramID(ctx, 1008, "alice2", "Alice Two")
	if err != nil {
		t.Fatalf("ensure alice: %v", err)
	}
	bob, err := s.EnsureUserByTelegramID(ctx, 1009, "bob2", "Bob Two")
	if err != nil {
		t.Fatalf("ensure bob: %v", err)
	}

	aliceDev, err := s.RegisterDevice(ctx, alice, "alice-laptop", "shared-key", nil)
	if err != nil {
		t.Fatalf("alice RegisterDevice: %v", err)
	}
	bobDev, err := s.RegisterDevice(ctx, bob, "bob-laptop", "shared-key", nil)
	if err != nil {
		t.Fatalf("bob RegisterDevice: %v", err)
	}

	if aliceDev == bobDev {
		t.Fatalf("cross-user collision: bob received alice's device_id %q", bobDev)
	}

	// Each device must belong to the user who registered it -- an id that
	// differs but resolves to the wrong account would be just as wrong.
	for _, tc := range []struct {
		name     string
		deviceID string
		wantUser int64
	}{
		{"alice", aliceDev, alice},
		{"bob", bobDev, bob},
	} {
		d, err := s.GetDevice(ctx, tc.deviceID)
		if err != nil {
			t.Fatalf("GetDevice(%s): %v", tc.name, err)
		}
		if d.UserID != tc.wantUser {
			t.Errorf("%s device belongs to user %d, want %d", tc.name, d.UserID, tc.wantUser)
		}
	}

	// Each user's own retry still collapses onto their own row.
	aliceRetry, err := s.RegisterDevice(ctx, alice, "alice-laptop", "shared-key", nil)
	if err != nil {
		t.Fatalf("alice retry: %v", err)
	}
	if aliceRetry != aliceDev {
		t.Errorf("alice retry returned %q, want her original %q", aliceRetry, aliceDev)
	}

	var count int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM local_bridge_devices WHERE idempotency_key = $1`, "shared-key",
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Errorf("expected one row per user for the shared key, got %d", count)
	}
}

// TouchDeviceLastSeen's doc comment promises a call against an
// already-revoked device affects zero rows. Without the revoked_at IS NULL
// guard the UPDATE still landed, so a revoked daemon that kept sending
// heartbeats would keep looking active to any staleness logic built on
// last_seen_at.
func TestTouchDeviceLastSeen_NoOpOnRevokedDevice(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 1010, "heidi", "Heidi")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	dev, err := s.RegisterDevice(ctx, uid, "heidi-laptop", "", nil)
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	if err := s.TouchDeviceLastSeen(ctx, dev); err != nil {
		t.Fatalf("first touch: %v", err)
	}
	before, err := s.GetDevice(ctx, dev)
	if err != nil {
		t.Fatalf("GetDevice before revoke: %v", err)
	}
	if before.LastSeenAt == nil {
		t.Fatal("last_seen_at not set by the pre-revoke touch")
	}

	if err := s.RevokeDevice(ctx, dev, "test"); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}

	// A revoked daemon keeps sending heartbeats: still not an error at this
	// layer, but it must not move last_seen_at.
	if err := s.TouchDeviceLastSeen(ctx, dev); err != nil {
		t.Fatalf("touch after revoke: %v", err)
	}
	after, err := s.GetDevice(ctx, dev)
	if err != nil {
		t.Fatalf("GetDevice after revoke: %v", err)
	}
	if after.LastSeenAt == nil {
		t.Fatal("last_seen_at was cleared, expected it to be left untouched")
	}
	if !after.LastSeenAt.Equal(*before.LastSeenAt) {
		t.Errorf("last_seen_at moved on a revoked device: %v -> %v", *before.LastSeenAt, *after.LastSeenAt)
	}
}

// A revoked device must not be resurrected by a retry, and revoking must not
// permanently burn the idempotency key. Before the fix the read-back had no
// revoked_at filter and the unique index covered revoked rows too, so
// re-running activation after a revoke returned the REVOKED device_id and no
// replacement row could ever be inserted -- the device was unusable and
// unre-registerable at the same time, and issue #483 would have gone on to
// mint credentials for the dead id.
func TestRegisterDevice_RevokedKeyIsReusable(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 1099, "carol", "Carol")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	const key = "idem-revoke-reuse"

	first, err := s.RegisterDevice(ctx, uid, "carol-laptop", key, nil)
	if err != nil {
		t.Fatalf("first RegisterDevice: %v", err)
	}
	if err := s.RevokeDevice(ctx, first, "user revoked"); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}

	second, err := s.RegisterDevice(ctx, uid, "carol-laptop", key, nil)
	if err != nil {
		t.Fatalf("re-register after revoke: %v", err)
	}
	if second == first {
		t.Fatalf("re-registration returned the revoked device_id %q", second)
	}

	// The replacement must be live, and the revoked row must stay revoked.
	var revokedAt sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM local_bridge_devices WHERE device_id = $1`, second,
	).Scan(&revokedAt); err != nil {
		t.Fatalf("read replacement: %v", err)
	}
	if revokedAt.Valid {
		t.Fatalf("replacement device %q is already revoked", second)
	}
	if err := s.DB.QueryRowContext(ctx,
		`SELECT revoked_at FROM local_bridge_devices WHERE device_id = $1`, first,
	).Scan(&revokedAt); err != nil {
		t.Fatalf("read original: %v", err)
	}
	if !revokedAt.Valid {
		t.Fatalf("original device %q lost its revocation", first)
	}

	// A retry after the replacement still collapses onto the live row.
	third, err := s.RegisterDevice(ctx, uid, "carol-laptop", key, nil)
	if err != nil {
		t.Fatalf("retry after re-register: %v", err)
	}
	if third != second {
		t.Fatalf("retry did not resolve to the live device: got %q want %q", third, second)
	}
}

// A revoke that lands between RegisterDevice's insert and its read-back must
// surface as ErrDeviceRevokedConcurrently, not as a bare sql.ErrNoRows
// wrapped in "read back". The interleaving is forced with an AFTER INSERT
// trigger, which revokes the freshly inserted row before control returns to
// the read-back -- the same observable ordering a concurrent RevokeDevice
// produces, without needing two connections to race.
func TestRegisterDevice_RevokedBetweenInsertAndReadBack(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 1100, "dave", "Dave")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`CREATE TRIGGER revoke_right_after_insert AFTER INSERT ON local_bridge_devices
		 BEGIN
		   UPDATE local_bridge_devices SET revoked_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
		 END`,
	); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	t.Cleanup(func() {
		if _, err := s.DB.ExecContext(context.Background(),
			`DROP TRIGGER IF EXISTS revoke_right_after_insert`); err != nil {
			t.Fatalf("drop trigger: %v", err)
		}
	})

	_, err = s.RegisterDevice(ctx, uid, "dave-laptop", "idem-raced-revoke", nil)
	if !errors.Is(err, ErrDeviceRevokedConcurrently) {
		t.Fatalf("expected ErrDeviceRevokedConcurrently, got %v", err)
	}
	// The generic read-back wrapper must not be what the caller sees.
	if strings.Contains(err.Error(), "no rows in result set") {
		t.Fatalf("raw sql.ErrNoRows leaked to the caller: %v", err)
	}
}

// issue-483 task 2: RegisterDevice persists a supplied pubkey, and GetDevice
// returns it back unchanged, defaulting device_pubkey_algo to 'ed25519'.
func TestRegisterDevice_WithPubkey(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 2001, "ivan", "Ivan")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	pubkey := bytes.Repeat([]byte{0x42}, 32)
	deviceID, err := s.RegisterDevice(ctx, uid, "ivan-laptop", "idem-pubkey", pubkey)
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	d, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if !bytes.Equal(d.DevicePubkey, pubkey) {
		t.Errorf("DevicePubkey = %x, want %x", d.DevicePubkey, pubkey)
	}
	if d.DevicePubkeyAlgo != "ed25519" {
		t.Errorf("DevicePubkeyAlgo = %q, want ed25519", d.DevicePubkeyAlgo)
	}
}

// The existing idempotency-retry path is unchanged when a pubkey is
// re-submitted identically: the retry resolves to the SAME row (created by
// the first call) rather than rewriting its pubkey.
func TestRegisterDevice_IdempotentRetry_PubkeyUnchanged(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 2002, "judy", "Judy")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	pubkey := bytes.Repeat([]byte{0x01}, 32)
	first, err := s.RegisterDevice(ctx, uid, "judy-desktop", "idem-pubkey-retry", pubkey)
	if err != nil {
		t.Fatalf("first RegisterDevice: %v", err)
	}
	// Retry with the identical pubkey (as a real retrying client would).
	second, err := s.RegisterDevice(ctx, uid, "judy-desktop", "idem-pubkey-retry", pubkey)
	if err != nil {
		t.Fatalf("second RegisterDevice: %v", err)
	}
	if first != second {
		t.Fatalf("device_id mismatch on retry: first=%q second=%q", first, second)
	}
	d, err := s.GetDevice(ctx, first)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if !bytes.Equal(d.DevicePubkey, pubkey) {
		t.Errorf("DevicePubkey after retry = %x, want %x", d.DevicePubkey, pubkey)
	}
}

// issue-483 task 9: ClaimDeviceCredentialLineage's conditional UPDATE claims
// the slot exactly once; a second claim attempt against the same device
// affects zero rows and does not overwrite the first claim.
func TestClaimDeviceCredentialLineage(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 2003, "kim", "Kim")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	deviceID, err := s.RegisterDevice(ctx, uid, "kim-phone", "idem-claim", bytes.Repeat([]byte{0x02}, 32))
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	won, err := s.ClaimDeviceCredentialLineage(ctx, deviceID, "jti-first", issuedAt)
	if err != nil {
		t.Fatalf("ClaimDeviceCredentialLineage: %v", err)
	}
	if !won {
		t.Fatal("first claim should have won")
	}
	// A second claim attempt (simulating a losing concurrent request) must
	// lose: it must not overwrite the stored jti.
	won2, err := s.ClaimDeviceCredentialLineage(ctx, deviceID, "jti-second", issuedAt)
	if err != nil {
		t.Fatalf("second ClaimDeviceCredentialLineage: %v", err)
	}
	if won2 {
		t.Fatal("second claim should have lost (slot already claimed)")
	}
	d, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if d.CurrentJti != "jti-first" {
		t.Errorf("CurrentJti = %q, want %q (the winning claim)", d.CurrentJti, "jti-first")
	}
	if d.CredentialIssuedAt == nil || !d.CredentialIssuedAt.Equal(issuedAt) {
		t.Errorf("CredentialIssuedAt = %v, want %v", d.CredentialIssuedAt, issuedAt)
	}
}

// T5e: a revoked device cannot claim a lineage slot -- the conditional
// UPDATE's revoked_at IS NULL predicate must make the claim lose.
func TestClaimDeviceCredentialLineage_RevokedDeviceLoses(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 2004, "liam", "Liam")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	deviceID, err := s.RegisterDevice(ctx, uid, "liam-phone", "idem-claim-revoked", bytes.Repeat([]byte{0x03}, 32))
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	if err := s.RevokeDevice(ctx, deviceID, "test"); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	won, err := s.ClaimDeviceCredentialLineage(ctx, deviceID, "jti-should-not-land", time.Now().UTC())
	if err != nil {
		t.Fatalf("ClaimDeviceCredentialLineage: %v", err)
	}
	if won {
		t.Fatal("claim on a revoked device should lose, not win")
	}
}

// issue-483 task 12: RevokeDeviceAndDenylist is atomic (revoke + denylist in
// one transaction), reads current_jti from the row it just locked, and is
// repeatable: a second call on an already-revoked device still returns and
// (re-)denylists the same jti.
func TestRevokeDeviceAndDenylist(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 2005, "mona", "Mona")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	deviceID, err := s.RegisterDevice(ctx, uid, "mona-laptop", "idem-revoke-denylist", bytes.Repeat([]byte{0x04}, 32))
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	if won, err := s.ClaimDeviceCredentialLineage(ctx, deviceID, "jti-mona-1", time.Now().UTC()); err != nil || !won {
		t.Fatalf("claim lineage: won=%v err=%v", won, err)
	}

	jti, err := s.RevokeDeviceAndDenylist(ctx, deviceID, 2005, "lost device", 0)
	if err != nil {
		t.Fatalf("RevokeDeviceAndDenylist: %v", err)
	}
	if jti != "jti-mona-1" {
		t.Fatalf("returned jti = %q, want %q", jti, "jti-mona-1")
	}
	revoked, err := s.IsWorkerTokenRevoked(ctx, "jti-mona-1", 2005, time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatalf("IsWorkerTokenRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("jti was not denylisted by RevokeDeviceAndDenylist")
	}

	// T6b: repeating the call on an already-revoked device must still
	// return (and thereby let the caller re-denylist/re-evict) the same
	// jti, not an error and not an empty string.
	jti2, err := s.RevokeDeviceAndDenylist(ctx, deviceID, 2005, "repeat call", 0)
	if err != nil {
		t.Fatalf("repeat RevokeDeviceAndDenylist: %v", err)
	}
	if jti2 != "jti-mona-1" {
		t.Fatalf("repeat call returned jti = %q, want %q", jti2, "jti-mona-1")
	}

	// revoked_reason must be unchanged by the repeat call (COALESCE keeps
	// the original), mirroring RevokeDevice's own no-op-on-retry contract.
	d, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if d.RevokedReason != "lost device" {
		t.Errorf("RevokedReason = %q, want %q (unchanged by repeat call)", d.RevokedReason, "lost device")
	}
}

// T6e: revoking a device that never issued succeeds -- the row comes back
// revoked, no denylist row is written (empty jti), and nothing rolls back.
func TestRevokeDeviceAndDenylist_NeverIssued(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 2006, "nate", "Nate")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	deviceID, err := s.RegisterDevice(ctx, uid, "nate-phone", "idem-never-issued", bytes.Repeat([]byte{0x05}, 32))
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	jti, err := s.RevokeDeviceAndDenylist(ctx, deviceID, 2006, "never issued", 0)
	if err != nil {
		t.Fatalf("RevokeDeviceAndDenylist: %v", err)
	}
	if jti != "" {
		t.Fatalf("jti = %q, want empty (device never issued)", jti)
	}
	d, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if d.RevokedAt == nil {
		t.Fatal("device row was not revoked")
	}
}

// Unknown device_id returns ErrDeviceNotFound, not a silent no-op.
func TestRevokeDeviceAndDenylist_NotFound(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	_, err := s.RevokeDeviceAndDenylist(ctx, "dev_does_not_exist", 1, "reason", 0)
	if !errors.Is(err, ErrDeviceNotFound) {
		t.Fatalf("err = %v, want ErrDeviceNotFound", err)
	}
}
