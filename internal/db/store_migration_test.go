package db

import (
	"bytes"
	"context"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	_ "modernc.org/sqlite"
)

func makeKey() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// newTestStoreCrypted opens an in-memory SQLite DB, applies the migration,
// and returns a Store wired with a configured AES key so SealForUser/Open
// actually run real crypto.
func newTestStoreCrypted(t *testing.T) *Store {
	t.Helper()
	ctx := context.Background()
	conn, err := Open(ctx, "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	c, err := crypto.New(makeKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	return &Store{DB: conn, Crypt: c}
}

func TestLoadSession_LazyMigratesV1ToV2(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid, err := s.EnsureUser(ctx, "alice", "", "test")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	pt := []byte("legacy session blob")

	// Seed the row with a v1 blob (single global key).
	v1, err := s.Crypt.Seal(pt)
	if err != nil {
		t.Fatalf("seal v1: %v", err)
	}
	if v1[0] != crypto.VersionMaster {
		t.Fatalf("expected v1 byte 0x01, got 0x%02x", v1[0])
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted) VALUES($1,$2)`,
		uid, v1,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// LoadSession should decrypt v1 *and* rewrap as v2 in-place.
	got, err := s.LoadSession(ctx, uid)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("plaintext mismatch: %q vs %q", got, pt)
	}

	var blob []byte
	if err := s.DB.QueryRowContext(ctx,
		`SELECT session_encrypted FROM telegram_accounts WHERE user_id=$1 AND revoked_at IS NULL`,
		uid,
	).Scan(&blob); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if blob[0] != crypto.VersionPerUser {
		t.Fatalf("expected blob rewrapped to v2 (0x02), got 0x%02x", blob[0])
	}

	// And a subsequent LoadSession still works against the now-v2 row.
	got2, err := s.LoadSession(ctx, uid)
	if err != nil {
		t.Fatalf("load after migration: %v", err)
	}
	if !bytes.Equal(got2, pt) {
		t.Fatal("post-migration roundtrip mismatch")
	}
}

// TestLoadSession_MigrationUpdateIsCASBound is the codex P1 fix for PR #3.
// If the row's session_encrypted is rotated between LoadSession's SELECT
// and its migration UPDATE, the UPDATE must be a no-op (not a clobber).
// We can't pause LoadSession mid-flight without exposing an injection
// point, so we test the SQL property directly: a v1 blob is seeded, then
// the row's blob is rotated out-of-band, then we manually invoke the
// migration UPDATE — it must leave the rotated value intact.
func TestLoadSession_MigrationUpdateIsCASBound(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid, err := s.EnsureUser(ctx, "race", "", "test")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	v1, _ := s.Crypt.Seal([]byte("stale plaintext"))
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted) VALUES($1,$2)`,
		uid, v1,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Read row id + blob (simulating LoadSession's SELECT).
	var rowID int64
	var snapshot []byte
	if err := s.DB.QueryRowContext(ctx,
		`SELECT id, session_encrypted FROM telegram_accounts WHERE user_id=$1 AND revoked_at IS NULL`,
		uid,
	).Scan(&rowID, &snapshot); err != nil {
		t.Fatalf("select: %v", err)
	}

	// Concurrent writer rotates the blob to a fresh value.
	rotated, _ := s.Crypt.SealForUser([]byte("rotated by writer B"), uid)
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET session_encrypted = $1 WHERE id = $2`,
		rotated, rowID,
	); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Migration UPDATE should be a no-op because session_encrypted no
	// longer equals the snapshot we captured.
	stalePT := []byte("stale plaintext")
	newBlob, _ := s.Crypt.SealForUser(stalePT, uid)
	res, err := s.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET session_encrypted = $1 WHERE id = $2 AND session_encrypted = $3`,
		newBlob, rowID, snapshot,
	)
	if err != nil {
		t.Fatalf("migration update: %v", err)
	}
	rows, _ := res.RowsAffected()
	if rows != 0 {
		t.Fatalf("CAS-bound migration must touch 0 rows when blob changed under us, got %d", rows)
	}

	// And the on-disk value remains the rotated one.
	var afterBlob []byte
	if err := s.DB.QueryRowContext(ctx,
		`SELECT session_encrypted FROM telegram_accounts WHERE id=$1`, rowID,
	).Scan(&afterBlob); err != nil {
		t.Fatalf("post select: %v", err)
	}
	if !bytes.Equal(afterBlob, rotated) {
		t.Fatal("rotated blob was overwritten by stale migration write")
	}
}

func TestSaveSession_AlwaysWritesV2(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid, err := s.EnsureUser(ctx, "bob", "", "test")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := s.SaveSession(ctx, uid, []byte("fresh"), 0, "", ""); err != nil {
		t.Fatalf("save: %v", err)
	}
	var blob []byte
	if err := s.DB.QueryRowContext(ctx,
		`SELECT session_encrypted FROM telegram_accounts WHERE user_id=$1`,
		uid,
	).Scan(&blob); err != nil {
		t.Fatalf("read: %v", err)
	}
	if blob[0] != crypto.VersionPerUser {
		t.Fatalf("SaveSession must write v2, got 0x%02x", blob[0])
	}
}

func TestUpdateSessionBlob_WritesV2(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid, err := s.EnsureUser(ctx, "carol", "", "test")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	// No prior row — UpdateSessionBlob should insert.
	if err := s.UpdateSessionBlob(ctx, uid, []byte("rotated")); err != nil {
		t.Fatalf("update: %v", err)
	}
	var blob []byte
	if err := s.DB.QueryRowContext(ctx,
		`SELECT session_encrypted FROM telegram_accounts WHERE user_id=$1`,
		uid,
	).Scan(&blob); err != nil {
		t.Fatalf("read: %v", err)
	}
	if blob[0] != crypto.VersionPerUser {
		t.Fatalf("UpdateSessionBlob must write v2, got 0x%02x", blob[0])
	}
}
