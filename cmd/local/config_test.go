package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ----- deviceIdentityUsable -----

func TestDeviceIdentityUsable_ValidPair(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	privB64 := base64.StdEncoding.EncodeToString(priv.Seed())
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	gotPriv, gotPub, ok := deviceIdentityUsable(privB64, pubB64)
	if !ok {
		t.Fatal("valid pair reported unusable")
	}
	if !bytes.Equal(gotPriv, priv) {
		t.Errorf("returned private key does not match input")
	}
	if !bytes.Equal(gotPub, pub) {
		t.Errorf("returned public key does not match input")
	}
}

// TestDeviceIdentityUsable_CorruptCases is table-driven over the corruption
// shapes T17/T24 name: absent, empty, truncated, over-long (the 64-byte
// ed25519.PrivateKeySize -- validating against that instead of SeedSize is
// exactly the bug T25 exists to catch), invalid base64, and a well-formed
// but non-matching pair.
func TestDeviceIdentityUsable_CorruptCases(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate second keypair: %v", err)
	}
	validPubB64 := base64.StdEncoding.EncodeToString(pub)

	cases := []struct {
		name    string
		privB64 string
		pubB64  string
	}{
		{"both empty", "", ""},
		{"private empty, public present", "", validPubB64},
		{"private truncated", base64.StdEncoding.EncodeToString(priv.Seed()[:10]), validPubB64},
		{"private over-long (PrivateKeySize, not SeedSize)", base64.StdEncoding.EncodeToString(priv), validPubB64},
		{"private invalid base64", "not-valid-base64!!!", validPubB64},
		{"public invalid base64", base64.StdEncoding.EncodeToString(priv.Seed()), "not-valid-base64!!!"},
		{"mismatched but well-formed pair", base64.StdEncoding.EncodeToString(priv.Seed()), base64.StdEncoding.EncodeToString(pub2)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, ok := deviceIdentityUsable(tc.privB64, tc.pubB64); ok {
				t.Errorf("case %q reported usable, want unusable", tc.name)
			}
		})
	}
}

// ----- loadOrCreateDeviceIdentity: repair-in-place, table-driven -----

// TestLoadOrCreateDeviceIdentity_RepairsCorruptRecords covers T17/T24: a
// device identity file whose key material is unusable -- for any of the
// reasons above, plus the pre-#484 (#482-era) shape that has no Ed25519
// fields at all -- is regenerated in place rather than panicking, and the
// caller gets back a fresh, usable keypair.
func TestLoadOrCreateDeviceIdentity_RepairsCorruptRecords(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate second keypair: %v", err)
	}

	cases := []struct {
		name string
		rec  deviceRecord
	}{
		{
			name: "pre-#484 shape (registration key only, no Ed25519 fields)",
			rec:  deviceRecord{DeviceRegistrationKey: "opaque-legacy-key"},
		},
		{
			name: "empty private_key",
			rec: deviceRecord{
				DeviceRegistrationKey: "reg-key",
				PrivateKey:            "",
				PublicKey:             base64.StdEncoding.EncodeToString(pub),
			},
		},
		{
			name: "truncated private_key",
			rec: deviceRecord{
				DeviceRegistrationKey: "reg-key",
				PrivateKey:            base64.StdEncoding.EncodeToString(priv.Seed()[:5]),
				PublicKey:             base64.StdEncoding.EncodeToString(pub),
			},
		},
		{
			name: "over-long private_key (PrivateKeySize instead of SeedSize)",
			rec: deviceRecord{
				DeviceRegistrationKey: "reg-key",
				PrivateKey:            base64.StdEncoding.EncodeToString(priv),
				PublicKey:             base64.StdEncoding.EncodeToString(pub),
			},
		},
		{
			name: "invalid base64 private_key",
			rec: deviceRecord{
				DeviceRegistrationKey: "reg-key",
				PrivateKey:            "***not-base64***",
				PublicKey:             base64.StdEncoding.EncodeToString(pub),
			},
		},
		{
			name: "mismatched but well-formed pair",
			rec: deviceRecord{
				DeviceRegistrationKey: "reg-key",
				PrivateKey:            base64.StdEncoding.EncodeToString(priv.Seed()),
				PublicKey:             base64.StdEncoding.EncodeToString(pub2),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("HOME", dir)
			writeRawDeviceRecord(t, &tc.rec)

			rec, gotPriv, gotPub, err := loadOrCreateDeviceIdentity()
			if err != nil {
				t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
			}
			if len(gotPriv) != ed25519.PrivateKeySize {
				t.Fatalf("repaired private key has length %d, want %d", len(gotPriv), ed25519.PrivateKeySize)
			}
			if len(gotPub) != ed25519.PublicKeySize {
				t.Fatalf("repaired public key has length %d, want %d", len(gotPub), ed25519.PublicKeySize)
			}
			// The repaired keypair must actually work: a signature made with
			// it must verify against the pubkey now on record.
			sig := ed25519.Sign(gotPriv, []byte("probe"))
			if !ed25519.Verify(gotPub, []byte("probe"), sig) {
				t.Fatal("repaired keypair does not produce a verifiable signature")
			}
			if rec.DeviceRegistrationKey == "" {
				t.Error("repaired record has no device_registration_key")
			}
		})
	}
}

// TestLoadOrCreateDeviceIdentity_482CaseDoesNotRotateRegistrationKey covers
// design.md's "The #482 case is the exception": completing a record that
// never had Ed25519 fields at all -- key material supplied for the FIRST
// time -- must NOT rotate device_registration_key, because there is no
// existing server-side row bound to a different pubkey for that key yet.
func TestLoadOrCreateDeviceIdentity_482CaseDoesNotRotateRegistrationKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	original := &deviceRecord{DeviceRegistrationKey: "original-482-key"}
	writeRawDeviceRecord(t, original)

	rec, _, _, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}
	if rec.DeviceRegistrationKey != "original-482-key" {
		t.Errorf("registration key rotated on first-time completion: got %q, want %q", rec.DeviceRegistrationKey, "original-482-key")
	}
}

// TestLoadOrCreateDeviceIdentity_CorruptionRotatesRegistrationKey covers
// T20: regenerating a corrupted keypair (key material being REPLACED, not
// supplied for the first time) rotates device_registration_key, so a
// later /activate/start sends a NEW idempotency key rather than the one
// bound to the old, discarded public key.
func TestLoadOrCreateDeviceIdentity_CorruptionRotatesRegistrationKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	rec1, _, _, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity (first): %v", err)
	}
	originalRegKey := rec1.DeviceRegistrationKey

	// Corrupt the private key in place, simulating a truncated/hand-edited
	// file.
	corrupt, err := readDeviceRecord()
	if err != nil {
		t.Fatalf("readDeviceRecord: %v", err)
	}
	corrupt.PrivateKey = "corrupted"
	if err := writeDeviceRecord(corrupt); err != nil {
		t.Fatalf("writeDeviceRecord: %v", err)
	}

	rec2, _, _, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity (after corruption): %v", err)
	}
	if rec2.DeviceRegistrationKey == originalRegKey {
		t.Error("registration key was not rotated after corrupted key material was regenerated")
	}

	// Also assert the credential fields (if any had been set) are cleared,
	// since a credential issued against the OLD public key can never
	// authenticate against a freshly-registered device.
	if rec2.DeviceID != "" || rec2.WorkerToken != "" {
		t.Error("stale credential fields survived a key-material rotation")
	}
}

// writeRawDeviceRecord writes rec directly to the device_key.json path
// without going through any of the load/repair helpers -- used to seed a
// specific on-disk shape before exercising loadOrCreateDeviceIdentity.
func writeRawDeviceRecord(t *testing.T, rec *deviceRecord) {
	t.Helper()
	dir, err := configDirPath()
	if err != nil {
		t.Fatalf("configDirPath: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatalf("marshal device record: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, deviceKeyName), data, 0o600); err != nil {
		t.Fatalf("write device record: %v", err)
	}
}

// ----- deviceCredentialUsable -----

func TestDeviceCredentialUsable(t *testing.T) {
	cases := []struct {
		name string
		rec  *deviceRecord
		want bool
	}{
		{"nil record", nil, false},
		{"empty record", &deviceRecord{}, false},
		{
			"complete and well-formed",
			&deviceRecord{DeviceID: "d1", WorkerToken: "aa.bb.cc", ExpiresAt: "2099-01-01T00:00:00Z", Jti: "j1"},
			true,
		},
		{
			"missing device_id",
			&deviceRecord{WorkerToken: "aa.bb.cc", ExpiresAt: "2099-01-01T00:00:00Z", Jti: "j1"},
			false,
		},
		{
			"worker_token not a 3-segment JWT",
			&deviceRecord{DeviceID: "d1", WorkerToken: "not-a-jwt", ExpiresAt: "2099-01-01T00:00:00Z", Jti: "j1"},
			false,
		},
		{
			"missing jti",
			&deviceRecord{DeviceID: "d1", WorkerToken: "aa.bb.cc", ExpiresAt: "2099-01-01T00:00:00Z"},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deviceCredentialUsable(tc.rec); got != tc.want {
				t.Errorf("deviceCredentialUsable(%+v) = %v, want %v", tc.rec, got, tc.want)
			}
		})
	}
}

// ----- mergeDeviceCredential -----

func TestMergeDeviceCredential_HappyPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, priv, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}
	_ = priv

	merged, err := mergeDeviceCredential(pub, "dev1", "aa.bb.cc", "2099-01-01T00:00:00Z", "jti1")
	if err != nil {
		t.Fatalf("mergeDeviceCredential: %v", err)
	}
	if !merged {
		t.Fatal("expected merge to succeed")
	}

	rec, err := readDeviceRecord()
	if err != nil {
		t.Fatalf("readDeviceRecord: %v", err)
	}
	if rec.DeviceID != "dev1" || rec.WorkerToken != "aa.bb.cc" || rec.Jti != "jti1" {
		t.Errorf("merged record incomplete: %+v", rec)
	}
}

// TestMergeDeviceCredential_AbandonsOnIdentityMismatch covers design.md's
// "every writer re-validates the identity before merging": a credential
// signed by a key that is no longer the one on disk (a concurrent activate
// replaced the identity) must not be merged.
func TestMergeDeviceCredential_AbandonsOnIdentityMismatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if _, _, _, err := loadOrCreateDeviceIdentity(); err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}

	// signingPub is some OTHER key, not the one on disk.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other keypair: %v", err)
	}

	merged, err := mergeDeviceCredential(otherPub, "devX", "aa.bb.cc", "2099-01-01T00:00:00Z", "jtiX")
	if err != nil {
		t.Fatalf("mergeDeviceCredential: %v", err)
	}
	if merged {
		t.Fatal("merge must be abandoned when the signing key no longer matches the on-disk identity")
	}

	rec, err := readDeviceRecord()
	if err != nil {
		t.Fatalf("readDeviceRecord: %v", err)
	}
	if rec.DeviceID != "" {
		t.Errorf("record was mutated despite the abandoned merge: %+v", rec)
	}
}

// TestMergeDeviceCredential_DoesNotClobberNewerSameDeviceCredential covers
// design.md's freshness guard: a usable credential for the SAME device that
// expires LATER than the one being written must not be overwritten.
func TestMergeDeviceCredential_DoesNotClobberNewerSameDeviceCredential(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, _, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}

	later := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	earlier := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)

	if _, err := mergeDeviceCredential(pub, "dev1", "aa.bb.newer", later, "jti-newer"); err != nil {
		t.Fatalf("first merge: %v", err)
	}
	merged, err := mergeDeviceCredential(pub, "dev1", "aa.bb.older", earlier, "jti-older")
	if err != nil {
		t.Fatalf("second merge: %v", err)
	}
	if merged {
		t.Fatal("a stale (earlier-expiring) same-device credential must not clobber a newer one")
	}

	rec, err := readDeviceRecord()
	if err != nil {
		t.Fatalf("readDeviceRecord: %v", err)
	}
	if rec.Jti != "jti-newer" {
		t.Errorf("record was clobbered: jti = %q, want jti-newer", rec.Jti)
	}
}

// TestMergeDeviceCredential_DifferentDeviceReplacesRegardlessOfExpiry
// covers the requirements.md freshness-guard criterion directly: a stored
// credential naming a DIFFERENT device -- even one with a later expires_at
// -- must never veto a write for the device that supersedes it (this is the
// scenario T15 exercises through the full activate/409 path; this test
// isolates the merge primitive itself).
func TestMergeDeviceCredential_DifferentDeviceReplacesRegardlessOfExpiry(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, _, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}

	farFuture := time.Now().Add(100 * time.Hour).UTC().Format(time.RFC3339)
	nearFuture := time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)

	if _, err := mergeDeviceCredential(pub, "dev-old", "aa.bb.old", farFuture, "jti-old"); err != nil {
		t.Fatalf("first merge: %v", err)
	}
	merged, err := mergeDeviceCredential(pub, "dev-new", "aa.bb.new", nearFuture, "jti-new")
	if err != nil {
		t.Fatalf("second merge: %v", err)
	}
	if !merged {
		t.Fatal("a credential naming a different device must replace unconditionally, regardless of expiry")
	}

	rec, err := readDeviceRecord()
	if err != nil {
		t.Fatalf("readDeviceRecord: %v", err)
	}
	if rec.DeviceID != "dev-new" || rec.Jti != "jti-new" {
		t.Errorf("record was not replaced: %+v", rec)
	}
}

// ----- withDeviceRecordLock -----

func TestWithDeviceRecordLock_WaitsThenSucceeds(t *testing.T) {
	dir := t.TempDir()

	var wg sync.WaitGroup
	holdReleased := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = withDeviceRecordLock(dir, 2*time.Second, func() error {
			time.Sleep(150 * time.Millisecond)
			close(holdReleased)
			return nil
		})
	}()

	// Give the goroutine a moment to acquire the lock first.
	time.Sleep(20 * time.Millisecond)

	start := time.Now()
	err := withDeviceRecordLock(dir, 2*time.Second, func() error { return nil })
	if err != nil {
		t.Fatalf("withDeviceRecordLock: %v", err)
	}
	if time.Since(start) < 100*time.Millisecond {
		t.Error("second call returned before the first lock was plausibly released -- lock may not be exclusive")
	}
	wg.Wait()
	select {
	case <-holdReleased:
	default:
		t.Error("first holder never ran its critical section")
	}
}

func TestWithDeviceRecordLock_TimesOutOnContention(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Hold the lock the way a live process holds it: on an open handle. The
	// file merely existing is not the lock -- see the staleness test below.
	f, err := os.OpenFile(deviceLockFilePath(dir), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open lock file: %v", err)
	}
	defer f.Close()
	got, err := lockFileExclusive(f)
	if err != nil || !got {
		t.Fatalf("seed lock: got=%v err=%v", got, err)
	}
	defer unlockFile(f)

	err = withDeviceRecordLock(dir, 200*time.Millisecond, func() error {
		t.Fatal("fn must not run when the lock could not be acquired")
		return nil
	})
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
}

// A lockfile left behind by a process that died holding it must NOT block
// anything. The lock lives on the open handle, and the kernel drops it when
// the holder dies however it dies -- which is the whole reason this is an
// advisory lock and not a sentinel file. With a sentinel, a SIGKILL, an OOM
// kill or a power cut left every later activate and daemon refresh failing
// until a human found and deleted the file: the guard against a bricked
// config directory becoming a way to brick one.
func TestWithDeviceRecordLock_StaleLockFileDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	// A file left over from a dead holder: present, unlocked.
	f, err := os.OpenFile(deviceLockFilePath(dir), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open lock file: %v", err)
	}
	if _, err := f.WriteString("leftover"); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close() // process died; the OS released whatever it held

	ran := false
	start := time.Now()
	if err := withDeviceRecordLock(dir, 2*time.Second, func() error {
		ran = true
		return nil
	}); err != nil {
		t.Fatalf("a leftover lock file blocked acquisition: %v", err)
	}
	if !ran {
		t.Fatal("fn did not run")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waited %v for a lock nobody holds", elapsed)
	}
}
