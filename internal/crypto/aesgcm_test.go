package crypto

import (
	"bytes"
	"testing"
)

const testKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func testKey(t *testing.T) []byte {
	t.Helper()
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		hi := hexNib(t, testKeyHex[i*2])
		lo := hexNib(t, testKeyHex[i*2+1])
		out[i] = hi<<4 | lo
	}
	return out
}

func hexNib(t *testing.T, b byte) byte {
	t.Helper()
	switch {
	case b >= '0' && b <= '9':
		return b - '0'
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10
	}
	t.Fatalf("bad hex char %q", b)
	return 0
}

func TestSealOpenForUser_Roundtrip(t *testing.T) {
	a, err := New(testKey(t))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	pt := []byte("hello, mtproto")
	blob, err := a.SealForUser(pt, 42)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if blob[0] != VersionPerUser {
		t.Fatalf("expected version byte 0x02, got 0x%02x", blob[0])
	}
	out, err := a.OpenForUser(blob, 42)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(pt, out) {
		t.Fatalf("roundtrip mismatch: %q vs %q", pt, out)
	}
}

func TestOpenForUser_WrongUserFails(t *testing.T) {
	a, _ := New(testKey(t))
	blob, _ := a.SealForUser([]byte("secret"), 42)
	_, err := a.OpenForUser(blob, 43)
	if err == nil {
		t.Fatal("expected GCM tag check to fail with wrong user id")
	}
}

func TestDifferentUsersProduceDifferentSubkeys(t *testing.T) {
	a, _ := New(testKey(t))
	k1, err := deriveUserKey(a.Key, 1)
	if err != nil {
		t.Fatalf("derive 1: %v", err)
	}
	k2, err := deriveUserKey(a.Key, 2)
	if err != nil {
		t.Fatalf("derive 2: %v", err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("HKDF should produce different subkeys for different users")
	}
}

func TestBlindIndexForUser_IsStableAndTenantScoped(t *testing.T) {
	a, _ := New(testKey(t))
	first, err := a.BlindIndexForUser("approval", []byte("ABC123"), 42)
	if err != nil {
		t.Fatalf("first index: %v", err)
	}
	repeated, err := a.BlindIndexForUser("approval", []byte("ABC123"), 42)
	if err != nil {
		t.Fatalf("repeated index: %v", err)
	}
	otherUser, err := a.BlindIndexForUser("approval", []byte("ABC123"), 43)
	if err != nil {
		t.Fatalf("other user index: %v", err)
	}
	otherPurpose, err := a.BlindIndexForUser("different", []byte("ABC123"), 42)
	if err != nil {
		t.Fatalf("other purpose index: %v", err)
	}
	if !bytes.Equal(first, repeated) {
		t.Fatal("blind index is not deterministic")
	}
	if bytes.Equal(first, otherUser) {
		t.Fatal("blind index must differ between users")
	}
	if bytes.Equal(first, otherPurpose) {
		t.Fatal("blind index must differ between purposes")
	}
	if bytes.Equal(first, []byte("ABC123")) {
		t.Fatal("blind index exposed plaintext")
	}
}

func TestOpenForUser_LegacyV1Blob(t *testing.T) {
	a, _ := New(testKey(t))
	// Produce a legacy v1 blob via the old Seal entry point.
	pt := []byte("legacy plaintext")
	v1blob, err := a.Seal(pt)
	if err != nil {
		t.Fatalf("seal v1: %v", err)
	}
	if v1blob[0] != VersionMaster {
		t.Fatalf("expected v1 byte 0x01, got 0x%02x", v1blob[0])
	}
	// OpenForUser must read v1 with the master key (user id is ignored for v1).
	out, err := a.OpenForUser(v1blob, 999)
	if err != nil {
		t.Fatalf("open v1: %v", err)
	}
	if !bytes.Equal(pt, out) {
		t.Fatalf("v1 roundtrip mismatch")
	}
}

func TestOpen_RejectsV2Blob(t *testing.T) {
	a, _ := New(testKey(t))
	v2blob, _ := a.SealForUser([]byte("x"), 7)
	if _, err := a.Open(v2blob); err == nil {
		t.Fatal("legacy Open must refuse v2 blobs — caller has no user id")
	}
}

func TestSealForUser_LocalDevPlaintextFallback(t *testing.T) {
	a, _ := New(nil) // local-dev mode
	blob, err := a.SealForUser([]byte("dev"), 1)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if blob[0] != VersionPlaintext {
		t.Fatalf("expected plaintext sentinel, got 0x%02x", blob[0])
	}
	out, err := a.OpenForUser(blob, 1)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(out, []byte("dev")) {
		t.Fatal("plaintext roundtrip mismatch")
	}
}

func TestBlobVersion(t *testing.T) {
	a, _ := New(testKey(t))
	v1, _ := a.Seal([]byte("a"))
	v2, _ := a.SealForUser([]byte("a"), 1)
	if a.BlobVersion(v1) != VersionMaster {
		t.Fatal("expected v1")
	}
	if a.BlobVersion(v2) != VersionPerUser {
		t.Fatal("expected v2")
	}
	if a.BlobVersion(nil) != 0xFF {
		t.Fatal("expected 0xFF sentinel on empty")
	}
}
