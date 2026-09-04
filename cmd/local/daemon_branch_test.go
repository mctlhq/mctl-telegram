package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestSelectDeviceCredentialSource_NoFilesAtAll covers the "config directory
// containing only legacy files" branch of task 5's DoD: with no device
// record present at all, the legacy path applies (nil, nil, nil).
func TestSelectDeviceCredentialSource_NoFilesAtAll(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	rec, priv, err := selectDeviceCredentialSource()
	if err != nil {
		t.Fatalf("selectDeviceCredentialSource: %v", err)
	}
	if rec != nil || priv != nil {
		t.Fatalf("expected legacy path (nil, nil) with no device files, got rec=%+v priv=%v", rec, priv != nil)
	}
}

// TestSelectDeviceCredentialSource_IdentityOnlyUsesLegacyPath covers T16:
// a device identity file with NO device credential (an interrupted
// activation) must still resolve to the legacy path -- branching on the
// identity's mere presence instead of the credential is exactly the
// mutation this test is designed to catch.
func TestSelectDeviceCredentialSource_IdentityOnlyUsesLegacyPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	rec, _, _, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}
	if rec.DeviceID != "" || rec.WorkerToken != "" {
		t.Fatalf("freshly generated identity unexpectedly has credential fields: %+v", rec)
	}

	gotRec, gotPriv, err := selectDeviceCredentialSource()
	if err != nil {
		t.Fatalf("selectDeviceCredentialSource: %v", err)
	}
	if gotRec != nil || gotPriv != nil {
		t.Fatalf("identity-only record must resolve to the legacy path (nil, nil), got rec=%+v priv=%v", gotRec, gotPriv != nil)
	}
}

// TestSelectDeviceCredentialSource_UsableCredentialUsesDeviceSignedPath
// covers the third leg of task 5's DoD: a device record with a usable
// credential resolves to the device-signed path.
func TestSelectDeviceCredentialSource_UsableCredentialUsesDeviceSignedPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, priv, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}
	future := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := mergeDeviceCredential(pub, "dev1", "a.b.c", future, "jti1"); err != nil {
		t.Fatalf("mergeDeviceCredential: %v", err)
	}

	gotRec, gotPriv, err := selectDeviceCredentialSource()
	if err != nil {
		t.Fatalf("selectDeviceCredentialSource: %v", err)
	}
	if gotRec == nil || gotRec.DeviceID != "dev1" {
		t.Fatalf("expected device-signed path naming dev1, got %+v", gotRec)
	}
	if len(gotPriv) != ed25519.PrivateKeySize {
		t.Fatalf("returned private key has length %d, want %d", len(gotPriv), ed25519.PrivateKeySize)
	}
	if string(gotPriv) != string(priv) {
		t.Error("returned private key does not match the one on disk")
	}
}

// TestSelectDeviceCredentialSource_CorruptKeyWithUsableCredentialErrors
// covers T23: a device record whose credential fields look complete but
// whose signing key material is unusable must return a hard error naming
// `activate`, NOT silently fall back to the legacy path and not panic.
func TestSelectDeviceCredentialSource_CorruptKeyWithUsableCredentialErrors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, _, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}
	future := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := mergeDeviceCredential(pub, "dev1", "a.b.c", future, "jti1"); err != nil {
		t.Fatalf("mergeDeviceCredential: %v", err)
	}

	// Corrupt the private key in place -- credential fields remain intact.
	rec, err := readDeviceRecord()
	if err != nil {
		t.Fatalf("readDeviceRecord: %v", err)
	}
	rec.PrivateKey = "corrupted-not-base64!!"
	if err := writeDeviceRecord(rec); err != nil {
		t.Fatalf("writeDeviceRecord: %v", err)
	}

	gotRec, gotPriv, err := selectDeviceCredentialSource()
	if err == nil {
		t.Fatal("expected an error for unusable key material with a usable-looking credential")
	}
	if !strings.Contains(err.Error(), "activate") {
		t.Errorf("error does not name `activate` as the fix: %v", err)
	}
	if gotRec != nil || gotPriv != nil {
		t.Errorf("expected no record/key returned alongside the error, got rec=%+v priv=%v", gotRec, gotPriv != nil)
	}

	// Must not have rotated or otherwise mutated the record as a side
	// effect of merely detecting the corruption -- that is `activate`'s job
	// alone.
	after, err := readDeviceRecord()
	if err != nil {
		t.Fatalf("readDeviceRecord (after): %v", err)
	}
	if after.PrivateKey != "corrupted-not-base64!!" {
		t.Error("selectDeviceCredentialSource must not repair or rotate corrupt key material -- that silently re-registers the device")
	}
	if after.DeviceID != "dev1" {
		t.Error("selectDeviceCredentialSource must not clear the credential fields either")
	}
}

// ----- out-of-band send-scope refresh bounds (T18) -----

// makeTestJWT builds a minimal, unsigned-but-well-shaped 3-segment JWT
// carrying the given scopes in its payload, sufficient for jwtScopes to
// decode (which never verifies the signature -- see its doc comment).
func makeTestJWT(t *testing.T, scopes []string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payloadJSON := `{"scopes":[`
	for i, s := range scopes {
		if i > 0 {
			payloadJSON += ","
		}
		payloadJSON += `"` + s + `"`
	}
	payloadJSON += `]}`
	payload := base64.RawURLEncoding.EncodeToString([]byte(payloadJSON))
	return header + "." + payload + ".sig"
}

// A failed refresh inside the reconnect loop must not kill the daemon. The
// loop runs on every reconnect, so the failure it sees most often is the same
// network trouble that dropped the connection — returning would turn a blip
// into a dead service that only a human restart brings back.
func TestRunDaemon_RefreshFailureRetriesInsteadOfExiting(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	// A device record with usable key material and a usable credential, so the
	// device-signed branch is the one taken -- pointed at a server that is not
	// there, so every refresh attempt fails.
	_, _, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}
	future := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := mergeDeviceCredential(pub, "dev_unreachable", "a.b.c", future, "jti1"); err != nil {
		t.Fatalf("mergeDeviceCredential: %v", err)
	}

	cfg := &localConfig{Server: "http://127.0.0.1:1"}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- runDaemon(ctx, cfg, nil, 1, nil) }()

	select {
	case err := <-done:
		// It must have stopped because the context ended, not because it gave
		// up on the refresh.
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
			t.Fatalf("daemon exited on a refresh failure instead of retrying: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runDaemon did not return after its context ended")
	}
}
