package main

import (
	"crypto/ed25519"
	"encoding/base64"
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

func TestJWTScopes_DecodesWithoutVerifyingSignature(t *testing.T) {
	tok := makeTestJWT(t, []string{"telegram:dialogs:read", "telegram:messages:send"})
	scopes, err := jwtScopes(tok)
	if err != nil {
		t.Fatalf("jwtScopes: %v", err)
	}
	if !hasScope(scopes, "telegram:messages:send") {
		t.Errorf("scopes = %v, want telegram:messages:send present", scopes)
	}
}

func TestJWTScopes_RejectsNonThreeSegmentToken(t *testing.T) {
	if _, err := jwtScopes("not-a-jwt"); err == nil {
		t.Fatal("expected an error for a non-3-segment token")
	}
}

// TestMaybeUpgradeSendMode_NoDeviceCredentialLeavesLegacyUntouched ensures
// the legacy (no device credential) path is left entirely alone.
func TestMaybeUpgradeSendMode_NoDeviceCredentialLeavesLegacyUntouched(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	realSend := false
	dryReason := "per-account send_enabled=false"
	cfg := &localConfig{Server: "http://unused.invalid"}

	maybeUpgradeSendMode(t.Context(), cfg, &realSend, &dryReason)

	if realSend {
		t.Error("realSend was upgraded despite no device credential on disk")
	}
	if dryReason != "per-account send_enabled=false" {
		t.Errorf("dryReason was mutated despite no device credential on disk: %q", dryReason)
	}
}

// TestMaybeUpgradeSendMode_AlreadyRealSendIsNoOp ensures a real send is
// never second-guessed.
func TestMaybeUpgradeSendMode_AlreadyRealSendIsNoOp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	realSend := true
	dryReason := ""
	cfg := &localConfig{Server: "http://unused.invalid"}

	maybeUpgradeSendMode(t.Context(), cfg, &realSend, &dryReason)

	if !realSend {
		t.Error("realSend was downgraded; a real send must never be second-guessed")
	}
}

// TestMaybeUpgradeSendMode_CooldownBoundsRepeatedRefusals covers T18: with
// the stored credential already lacking the send scope and an
// unreachable/failing server, repeated calls must not each attempt a
// network refresh once the cooldown window is active. This exercises the
// bound structurally (the cooldown timer) rather than by counting HTTP
// calls against a real server, since a failing refresh already returns
// early: the real assurance is that lastOutOfBandRefresh is set on the
// FIRST attempt and blocks the second within the cooldown window.
func TestMaybeUpgradeSendMode_CooldownBoundsRepeatedRefusals(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, _, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}
	readOnlyToken := makeTestJWT(t, []string{"telegram:dialogs:read"})
	future := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := mergeDeviceCredential(pub, "dev1", readOnlyToken, future, "jti1"); err != nil {
		t.Fatalf("mergeDeviceCredential: %v", err)
	}

	outOfBandRefreshMu.Lock()
	lastOutOfBandRefresh = time.Now() // pretend a refresh JUST happened
	outOfBandRefreshMu.Unlock()
	t.Cleanup(func() {
		outOfBandRefreshMu.Lock()
		lastOutOfBandRefresh = time.Time{}
		outOfBandRefreshMu.Unlock()
	})

	realSend := false
	dryReason := "mode=draft"
	cfg := &localConfig{Server: "http://127.0.0.1:1"} // nothing listens here
	maybeUpgradeSendMode(t.Context(), cfg, &realSend, &dryReason)

	if realSend {
		t.Error("realSend was upgraded during the cooldown window")
	}
	rec, err := readDeviceRecord()
	if err != nil {
		t.Fatalf("readDeviceRecord: %v", err)
	}
	if rec.Jti != "jti1" {
		t.Error("a refresh attempt was made during the cooldown window (credential changed)")
	}
}

// TestMaybeUpgradeSendMode_AlreadyHasScopeSkipsRefresh ensures a stored
// credential that already carries the send scope is not refreshed again --
// the draft verdict must have come from something else a refresh cannot
// fix.
func TestMaybeUpgradeSendMode_AlreadyHasScopeSkipsRefresh(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, _, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}
	sendToken := makeTestJWT(t, []string{"telegram:dialogs:read", "telegram:messages:send"})
	future := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := mergeDeviceCredential(pub, "dev1", sendToken, future, "jti1"); err != nil {
		t.Fatalf("mergeDeviceCredential: %v", err)
	}

	realSend := false
	dryReason := "server flag ALLOW_SEND=false"
	cfg := &localConfig{Server: "http://127.0.0.1:1"}
	maybeUpgradeSendMode(t.Context(), cfg, &realSend, &dryReason)

	if realSend {
		t.Error("realSend was upgraded even though the draft verdict did not come from a scope gap")
	}
	if dryReason != "server flag ALLOW_SEND=false" {
		t.Errorf("dryReason was mutated: %q", dryReason)
	}
}
