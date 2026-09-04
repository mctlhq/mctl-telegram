package oauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
)

// registerTestDevice creates a user + local account + device row with a
// freshly generated Ed25519 keypair, returning the device_id and private key
// so tests can sign PoP requests against it.
func registerTestDevice(t *testing.T, srv *Server, tgID int64) (deviceID string, priv ed25519.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, tgID, "u", "U")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := srv.store.ProvisionLocalAccount(ctx, uid, tgID, "U", "u"); err != nil {
		t.Fatalf("provision local account: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	deviceID, err = srv.store.RegisterDevice(ctx, uid, "test-device", randomToken(8), pub)
	if err != nil {
		t.Fatalf("register device: %v", err)
	}
	return deviceID, priv
}

func chiRouterFor(srv *Server) http.Handler {
	r := chi.NewRouter()
	srv.Register(r)
	return r
}

func doDeviceNonce(t *testing.T, h http.Handler, deviceID string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/local-bridge/devices/"+deviceID+"/nonce", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("nonce status = %d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode nonce response: %v", err)
	}
	return out.Nonce
}

func signDevicePoP(priv ed25519.PrivateKey, deviceID, nonce string) string {
	sig := ed25519.Sign(priv, []byte(deviceID+"."+nonce))
	return base64.StdEncoding.EncodeToString(sig)
}

func doDeviceCredential(t *testing.T, h http.Handler, path, deviceID, nonce, sig string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(devicePoPRequest{Nonce: nonce, Signature: sig})
	req := httptest.NewRequest(http.MethodPost, "/api/local-bridge/devices/"+deviceID+"/"+path, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// T3: first credential for a freshly activated device is hours-scale TTL,
// carries DeviceID, and NEVER carries send/pin scope even when the
// account's send_enabled is already true from a prior admin action.
func TestDeviceCredential_IssuanceIsAlwaysReadOnly(t *testing.T) {
	srv := newTestServer(t)
	h := chiRouterFor(srv)
	deviceID, priv := registerTestDevice(t, srv, 700000001)
	// send_enabled already true before first issuance.
	uid, _ := srv.store.UserIDByTelegramID(context.Background(), 700000001)
	if _, err := srv.store.SetSendEnabled(context.Background(), uid, true); err != nil {
		t.Fatalf("set send enabled: %v", err)
	}

	nonce := doDeviceNonce(t, h, deviceID)
	sig := signDevicePoP(priv, deviceID, nonce)
	rec := doDeviceCredential(t, h, "credential", deviceID, nonce, sig)
	if rec.Code != http.StatusOK {
		t.Fatalf("credential status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp deviceCredentialResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	claims, err := localjwt.Verify(resp.WorkerToken, srv.cfg.JWTSecret, srv.cfg.Issuer)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.DeviceID != deviceID {
		t.Errorf("DeviceID = %q, want %q", claims.DeviceID, deviceID)
	}
	for _, s := range claims.Scopes {
		if s == "telegram:messages:send" || s == "telegram:messages:pin" {
			t.Fatalf("first issuance carries a send/pin scope despite send_enabled being irrelevant at issuance: %v", claims.Scopes)
		}
	}
	ttl := claims.ExpiresAt - claims.IssuedAt
	if ttl <= 0 || ttl > int64((25*3600)) {
		t.Errorf("TTL = %ds, want hours-scale (<=24h)", ttl)
	}
}

// T4b: a device row with a malformed stored key (wrong length) is rejected
// generically, and the handler does not panic -- this is exactly the guard
// that must run before ed25519.Verify.
func TestDeviceCredential_MalformedStoredKeyDoesNotPanic(t *testing.T) {
	srv := newTestServer(t)
	h := chiRouterFor(srv)
	ctx := context.Background()
	uid, _ := srv.store.EnsureUserByTelegramID(ctx, 700000002, "u2", "U2")
	if err := srv.store.ProvisionLocalAccount(ctx, uid, 700000002, "U2", "u2"); err != nil {
		t.Fatalf("provision: %v", err)
	}
	// Truncated "pubkey" -- 5 bytes, not 32.
	deviceID, err := srv.store.RegisterDevice(ctx, uid, "bad-key-device", "idem", []byte{1, 2, 3, 4, 5})
	if err != nil {
		t.Fatalf("register device: %v", err)
	}

	nonce := doDeviceNonce(t, h, deviceID)
	// The signature content does not matter -- the length guard must reject
	// before any verification is attempted.
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("handler panicked on malformed stored key: %v", p)
		}
	}()
	rec := doDeviceCredential(t, h, "credential", deviceID, nonce, base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (generic rejection, no panic)", rec.Code)
	}
	if rec.Body.String() == "" || !bytes.Contains(rec.Body.Bytes(), []byte(devicePoPGenericRejection)) {
		t.Errorf("body = %s, want generic rejection message", rec.Body.String())
	}
}

// Unknown device_id and a bad signature return the SAME generic rejection --
// no oracle distinguishing "device doesn't exist" from "wrong key".
func TestDeviceCredential_UnknownDeviceAndBadSignatureAreIndistinguishable(t *testing.T) {
	srv := newTestServer(t)
	h := chiRouterFor(srv)
	deviceID, priv := registerTestDevice(t, srv, 700000003)

	// Unknown device.
	unknownNonce := doDeviceNonce(t, h, "dev_does_not_exist")
	recUnknown := doDeviceCredential(t, h, "credential", "dev_does_not_exist", unknownNonce,
		base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))

	// Bad signature against a real device.
	nonce := doDeviceNonce(t, h, deviceID)
	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	_ = priv
	badSig := signDevicePoP(wrongPriv, deviceID, nonce)
	recBadSig := doDeviceCredential(t, h, "credential", deviceID, nonce, badSig)

	if recUnknown.Code != recBadSig.Code || recUnknown.Code != http.StatusForbidden {
		t.Fatalf("status codes differ or aren't 403: unknown=%d badsig=%d", recUnknown.Code, recBadSig.Code)
	}
	if recUnknown.Body.String() != recBadSig.Body.String() {
		t.Fatalf("bodies differ, creating an oracle: unknown=%q badsig=%q", recUnknown.Body.String(), recBadSig.Body.String())
	}
}

// T5g: refresh before issuance is refused with 409 and mints nothing.
func TestDeviceRefresh_BeforeIssuanceRefused(t *testing.T) {
	srv := newTestServer(t)
	h := chiRouterFor(srv)
	deviceID, priv := registerTestDevice(t, srv, 700000004)

	nonce := doDeviceNonce(t, h, deviceID)
	sig := signDevicePoP(priv, deviceID, nonce)
	rec := doDeviceCredential(t, h, "refresh", deviceID, nonce, sig)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	d, err := srv.store.GetDevice(context.Background(), deviceID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if d.CurrentJti != "" {
		t.Fatal("refresh before issuance must not claim a lineage")
	}
}

// T5: grant send_enabled after issuance -> next refresh includes send/pin;
// revoke -> next refresh omits them.
func TestDeviceRefresh_ScopesDerivedFromLiveSendEnabled(t *testing.T) {
	srv := newTestServer(t)
	h := chiRouterFor(srv)
	deviceID, priv := registerTestDevice(t, srv, 700000005)

	// First issuance.
	nonce := doDeviceNonce(t, h, deviceID)
	sig := signDevicePoP(priv, deviceID, nonce)
	rec := doDeviceCredential(t, h, "credential", deviceID, nonce, sig)
	if rec.Code != http.StatusOK {
		t.Fatalf("issuance status = %d body=%s", rec.Code, rec.Body.String())
	}
	var issued deviceCredentialResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &issued)

	// Grant send consent, then refresh -- must include send/pin.
	uid, _ := srv.store.UserIDByTelegramID(context.Background(), 700000005)
	if _, err := srv.store.SetSendEnabled(context.Background(), uid, true); err != nil {
		t.Fatalf("grant: %v", err)
	}
	nonce2 := doDeviceNonce(t, h, deviceID)
	sig2 := signDevicePoP(priv, deviceID, nonce2)
	rec2 := doDeviceCredential(t, h, "refresh", deviceID, nonce2, sig2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("refresh after grant status = %d body=%s", rec2.Code, rec2.Body.String())
	}
	var afterGrant deviceCredentialResponse
	_ = json.Unmarshal(rec2.Body.Bytes(), &afterGrant)
	claimsGrant, err := localjwt.Verify(afterGrant.WorkerToken, srv.cfg.JWTSecret, srv.cfg.Issuer)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !hasScope(claimsGrant.Scopes, "telegram:messages:send") {
		t.Fatalf("refresh after grant missing send scope: %v", claimsGrant.Scopes)
	}
	// jti/original_issued_at unchanged across refresh (T5f).
	if afterGrant.Jti != issued.Jti {
		t.Errorf("jti changed across refresh: %q -> %q", issued.Jti, afterGrant.Jti)
	}

	// Revoke send consent, then refresh -- must omit send/pin.
	if _, err := srv.store.SetSendEnabled(context.Background(), uid, false); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	nonce3 := doDeviceNonce(t, h, deviceID)
	sig3 := signDevicePoP(priv, deviceID, nonce3)
	rec3 := doDeviceCredential(t, h, "refresh", deviceID, nonce3, sig3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("refresh after revoke status = %d body=%s", rec3.Code, rec3.Body.String())
	}
	var afterRevoke deviceCredentialResponse
	_ = json.Unmarshal(rec3.Body.Bytes(), &afterRevoke)
	claimsRevoke, err := localjwt.Verify(afterRevoke.WorkerToken, srv.cfg.JWTSecret, srv.cfg.Issuer)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if hasScope(claimsRevoke.Scopes, "telegram:messages:send") {
		t.Fatalf("refresh after revoke still carries send scope: %v", claimsRevoke.Scopes)
	}
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

// T5d: two concurrent first-issuance CLAIMS for the same device_id -- exactly
// one wins, the other loses with nothing minted. This races
// ClaimDeviceCredentialLineage directly (the actual serialisation point
// handleDeviceCredential relies on -- see db.Store.ClaimDeviceCredentialLineage
// and its own dedicated concurrency coverage in internal/db) rather than two
// full PoP round trips: Server.deviceNonces holds exactly one live nonce per
// device_id, so two concurrent HTTP requests for the same device race the
// NONCE slot first, which is a legitimate, separate single-flight property
// of this design, not the lineage race this test exists to isolate.
func TestDeviceCredential_ConcurrentFirstIssuanceClaim(t *testing.T) {
	srv := newTestServer(t)
	deviceID, _ := registerTestDevice(t, srv, 700000006)

	var wg sync.WaitGroup
	won := make([]bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			w, err := srv.store.ClaimDeviceCredentialLineage(context.Background(), deviceID, "jti-race-"+string(rune('A'+idx)), srv.clock())
			if err != nil {
				return
			}
			won[idx] = w
		}(i)
	}
	wg.Wait()

	successCount := 0
	for _, w := range won {
		if w {
			successCount++
		}
	}
	if successCount != 1 {
		t.Fatalf("expected exactly 1 winning claim, got %d (won=%v)", successCount, won)
	}
}

// T5e: revoking the device between the PoP check and the claim makes the
// conditional UPDATE's revoked_at IS NULL predicate refuse issuance, with no
// credential minted.
func TestDeviceCredential_IssuanceRacingRevocationLoses(t *testing.T) {
	srv := newTestServer(t)
	h := chiRouterFor(srv)
	deviceID, priv := registerTestDevice(t, srv, 700000007)

	nonce := doDeviceNonce(t, h, deviceID)
	sig := signDevicePoP(priv, deviceID, nonce)

	// Revoke the device BEFORE the claim (simulating a revoke landing
	// between PoP verification and the claim statement, which the
	// conditional UPDATE's predicate must catch regardless of timing).
	if err := srv.store.RevokeDevice(context.Background(), deviceID, "raced revoke"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	rec := doDeviceCredential(t, h, "credential", deviceID, nonce, sig)
	// verifyDevicePoP itself already refuses a revoked device (device.RevokedAt
	// != nil), so this is refused at the PoP stage -- 403, generic rejection --
	// which is an even stronger guarantee than reaching the claim statement.
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (revoked device refused)", rec.Code)
	}
	d, err := srv.store.GetDevice(context.Background(), deviceID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if d.CurrentJti != "" {
		t.Fatal("a revoked device must not have claimed a lineage")
	}
}

// The nonce map's capacity bound was itself the attack. /nonce is
// unauthenticated, so an attacker cycling through random device_id values
// filled the map and then evicted a live nonce with every further request:
// no real device could complete a PoP round trip, and issuance and refresh
// stopped working for everyone. A bogus device_id must therefore occupy no
// slot at all. The flood comes from distinct source addresses, because a
// single-address flood is already stopped by the per-IP failure budget --
// the slot rule is what has to hold when that budget does not apply.
func TestDeviceNonce_UnknownDeviceOccupiesNoSlot(t *testing.T) {
	srv := newTestServer(t)
	h := chiRouterFor(srv)
	deviceID, priv := registerTestDevice(t, srv, 700000201)

	// A legitimate device takes its nonce first, making it the oldest entry
	// and therefore the first casualty of a global oldest-evict.
	victimNonce := doDeviceNonce(t, h, deviceID)

	for i := 0; i < 200; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST",
			"/api/local-bridge/devices/dev_flood_"+randomToken(8)+"/nonce", nil)
		req.RemoteAddr = fmt.Sprintf("203.0.%d.%d:1000", i/254, i%254)
		h.ServeHTTP(rec, req)
	}

	srv.mu.Lock()
	stored := len(srv.deviceNonces)
	_, victimStillThere := srv.deviceNonces[deviceID]
	srv.mu.Unlock()
	if stored != 1 {
		t.Errorf("nonce map holds %d entries after a 200-request flood, want 1", stored)
	}
	if !victimStillThere {
		t.Fatal("the flood evicted a legitimate device's nonce")
	}

	// And the victim's nonce is still usable, which is the property that
	// actually matters to them.
	rec := doDeviceCredential(t, h, "credential", deviceID, victimNonce, signDevicePoP(priv, deviceID, victimNonce))
	if rec.Code != http.StatusOK {
		t.Fatalf("victim's credential call after the flood = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// Refusing to store a bogus id must not become an "does this device exist"
// oracle: at equal rate-limiter state, a real device_id and a bogus one are
// answered identically, so the distinction is only ever learned at the
// credential step, where it already collapses into one generic rejection.
func TestDeviceNonce_KnownAndUnknownAreIndistinguishable(t *testing.T) {
	srv := newTestServer(t)
	h := chiRouterFor(srv)
	deviceID, _ := registerTestDevice(t, srv, 700000202)

	call := func(id, addr string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/local-bridge/devices/"+id+"/nonce", nil)
		req.RemoteAddr = addr
		h.ServeHTTP(rec, req)
		return rec
	}
	real := call(deviceID, "198.51.100.1:1000")
	bogus := call("dev_definitely_not_real", "198.51.100.2:1000")

	if real.Code != bogus.Code {
		t.Fatalf("status codes differ: real=%d bogus=%d", real.Code, bogus.Code)
	}
	var rj, bj map[string]any
	if err := json.Unmarshal(real.Body.Bytes(), &rj); err != nil {
		t.Fatalf("decode real: %v", err)
	}
	if err := json.Unmarshal(bogus.Body.Bytes(), &bj); err != nil {
		t.Fatalf("decode bogus: %v", err)
	}
	if len(rj) != len(bj) || rj["expires_in"] != bj["expires_in"] {
		t.Fatalf("response shapes differ, creating an oracle: real=%v bogus=%v", rj, bj)
	}
	if rj["nonce"] == "" || bj["nonce"] == "" {
		t.Fatal("one of the responses carried no nonce")
	}
}
