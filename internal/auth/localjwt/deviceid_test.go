package localjwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// T8: Mint with Claims.DeviceID set followed by Verify returns
// Claims.DeviceID unchanged.
func TestMint_Verify_DeviceIDRoundtrip(t *testing.T) {
	iss, err := NewIssuer(testSecret, testIssuer)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, err := iss.Mint(Claims{
		Subject:  "tg:1",
		DeviceID: "dev_abc",
	}, 1*time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	c, err := Verify(tok, testSecret, testIssuer)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.DeviceID != "dev_abc" {
		t.Errorf("DeviceID = %q, want %q", c.DeviceID, "dev_abc")
	}
}

// T9: Mint with DeviceID unset produces a token whose decoded payload does
// not contain the "device_id" key at all -- asserts the omitempty behavior
// directly, not just the round-trip.
func TestMint_OmitsEmptyDeviceID(t *testing.T) {
	iss, err := NewIssuer(testSecret, testIssuer)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, err := iss.Mint(Claims{Subject: "tg:1"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token does not have 3 parts: %q", tok)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payloadJSON, &raw); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if _, present := raw["device_id"]; present {
		t.Errorf("payload contains a device_id key when DeviceID was unset: %s", payloadJSON)
	}
}

// T10 (the issue's Definition of Done regression test): Verify on a
// hand-constructed token payload shaped like one minted before this claim
// existed -- no device_id key present at all -- succeeds and returns
// Claims.DeviceID == "", with every other claim intact. This is a raw
// fixture payload rather than a round-trip through the new Mint, so it
// actually exercises "a token that predates the field" rather than "a token
// that sets the field to its zero value."
func TestVerify_LegacyTokenWithoutDeviceID(t *testing.T) {
	now := time.Now()
	legacyPayload := map[string]any{
		"iss":         testIssuer,
		"sub":         "tg:210408407",
		"tg_id":       210408407,
		"tg_username": "MashkovD",
		"iat":         now.Unix(),
		"exp":         now.Add(1 * time.Hour).Unix(),
		// Deliberately no "device_id" key -- this is what every token minted
		// before this field existed looks like on the wire.
	}
	tok := signRawPayload(t, legacyPayload, testSecret)
	c, err := Verify(tok, testSecret, testIssuer)
	if err != nil {
		t.Fatalf("Verify legacy token: %v", err)
	}
	if c.DeviceID != "" {
		t.Errorf("DeviceID = %q, want empty string for a legacy token", c.DeviceID)
	}
	if c.Subject != "tg:210408407" {
		t.Errorf("Subject = %q", c.Subject)
	}
	if c.TelegramID != 210408407 {
		t.Errorf("TelegramID = %d", c.TelegramID)
	}
	if c.TelegramUsername != "MashkovD" {
		t.Errorf("TelegramUsername = %q", c.TelegramUsername)
	}
}

// signRawPayload builds and signs a compact HS256 JWT from an arbitrary
// payload map, bypassing Issuer.Mint entirely. Used to fabricate a fixture
// shaped like a token minted before a given claim existed.
func signRawPayload(t *testing.T, payload map[string]any, secret []byte) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	bodyB64 := base64.RawURLEncoding.EncodeToString(body)
	sigInput := hdr + "." + bodyB64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return sigInput + "." + sig
}
