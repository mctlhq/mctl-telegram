package telegramoidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// TestExchange_VerifiesAgainstSecp256k1JWKS is the end-to-end regression test
// for PR #57. A fake OpenID Provider serves a JWKS that — like Telegram's —
// mixes an RS256 key with a secp256k1 key go-jose cannot decode. Without the
// filtering transport reaching the verifier's RemoteKeySet, go-jose rejects the
// whole key set and Exchange fails. The test fails if the filtering transport
// is removed from the OIDC client context entirely.
func TestExchange_VerifiesAgainstSecp256k1JWKS(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pubJWK := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "rsa-1", Algorithm: "RS256", Use: "sig"}
	pubJSON, err := pubJWK.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal JWK: %v", err)
	}
	// keys[1] is a structurally valid JWK on the secp256k1 curve — go-jose
	// rejects this curve, which is exactly the production failure mode.
	jwks := `{"keys":[` + string(pubJSON) +
		`,{"kty":"EC","crv":"secp256k1","kid":"es256k","alg":"ES256K","use":"sig",` +
		`"x":"vsk5i5YJu8H_VPL7DWTgVGXBPrqgkyNmYvfgOrVut38",` +
		`"y":"Mrg56tBhVeorHPXK1LbTX2jP7rEqOHIatM96HFzVMIU"}]}`

	const clientID = "8568443430"
	const nonce = "test-nonce"

	mux := http.NewServeMux()
	var srv *httptest.Server
	var idToken string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/auth",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(jwks))
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "x", "token_type": "Bearer", "id_token": idToken,
		})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: priv, KeyID: "rsa-1"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	now := time.Now()
	claims, err := json.Marshal(map[string]any{
		"iss":   srv.URL,
		"aud":   clientID,
		"sub":   "1234567890123456789",
		"id":    "210408407",
		"nonce": nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("sign id_token: %v", err)
	}
	if idToken, err = jws.CompactSerialize(); err != nil {
		t.Fatalf("serialize id_token: %v", err)
	}

	ctx := context.Background()
	client, err := New(ctx, Config{
		IssuerURL:    srv.URL,
		ClientID:     clientID,
		ClientSecret: "secret",
		RedirectURL:  "https://tg.mctl.ai/oauth/telegram/callback",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := client.Exchange(ctx, "auth-code", "code-verifier", nonce)
	if err != nil {
		t.Fatalf("Exchange failed — JWKS filter likely not wired into the verifier: %v", err)
	}
	if id.TelegramID != 210408407 {
		t.Errorf("TelegramID = %d, want 210408407", id.TelegramID)
	}
}
