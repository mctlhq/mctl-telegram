// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cimd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const testAud = "https://api.example.com"

var (
	rsaKeyA = sync.OnceValue(func() *rsa.PrivateKey { return mustRSA(2048) })
	rsaKeyB = sync.OnceValue(func() *rsa.PrivateKey { return mustRSA(2048) })
)

func mustRSA(bits int) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	return k
}

// keyServer serves a private_key_jwt document at /client.json and a JWK Set
// at /jwks.json that a test can swap.
type keyServer struct {
	*fixture
	jwksURL  string
	mu       sync.Mutex
	jwks     string
	jwksHits atomic.Int32
	jwksCode int
}

func newKeyServer(t *testing.T, alg string, keys ...jose.JSONWebKey) *keyServer {
	t.Helper()
	ks := &keyServer{fixture: newFixture(t, nil), jwksCode: http.StatusOK}
	ks.jwksURL = "https://app.example.com/jwks.json"
	ks.setKeys(t, keys...)
	body := pkjwtDoc(ks.url, ks.jwksURL, alg)
	ks.h = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/jwks.json" {
			ks.jwksHits.Add(1)
			ks.mu.Lock()
			code, set := ks.jwksCode, ks.jwks
			ks.mu.Unlock()
			w.Header().Set("Content-Type", "application/jwk-set+json")
			w.WriteHeader(code)
			_, _ = fmt.Fprint(w, set)
			return
		}
		serve(body)(w, r)
	}
	return ks
}

func (ks *keyServer) setKeys(t *testing.T, keys ...jose.JSONWebKey) {
	t.Helper()
	b, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	ks.mu.Lock()
	ks.jwks = string(b)
	ks.mu.Unlock()
}

func pkjwtDoc(id, jwksURI, alg string) string {
	return fmt.Sprintf(`{"client_id":%q,"client_name":"Demo","redirect_uris":["https://app.example.com/cb"],`+
		`"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_signing_alg":%q,"jwks_uri":%q}`, id, alg, jwksURI)
}

func pub(k any, kid, alg string) jose.JSONWebKey {
	return jose.JSONWebKey{Key: k, KeyID: kid, Algorithm: alg, Use: "sig"}
}

func sign(t *testing.T, key any, alg jose.SignatureAlgorithm, kid string, c any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jwt.Signed(s).Claims(c).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func claimsAt(id string, now time.Time) jwt.Claims {
	return jwt.Claims{
		Issuer: id, Subject: id, Audience: jwt.Audience{testAud},
		Expiry: jwt.NewNumericDate(now.Add(2 * time.Minute)), IssuedAt: jwt.NewNumericDate(now),
		ID: fmt.Sprintf("jti-%d", now.UnixNano()),
	}
}

func resolveDoc(t *testing.T, ks *keyServer, r *Resolver) Document {
	t.Helper()
	d, err := r.Resolve(context.Background(), ks.url)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return d
}

func TestPrivateKeyJWTDocument(t *testing.T) {
	ks := newKeyServer(t, "RS256", pub(&rsaKeyA().PublicKey, "a", "RS256"))
	d := resolveDoc(t, ks, ks.resolver())
	if d.AuthMethod != AuthMethodPrivateKeyJWT || d.SigningAlg != "RS256" || d.JWKSURI != ks.jwksURL {
		t.Fatalf("%+v", d)
	}

	id := ks.url
	base := `"client_id":%q,"redirect_uris":["https://app.example.com/cb"],"token_endpoint_auth_method":"private_key_jwt"`
	cases := map[string]string{
		"no jwks_uri":          `,"token_endpoint_auth_signing_alg":"RS256"`,
		"inline jwks":          `,"token_endpoint_auth_signing_alg":"RS256","jwks_uri":"https://app.example.com/jwks.json","jwks":{"keys":[]}`,
		"jwks on other host":   `,"token_endpoint_auth_signing_alg":"RS256","jwks_uri":"https://keys.example.net/jwks.json"`,
		"jwks on subdomain":    `,"token_endpoint_auth_signing_alg":"RS256","jwks_uri":"https://keys.app.example.com/jwks.json"`,
		"jwks over http":       `,"token_endpoint_auth_signing_alg":"RS256","jwks_uri":"http://app.example.com/jwks.json"`,
		"jwks with query":      `,"token_endpoint_auth_signing_alg":"RS256","jwks_uri":"https://app.example.com/jwks.json?x=1"`,
		"jwks on ip":           `,"token_endpoint_auth_signing_alg":"RS256","jwks_uri":"https://127.0.0.1/jwks.json"`,
		"no alg":               `,"jwks_uri":"https://app.example.com/jwks.json"`,
		"alg none":             `,"token_endpoint_auth_signing_alg":"none","jwks_uri":"https://app.example.com/jwks.json"`,
		"alg HS256":            `,"token_endpoint_auth_signing_alg":"HS256","jwks_uri":"https://app.example.com/jwks.json"`,
		"alg PS256 (not ours)": `,"token_endpoint_auth_signing_alg":"PS256","jwks_uri":"https://app.example.com/jwks.json"`,
	}
	for name, extra := range cases {
		if _, err := parseDocument([]byte(fmt.Sprintf("{"+base+extra+"}", id)), id); !errors.Is(err, ErrInvalidDocument) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, m := range []string{"client_secret_basic", "client_secret_post", "tls_client_auth", ""} {
		body := fmt.Sprintf(`{"client_id":%q,"redirect_uris":["https://app.example.com/cb"],"token_endpoint_auth_method":%q}`, id, m)
		if _, err := parseDocument([]byte(body), id); !errors.Is(err, ErrInvalidDocument) {
			t.Errorf("method %q: %v", m, err)
		}
	}
	// A none client carries no key binding even if it names one.
	d, err := parseDocument([]byte(doc(id, `,"jwks_uri":"https://evil.example/j","token_endpoint_auth_signing_alg":"RS256"`)), id)
	if err != nil || d.AuthMethod != AuthMethodNone || d.JWKSURI != "" || d.SigningAlg != "" {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestVerifyAssertionOK(t *testing.T) {
	ks := newKeyServer(t, "RS256", pub(&rsaKeyA().PublicKey, "a", "RS256"))
	r := ks.resolver()
	d := resolveDoc(t, ks, r)
	c := claimsAt(ks.url, ks.clock)
	a, err := r.VerifyAssertion(context.Background(), d, sign(t, rsaKeyA(), jose.RS256, "a", c), []string{testAud, testAud + "/oauth/token"})
	if err != nil {
		t.Fatal(err)
	}
	if a.JTI != c.ID || a.RememberFor != 2*time.Minute+ClockSkew {
		t.Fatalf("%+v", a)
	}
	// The token endpoint URL is the other accepted audience, and a single
	// audience may come as a one-element array or a bare string.
	c.Audience = jwt.Audience{testAud + "/oauth/token"}
	if _, err := r.VerifyAssertion(context.Background(), d, sign(t, rsaKeyA(), jose.RS256, "a", c), []string{testAud, testAud + "/oauth/token"}); err != nil {
		t.Fatal(err)
	}
	// No kid: any usable key of the set is tried.
	if _, err := r.VerifyAssertion(context.Background(), d, sign(t, rsaKeyA(), jose.RS256, "", claimsAt(ks.url, ks.clock)), []string{testAud}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAssertionES256(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks := newKeyServer(t, "ES256", pub(&ec.PublicKey, "e", "ES256"))
	r := ks.resolver()
	d := resolveDoc(t, ks, r)
	if _, err := r.VerifyAssertion(context.Background(), d, sign(t, ec, jose.ES256, "e", claimsAt(ks.url, ks.clock)), []string{testAud}); err != nil {
		t.Fatal(err)
	}
	// The document's algorithm, not the header's, decides: an RS256 token is
	// refused for an ES256 client even with a key the set does not hold.
	if _, err := r.VerifyAssertion(context.Background(), d, sign(t, rsaKeyA(), jose.RS256, "e", claimsAt(ks.url, ks.clock)), []string{testAud}); !errors.Is(err, ErrAssertion) {
		t.Fatal(err)
	}
}

func TestVerifyAssertionRefusals(t *testing.T) {
	ks := newKeyServer(t, "RS256", pub(&rsaKeyA().PublicKey, "a", "RS256"))
	r := ks.resolver()
	d := resolveDoc(t, ks, r)
	now := ks.clock
	mod := func(f func(*jwt.Claims)) string {
		c := claimsAt(ks.url, now)
		f(&c)
		return sign(t, rsaKeyA(), jose.RS256, "a", c)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	der, _ := x509.MarshalPKIXPublicKey(&rsaKeyA().PublicKey)
	cases := map[string]string{
		"wrong aud":  mod(func(c *jwt.Claims) { c.Audience = jwt.Audience{"https://other.example.com"} }),
		"aud prefix": mod(func(c *jwt.Claims) { c.Audience = jwt.Audience{testAud + "/"} }),
		"two auds":   mod(func(c *jwt.Claims) { c.Audience = jwt.Audience{testAud, "https://other.example.com"} }),
		"no aud":     mod(func(c *jwt.Claims) { c.Audience = nil }),
		"expired":    mod(func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(now.Add(-ClockSkew - time.Second)) }),
		"exp too far": mod(func(c *jwt.Claims) {
			c.Expiry = jwt.NewNumericDate(now.Add(MaxAssertionLifetime + ClockSkew + time.Second))
		}),
		"no exp":            mod(func(c *jwt.Claims) { c.Expiry = nil }),
		"nbf in future":     mod(func(c *jwt.Claims) { c.NotBefore = jwt.NewNumericDate(now.Add(ClockSkew + time.Second)) }),
		"iat in future":     mod(func(c *jwt.Claims) { c.IssuedAt = jwt.NewNumericDate(now.Add(ClockSkew + time.Second)) }),
		"no jti":            mod(func(c *jwt.Claims) { c.ID = "" }),
		"long jti":          mod(func(c *jwt.Claims) { c.ID = strings.Repeat("j", maxJTIBytes+1) }),
		"iss other":         mod(func(c *jwt.Claims) { c.Issuer = "https://app.example.com/other.json" }),
		"sub other":         mod(func(c *jwt.Claims) { c.Subject = "someone" }),
		"other key":         sign(t, rsaKeyB(), jose.RS256, "a", claimsAt(ks.url, now)),
		"unknown kid":       sign(t, rsaKeyA(), jose.RS256, "nope", claimsAt(ks.url, now)),
		"HS256 with pubkey": sign(t, der, jose.HS256, "a", claimsAt(ks.url, now)),
		"alg none": b64([]byte(`{"alg":"none","kid":"a"}`)) + "." +
			b64(must(json.Marshal(claimsAt(ks.url, now)))) + ".",
		"garbage":   "not.a.jwt",
		"empty":     "",
		"oversized": strings.Repeat("a", maxAssertionBytes+1),
	}
	for name, as := range cases {
		if _, err := r.VerifyAssertion(context.Background(), d, as, []string{testAud, testAud + "/oauth/token"}); !errors.Is(err, ErrAssertion) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Inside the skew allowance an exp just past is still accepted.
	ok := mod(func(c *jwt.Claims) { c.Expiry = jwt.NewNumericDate(now.Add(-ClockSkew + time.Second)) })
	if _, err := r.VerifyAssertion(context.Background(), d, ok, []string{testAud}); err != nil {
		t.Fatal(err)
	}
	// A none client never verifies an assertion, however valid.
	none := d
	none.AuthMethod = AuthMethodNone
	if _, err := r.VerifyAssertion(context.Background(), none, ok, []string{testAud}); !errors.Is(err, ErrAssertion) {
		t.Fatal(err)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// A rotated-in key is picked up by one refetch, but no sooner than minTTL
// after the last fetch, so unknown kids cannot drive fetches.
func TestKeyRotationRefetchesOnceAfterFloor(t *testing.T) {
	ks := newKeyServer(t, "RS256", pub(&rsaKeyA().PublicKey, "a", "RS256"))
	r := ks.resolver()
	d := resolveDoc(t, ks, r)
	auds := []string{testAud}
	if _, err := r.VerifyAssertion(context.Background(), d, sign(t, rsaKeyA(), jose.RS256, "a", claimsAt(ks.url, ks.clock)), auds); err != nil {
		t.Fatal(err)
	}
	ks.setKeys(t, pub(&rsaKeyA().PublicKey, "a", "RS256"), pub(&rsaKeyB().PublicKey, "b", "RS256"))
	for i := range 5 {
		c := claimsAt(ks.url, ks.clock)
		c.ID = fmt.Sprintf("j%d", i)
		if _, err := r.VerifyAssertion(context.Background(), d, sign(t, rsaKeyB(), jose.RS256, "b", c), auds); !errors.Is(err, ErrAssertion) {
			t.Fatalf("before the floor: %v", err)
		}
	}
	if n := ks.jwksHits.Load(); n != 1 {
		t.Fatalf("jwks fetches = %d, want 1 before the floor", n)
	}
	ks.advance(minTTL)
	if _, err := r.VerifyAssertion(context.Background(), d, sign(t, rsaKeyB(), jose.RS256, "b", claimsAt(ks.url, ks.clock)), auds); err != nil {
		t.Fatalf("after the floor: %v", err)
	}
	if n := ks.jwksHits.Load(); n != 2 {
		t.Fatalf("jwks fetches = %d, want 2", n)
	}
	// A retired key stops verifying once the set is refetched without it.
	ks.setKeys(t, pub(&rsaKeyB().PublicKey, "b", "RS256"))
	ks.advance(defaultTTL)
	if _, err := r.VerifyAssertion(context.Background(), d, sign(t, rsaKeyA(), jose.RS256, "a", claimsAt(ks.url, ks.clock)), auds); !errors.Is(err, ErrAssertion) {
		t.Fatalf("retired key: %v", err)
	}
}

// A refetch that fails, here driven by an unknown kid during a key set
// outage, keeps the keys already in hand until the cached set expires. The
// unknown kid gets the fetch error, which the token endpoint answers as a
// retryable server error.
func TestFailedRefetchKeepsKnownKeys(t *testing.T) {
	ks := newKeyServer(t, "RS256", pub(&rsaKeyA().PublicKey, "a", "RS256"))
	r := ks.resolver()
	d := resolveDoc(t, ks, r)
	auds := []string{testAud}
	signA := func(id string) string {
		c := claimsAt(ks.url, ks.clock)
		c.ID = id
		return sign(t, rsaKeyA(), jose.RS256, "a", c)
	}
	if _, err := r.VerifyAssertion(context.Background(), d, signA("j0"), auds); err != nil {
		t.Fatal(err)
	}
	ks.mu.Lock()
	ks.jwksCode = http.StatusServiceUnavailable
	ks.mu.Unlock()
	ks.advance(minTTL)
	if _, err := r.VerifyAssertion(context.Background(), d, sign(t, rsaKeyB(), jose.RS256, "b", claimsAt(ks.url, ks.clock)), auds); !errors.Is(err, ErrFetch) {
		t.Fatalf("unknown kid during the outage: %v", err)
	}
	if _, err := r.VerifyAssertion(context.Background(), d, signA("j1"), auds); err != nil {
		t.Fatalf("known key after a failed refetch: %v", err)
	}
	// The failed attempt still floors the next refetch.
	// Until then the unknown kid keeps getting the fetch error, not
	// ErrAssertion: the cause is the same outage.
	before := ks.jwksHits.Load()
	if _, err := r.VerifyAssertion(context.Background(), d, sign(t, rsaKeyB(), jose.RS256, "b", claimsAt(ks.url, ks.clock)), auds); !errors.Is(err, ErrFetch) {
		t.Fatalf("unknown kid within the floor: %v", err)
	}
	if ks.jwksHits.Load() != before {
		t.Fatal("refetch was not floored after a failure")
	}
	// The held keys do not outlive the set's own cache lifetime.
	ks.advance(defaultTTL)
	if _, err := r.VerifyAssertion(context.Background(), d, signA("j2"), auds); err == nil {
		t.Fatal("held keys outlived the cached set")
	}
}

func TestKeySetFailuresFailClosed(t *testing.T) {
	weak := mustRSA(1024)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cases := map[string]func(*keyServer){
		"status": func(ks *keyServer) { ks.mu.Lock(); ks.jwksCode = http.StatusNotFound; ks.mu.Unlock() },
		"weak rsa": func(ks *keyServer) {
			ks.setKeys(t, pub(&weak.PublicKey, "a", "RS256"))
		},
		"private key only": func(ks *keyServer) {
			ks.setKeys(t, pub(rsaKeyA(), "a", "RS256"))
		},
		"enc use": func(ks *keyServer) {
			ks.setKeys(t, jose.JSONWebKey{Key: &rsaKeyA().PublicKey, KeyID: "a", Use: "enc"})
		},
		"other alg": func(ks *keyServer) {
			ks.setKeys(t, pub(&rsaKeyA().PublicKey, "a", "RS384"))
		},
		"wrong curve": func(ks *keyServer) {
			ks.setKeys(t, pub(&ec384.PublicKey, "a", ""))
		},
		"too many keys": func(ks *keyServer) {
			keys := make([]jose.JSONWebKey, maxJWKSKeys+1)
			for i := range keys {
				keys[i] = pub(&rsaKeyA().PublicKey, "a", "RS256")
			}
			ks.setKeys(t, keys...)
		},
		"not a set": func(ks *keyServer) { ks.mu.Lock(); ks.jwks = `[]`; ks.mu.Unlock() },
	}
	for name, mutate := range cases {
		ks := newKeyServer(t, "RS256", pub(&rsaKeyA().PublicKey, "a", "RS256"))
		r := ks.resolver()
		d := resolveDoc(t, ks, r)
		mutate(ks)
		// Sign with the key the set offers, so only the set's own rule refuses.
		key := rsaKeyA()
		if name == "weak rsa" {
			key = weak
		}
		_, err := r.VerifyAssertion(context.Background(), d, sign(t, key, jose.RS256, "a", claimsAt(ks.url, ks.clock)), []string{testAud})
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The set is fetched under the allowlist even when the document is already
// in hand: a Document naming a key set on another host is refused before
// any network access.
func TestKeySetHostMustBeAllowed(t *testing.T) {
	ks := newKeyServer(t, "RS256", pub(&rsaKeyA().PublicKey, "a", "RS256"))
	r := ks.resolver()
	d := resolveDoc(t, ks, r)
	d.JWKSURI = "https://keys.example.net/jwks.json"
	_, err := r.VerifyAssertion(context.Background(), d, sign(t, rsaKeyA(), jose.RS256, "a", claimsAt(ks.url, ks.clock)), []string{testAud})
	if !errors.Is(err, ErrNotAllowed) || ks.jwksHits.Load() != 0 {
		t.Fatalf("%v, %d fetches", err, ks.jwksHits.Load())
	}
}

func TestUnverifiedClientID(t *testing.T) {
	ks := newKeyServer(t, "RS256")
	if got := UnverifiedClientID(sign(t, rsaKeyB(), jose.RS256, "", claimsAt(ks.url, ks.clock))); got != ks.url {
		t.Fatalf("got %q", got)
	}
	for _, s := range []string{"", "x.y.z", strings.Repeat("a", maxAssertionBytes+1)} {
		if got := UnverifiedClientID(s); got != "" {
			t.Errorf("%q: %q", s, got)
		}
	}
}

// The set keeps only public signature keys of a usable type and size. Some
// of these rules are also enforced by the JOSE library at verification;
// this pins them at admission, so a refused key never enters the cache.
func TestFetchKeysAdmitsOnlyUsableKeys(t *testing.T) {
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	ks := newKeyServer(t, "RS256",
		pub(&rsaKeyA().PublicKey, "good-rsa", "RS256"),
		pub(&ec256.PublicKey, "good-ec", "ES256"),
		pub(&mustRSA(1024).PublicKey, "weak", "RS256"),
		pub(rsaKeyB(), "private", "RS256"),
		pub(&ec384.PublicKey, "p384", ""),
		jose.JSONWebKey{Key: &rsaKeyA().PublicKey, KeyID: "enc", Use: "enc"},
		pub(&rsaKeyA().PublicKey, "ops-verify", "RS256"),
		pub(&rsaKeyA().PublicKey, "ops-encrypt", "RS256"),
	)
	// go-jose does not marshal key_ops, so it is added to the set by hand.
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal([]byte(ks.jwks), &set); err != nil {
		t.Fatal(err)
	}
	for _, k := range set.Keys {
		switch k["kid"] {
		case "ops-verify":
			k["key_ops"] = []string{"verify"}
		case "ops-encrypt":
			k["key_ops"] = []string{"encrypt", "wrapKey"}
		}
	}
	b, _ := json.Marshal(set)
	ks.jwks = string(b)
	keys, _, err := ks.resolver().fetchKeys(context.Background(), ks.jwksURL)
	if err != nil {
		t.Fatal(err)
	}
	var kids []string
	for i := range keys {
		kids = append(kids, keys[i].KeyID)
	}
	if strings.Join(kids, ",") != "good-rsa,good-ec,ops-verify" {
		t.Fatalf("admitted %v", kids)
	}
}

// A key set that was fetched but holds nothing usable is the client's
// configuration (ErrInvalidKeySet); one that could not be fetched is not
// (ErrFetch). The token endpoint answers them differently.
func TestKeySetErrorsAreClassified(t *testing.T) {
	ks := newKeyServer(t, "RS256", pub(&mustRSA(1024).PublicKey, "weak", "RS256"))
	r := ks.resolver()
	if _, _, err := r.fetchKeys(context.Background(), ks.jwksURL); !errors.Is(err, ErrInvalidKeySet) || errors.Is(err, ErrFetch) {
		t.Fatalf("no usable key: %v", err)
	}
	ks.mu.Lock()
	ks.jwks = `{"keys":"nope"}`
	ks.mu.Unlock()
	if _, _, err := r.fetchKeys(context.Background(), ks.jwksURL); !errors.Is(err, ErrInvalidKeySet) || errors.Is(err, ErrFetch) {
		t.Fatalf("not a set: %v", err)
	}
	ks.mu.Lock()
	ks.jwksCode = http.StatusServiceUnavailable
	ks.mu.Unlock()
	if _, _, err := r.fetchKeys(context.Background(), ks.jwksURL); !errors.Is(err, ErrFetch) || errors.Is(err, ErrInvalidKeySet) {
		t.Fatalf("503: %v", err)
	}
}
