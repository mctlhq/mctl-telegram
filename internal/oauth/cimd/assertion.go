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
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/mctlhq/mctl-telegram/internal/netsafe"
)

// ErrAssertion is a client assertion (RFC 7523 section 2.2) that does not
// authenticate the client: malformed, wrongly signed, for another audience,
// expired, or for a client that does not use private_key_jwt.
var ErrAssertion = errors.New("cimd: invalid client assertion")

// ErrInvalidKeySet is a JWK Set that was fetched but is not usable: not a
// set, too large, or with no admissible signature key. Unlike ErrFetch it is
// the client's published configuration, not a failure to observe it.
var ErrInvalidKeySet = errors.New("cimd: invalid key set")

const (
	// MaxAssertionLifetime bounds how far ahead of now an assertion's exp may
	// lie. It also bounds how long a jti has to be remembered.
	MaxAssertionLifetime = 5 * time.Minute
	// ClockSkew is the tolerance for exp, nbf and iat against this server's
	// clock.
	ClockSkew = time.Minute

	maxAssertionBytes = 8 << 10
	maxJTIBytes       = 256
	maxJWKSKeys       = 20
	minRSABits        = 2048
	// keysTTLOnError is how long a failed key set fetch is remembered. It is
	// shorter than negativeTTL, like fetchErrTTL: a key outage refuses every
	// token request of the client, not only new sign-ins.
	keysTTLOnError = minTTL
)

// Assertion is what a verified client assertion contributes to the replay
// check.
type Assertion struct {
	JTI string
	// RememberFor is how long the jti must stay recorded: until exp plus the
	// skew allowance, after which the assertion is refused as expired anyway.
	RememberFor time.Duration
}

// UnverifiedClientID returns the iss claim of assertion without verifying
// anything. It only picks which document to verify against when a token
// request omits client_id (RFC 7521 section 4.2); VerifyAssertion still
// requires iss and sub to equal that document's client_id.
func UnverifiedClientID(assertion string) string {
	if len(assertion) > maxAssertionBytes {
		return ""
	}
	tok, err := jwt.ParseSigned(assertion, joseAlgs())
	if err != nil {
		return ""
	}
	var c jwt.Claims
	if tok.UnsafeClaimsWithoutVerification(&c) != nil {
		return ""
	}
	return c.Issuer
}

// VerifyAssertion checks a private_key_jwt client assertion for doc: the
// signature under doc's own algorithm with a key from doc's key set,
// iss == sub == client_id, exactly one audience from audiences, an exp no
// more than MaxAssertionLifetime ahead, sane nbf and iat, and a jti. It does
// not check the jti for replay; the caller records it for RememberFor.
func (r *Resolver) VerifyAssertion(ctx context.Context, doc Document, assertion string, audiences []string) (Assertion, error) {
	fail := func(format string, a ...any) (Assertion, error) {
		return Assertion{}, fmt.Errorf("%w: %s", ErrAssertion, fmt.Sprintf(format, a...))
	}
	if doc.AuthMethod != AuthMethodPrivateKeyJWT || doc.JWKSURI == "" || !slices.Contains(signingAlgs, doc.SigningAlg) {
		return fail("client does not use private_key_jwt")
	}
	if assertion == "" || len(assertion) > maxAssertionBytes {
		return fail("missing or oversized")
	}
	// Only the document's algorithm is accepted, whatever the header says:
	// this is what refuses alg=none and an HS256 token keyed with the public
	// key.
	tok, err := jwt.ParseSigned(assertion, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(doc.SigningAlg)})
	if err != nil {
		return fail("not a compact JWS signed with %s", doc.SigningAlg)
	}
	if len(tok.Headers) != 1 {
		return fail("exactly one signature required")
	}
	keys, err := r.keysFor(ctx, doc, tok.Headers[0].KeyID)
	if err != nil {
		return Assertion{}, err
	}
	var c jwt.Claims
	verified := false
	for i := range keys {
		if tok.Claims(keys[i].Key, &c) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return fail("signature does not verify with the client's keys")
	}
	now := r.now()
	switch {
	case c.Issuer != doc.ClientID || c.Subject != doc.ClientID:
		return fail("iss and sub must equal the client_id")
	case len(c.Audience) != 1 || !slices.Contains(audiences, c.Audience[0]):
		return fail("aud must be exactly one of %s", strings.Join(audiences, ", "))
	case c.Expiry == nil:
		return fail("exp is required")
	case now.After(c.Expiry.Time().Add(ClockSkew)):
		return fail("expired")
	case c.Expiry.Time().After(now.Add(MaxAssertionLifetime + ClockSkew)):
		return fail("exp is more than %s ahead", MaxAssertionLifetime)
	case c.NotBefore != nil && c.NotBefore.Time().After(now.Add(ClockSkew)):
		return fail("not yet valid")
	case c.IssuedAt != nil && c.IssuedAt.Time().After(now.Add(ClockSkew)):
		return fail("issued in the future")
	case c.ID == "" || len(c.ID) > maxJTIBytes:
		return fail("jti is required and at most %d bytes", maxJTIBytes)
	}
	return Assertion{JTI: c.ID, RememberFor: c.Expiry.Time().Add(ClockSkew).Sub(now)}, nil
}

func joseAlgs() []jose.SignatureAlgorithm {
	out := make([]jose.SignatureAlgorithm, 0, len(signingAlgs))
	for _, a := range signingAlgs {
		out = append(out, jose.SignatureAlgorithm(a))
	}
	return out
}

// keysFor returns the keys of doc's set that may verify an assertion with
// key id kid (any usable key when kid is empty). On a cached set without
// such a key it refetches once, at most every minTTL per set and within the
// host's fetch budget, so a rotated-in key is picked up without letting
// unknown kids drive fetches. A refetch that fails keeps the set already in
// hand until it expires as cached, so a key the client still signs with is
// not dropped for an outage at its key set.
func (r *Resolver) keysFor(ctx context.Context, doc Document, kid string) ([]jose.JSONWebKey, error) {
	key := "jwks\x00" + doc.JWKSURI
	e, hit := r.cachedEntry(key)
	if hit && e.err != nil {
		return nil, e.err
	}
	if hit {
		if ks := pickKeys(e.keys, doc.SigningAlg, kid); len(ks) > 0 {
			return ks, nil
		}
	}
	v, err, _ := r.sf.Do(key, func() (any, error) {
		e, hit := r.cachedEntry(key)
		if hit && e.err != nil {
			return nil, e.err
		}
		if hit && r.now().Sub(e.fetched) < minTTL {
			return e.keys, e.refetchErr
		}
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.timeout)
		defer cancel()
		keys, ttl, err := r.fetchKeys(fctx, doc.JWKSURI)
		if errors.Is(err, ErrRateLimited) || (err != nil && ctx.Err() != nil) {
			return nil, err
		}
		if err != nil && hit {
			// Only the fetch time moves, so the next refetch is still floored.
			r.storeEntry(&cacheEntry{key: key, keys: e.keys, refetchErr: err, fetched: r.now(), expires: e.expires})
			return e.keys, err
		}
		if err != nil {
			ttl = keysTTLOnError
		}
		r.storeEntry(&cacheEntry{key: key, keys: keys, err: err, fetched: r.now(), expires: r.now().Add(ttl)})
		return keys, err
	})
	held, _ := v.([]jose.JSONWebKey)
	if ks := pickKeys(held, doc.SigningAlg, kid); len(ks) > 0 {
		return ks, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: no usable key with kid %q", ErrAssertion, kid)
}

// pickKeys returns the keys usable for alg, narrowed to kid when given.
func pickKeys(keys []jose.JSONWebKey, alg, kid string) []jose.JSONWebKey {
	var out []jose.JSONWebKey
	for i := range keys {
		k := &keys[i]
		if kid != "" && k.KeyID != kid {
			continue
		}
		if k.Algorithm != "" && k.Algorithm != alg {
			continue
		}
		switch k.Key.(type) {
		case *rsa.PublicKey:
			if alg == "RS256" {
				out = append(out, *k)
			}
		case *ecdsa.PublicKey:
			// fetchKeys admits P-256 keys only.
			if alg == "ES256" {
				out = append(out, *k)
			}
		}
	}
	return out
}

// fetchKeys fetches a JWK Set under the same allowlist, address rules and
// limits as a document. Entries that do not parse, are not public signature
// keys, or are too weak are skipped; a set with no usable key is an error.
func (r *Resolver) fetchKeys(ctx context.Context, uri string) ([]jose.JSONWebKey, time.Duration, error) {
	u, ok := parseCIMDURL(uri)
	if !ok {
		return nil, 0, fmt.Errorf("%w: jwks_uri is not an https URL", ErrFetch)
	}
	if !r.hostAllowed(u.Hostname()) {
		return nil, 0, ErrNotAllowed
	}
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	default:
		return nil, 0, ErrRateLimited
	}
	if !r.allowHost(strings.ToLower(u.Hostname())) {
		return nil, 0, ErrRateLimited
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("%w: jwks status %d", ErrFetch, resp.StatusCode)
	}
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (mt != "application/json" && mt != "application/jwk-set+json") {
		return nil, 0, fmt.Errorf("%w: jwks content type %q", ErrFetch, resp.Header.Get("Content-Type"))
	}
	body, err := netsafe.ReadLimited(resp, maxBodyBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, 0, fmt.Errorf("%w: jwks is not a JWK Set", ErrInvalidKeySet)
	}
	if len(set.Keys) > maxJWKSKeys {
		return nil, 0, fmt.Errorf("%w: jwks has more than %d keys", ErrInvalidKeySet, maxJWKSKeys)
	}
	var keys []jose.JSONWebKey
	for _, raw := range set.Keys {
		var k jose.JSONWebKey
		if k.UnmarshalJSON(raw) != nil || !k.Valid() || (k.Use != "" && k.Use != "sig") {
			continue
		}
		// A key restricted by key_ops to other operations is not a
		// verification key. "sign" is admitted too: a set may list the
		// private key's operations next to the public key. go-jose does not
		// expose key_ops, so it is read from the entry itself.
		var ops struct {
			KeyOps []string `json:"key_ops"`
		}
		if json.Unmarshal(raw, &ops) != nil || (len(ops.KeyOps) > 0 && !slices.Contains(ops.KeyOps, "verify") && !slices.Contains(ops.KeyOps, "sign")) {
			continue
		}
		// Only public key types are admitted, so a private key published by
		// mistake is skipped by the default arm.
		switch pub := k.Key.(type) {
		case *rsa.PublicKey:
			if pub.N.BitLen() < minRSABits {
				continue
			}
		case *ecdsa.PublicKey:
			if pub.Curve != elliptic.P256() {
				continue
			}
		default:
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, 0, fmt.Errorf("%w: jwks has no usable signature key", ErrInvalidKeySet)
	}
	return slices.Clip(keys), cacheTTL(resp.Header.Get("Cache-Control")), nil
}
