package oauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/oauth/cimd"
)

// A synthetic private_key_jwt platform, shaped like ChatGPT's document: the
// key set lives on the client_id's own host.
const (
	pkjwtClientID = "https://chat.example.test/oauth/client.json"
	pkjwtJWKSURI  = "https://chat.example.test/oauth/jwks.json"
	pkjwtCallback = "https://chat.example.test/connector/oauth/callback"
	pkjwtKeyID    = "k1"
)

type pkjwtPlatform struct {
	t    *testing.T
	key  *ecdsa.PrivateKey
	docs map[string][]byte
}

// newPKJWTPlatform serves the document and key set from memory. The real
// resolver runs on top, so allowlist, parsing, caching and key selection are
// all the production code paths; only the network is replaced.
func newPKJWTPlatform(t *testing.T) *pkjwtPlatform {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(map[string]any{
		"client_id":                       pkjwtClientID,
		"client_name":                     "Example Chat",
		"redirect_uris":                   []string{pkjwtCallback},
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": "ES256",
		"jwks_uri":                        pkjwtJWKSURI,
	})
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &key.PublicKey, KeyID: pkjwtKeyID, Algorithm: "ES256", Use: "sig",
	}}})
	return &pkjwtPlatform{t: t, key: key, docs: map[string][]byte{pkjwtClientID: doc, pkjwtJWKSURI: jwks}}
}

func (p *pkjwtPlatform) resolver() *cimd.Resolver {
	return cimd.NewResolver(cimd.Options{
		AllowedHosts: []string{"chat.example.test"},
		HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body, ok := p.docs[r.URL.String()]
			if !ok {
				return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}}, nil
			}
			h := http.Header{}
			h.Set("Content-Type", "application/json")
			h.Set("Cache-Control", "max-age=300")
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: h}, nil
		})},
	})
}

type assertionOpts struct {
	aud string
	jti string
	iss string
	exp time.Duration
}

// assertion signs a client assertion. Zero fields take valid defaults.
func (p *pkjwtPlatform) assertion(o assertionOpts) string {
	p.t.Helper()
	if o.aud == "" {
		o.aud = testIssuer + "/oauth/token"
	}
	if o.jti == "" {
		o.jti = randomToken(12)
	}
	if o.iss == "" {
		o.iss = pkjwtClientID
	}
	if o.exp == 0 {
		o.exp = 2 * time.Minute
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: p.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", pkjwtKeyID))
	if err != nil {
		p.t.Fatal(err)
	}
	now := time.Now()
	tok, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer: o.iss, Subject: o.iss, Audience: jwt.Audience{o.aud}, ID: o.jti,
		IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(o.exp)),
	}).Serialize()
	if err != nil {
		p.t.Fatal(err)
	}
	return tok
}

func withAssertion(form url.Values, assertion string) url.Values {
	out := url.Values{}
	for k, v := range form {
		out[k] = append([]string(nil), v...)
	}
	out.Set("client_assertion_type", ClientAssertionTypeJWT)
	out.Set("client_assertion", assertion)
	return out
}

// TestCIMD_PrivateKeyJWT_FullFlow drives a private_key_jwt client through
// authorize, code exchange and refresh with a fresh assertion each time, and
// pins every way its client authentication is refused.
func TestCIMD_PrivateKeyJWT_FullFlow(t *testing.T) {
	p := newPKJWTPlatform(t)
	srv := newTestServer(t, withCIMD(p.resolver()))
	mux := newMockRouter()
	srv.Register(mux)

	verifier, challenge := pkceVerifierAndChallenge()
	cs := obtainAuthorizationCodeFor(t, srv, mux, challenge, pkjwtClientID, pkjwtCallback)
	codeForm := url.Values{
		"grant_type": {"authorization_code"}, "code": {cs.code}, "client_id": {pkjwtClientID},
		"redirect_uri": {pkjwtCallback}, "code_verifier": {verifier},
	}

	expectInvalidClient := func(name string, form url.Values) {
		t.Helper()
		rec := doTokenRequest(t, mux, form)
		if rec.Code != http.StatusBadRequest || tokenErrorCode(t, rec.Body.String()) != "invalid_client" {
			t.Fatalf("%s: %d %s, want 400 invalid_client", name, rec.Code, rec.Body.String())
		}
	}
	// Each refusal happens before the code is consumed, so the same code is
	// redeemed successfully at the end.
	expectInvalidClient("no assertion", codeForm)
	expectInvalidClient("wrong assertion type", func() url.Values {
		f := withAssertion(codeForm, p.assertion(assertionOpts{}))
		f.Set("client_assertion_type", "urn:example:other")
		return f
	}())
	expectInvalidClient("wrong audience", withAssertion(codeForm, p.assertion(assertionOpts{aud: "https://other.example.test"})))
	expectInvalidClient("expired", withAssertion(codeForm, p.assertion(assertionOpts{exp: -5 * time.Minute})))
	expectInvalidClient("too far ahead", withAssertion(codeForm, p.assertion(assertionOpts{exp: time.Hour})))
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forged := &pkjwtPlatform{t: t, key: other}
	expectInvalidClient("signed with another key", withAssertion(codeForm, forged.assertion(assertionOpts{})))

	used := p.assertion(assertionOpts{})
	rec := doTokenRequest(t, mux, withAssertion(codeForm, used))
	if rec.Code != http.StatusOK {
		t.Fatalf("code exchange with a valid assertion: %d %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	rt, _ := resp["refresh_token"].(string)
	if rt == "" {
		t.Fatal("no refresh_token")
	}

	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {pkjwtClientID}}
	// The assertion already spent on the code exchange is a replay.
	expectInvalidClient("replayed assertion", withAssertion(refreshForm, used))
	expectInvalidClient("refresh without assertion", refreshForm)

	// RFC 7521 section 4.2: client_id may be omitted when the assertion
	// names the client.
	noID := withAssertion(refreshForm, p.assertion(assertionOpts{}))
	noID.Del("client_id")
	if rec = doTokenRequest(t, mux, noID); rec.Code != http.StatusOK {
		t.Fatalf("refresh with client_id taken from the assertion: %d %s", rec.Code, rec.Body.String())
	}
}

// TestCIMD_NoneClientMustNotSendAssertion pins the other direction: a
// document that declares none is a public client, and an assertion on its
// token request is refused rather than ignored.
func TestCIMD_NoneClientMustNotSendAssertion(t *testing.T) {
	stub := &stubCIMD{}
	stub.set(platformDoc(), nil)
	srv := newTestServer(t, withCIMD(stub))
	mux := newMockRouter()
	srv.Register(mux)
	verifier, challenge := pkceVerifierAndChallenge()
	cs := obtainAuthorizationCodeFor(t, srv, mux, challenge, cimdClientID, cimdCallback)
	form := withAssertion(url.Values{
		"grant_type": {"authorization_code"}, "code": {cs.code}, "client_id": {cimdClientID},
		"redirect_uri": {cimdCallback}, "code_verifier": {verifier},
	}, "header.payload.signature")
	rec := doTokenRequest(t, mux, form)
	if rec.Code != http.StatusBadRequest || tokenErrorCode(t, rec.Body.String()) != "invalid_client" {
		t.Fatalf("none client with an assertion: %d %s, want 400 invalid_client", rec.Code, rec.Body.String())
	}
}

// TestCIMD_Discovery checks that CIMD and private_key_jwt appear in the
// authorization server metadata only while advertising is on.
func TestCIMD_Discovery(t *testing.T) {
	meta := func(opts ...func(*Config)) map[string]any {
		t.Helper()
		srv := newTestServer(t, opts...)
		rec := httptest.NewRecorder()
		srv.handleAuthorizationServerMetadata(rec, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	stub := &stubCIMD{}
	for name, opts := range map[string][]func(*Config){
		"off":                {},
		"accept only":        {withCIMD(stub)},
		"advertise, no CIMD": {func(c *Config) { c.CIMDAdvertise = true }},
	} {
		m := meta(opts...)
		if _, ok := m["client_id_metadata_document_supported"]; ok {
			t.Errorf("%s: CIMD advertised", name)
		}
		if got, _ := json.Marshal(m["token_endpoint_auth_methods_supported"]); string(got) != `["none"]` {
			t.Errorf("%s: token_endpoint_auth_methods_supported = %s, want [\"none\"]", name, got)
		}
		if _, ok := m["registration_endpoint"]; !ok {
			t.Errorf("%s: registration_endpoint missing", name)
		}
	}
	m := meta(withCIMD(stub), func(c *Config) { c.CIMDAdvertise = true })
	if m["client_id_metadata_document_supported"] != true {
		t.Fatalf("advertise: client_id_metadata_document_supported = %v", m["client_id_metadata_document_supported"])
	}
	if got, _ := json.Marshal(m["token_endpoint_auth_methods_supported"]); string(got) != `["none","private_key_jwt"]` {
		t.Fatalf("advertise: token_endpoint_auth_methods_supported = %s", got)
	}
	if got, _ := json.Marshal(m["token_endpoint_auth_signing_alg_values_supported"]); string(got) != `["RS256","ES256"]` {
		t.Fatalf("advertise: signing algs = %s", got)
	}
	if _, ok := m["registration_endpoint"]; !ok {
		t.Fatal("advertise: DCR must stay available next to CIMD")
	}
}

// TestCIMD_JTIReplayAcrossReplicas_Postgres records a jti through one server
// and replays it through a second one on the same database: the replay
// check must hold across replicas.
func TestCIMD_JTIReplayAcrossReplicas_Postgres(t *testing.T) {
	store := newPostgresOAuthStore(t)
	mk := func() *Server {
		srv, err := New(context.Background(), Config{
			Issuer: testIssuer, JWTSecret: testJWTSecret, TelegramOIDC: newFakeAuthenticator(),
			AccessTokenTTL: time.Hour, CodeTTL: time.Minute, UseDBForOAuth: true,
		}, store)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if !srv.useDB {
			t.Fatal("server is not using the database for OAuth state")
		}
		return srv
	}
	a, b := mk(), mk()
	as := cimd.Assertion{JTI: "replica-jti", RememberFor: time.Minute}
	if err := a.consumeJTI(context.Background(), pkjwtClientID, as); err != nil {
		t.Fatalf("first use on replica A: %v", err)
	}
	if err := b.consumeJTI(context.Background(), pkjwtClientID, as); err == nil {
		t.Fatal("replay on replica B was accepted")
	}
}

// TestCIMD_JTIStoreErrorIsRetryableNeverAPass pins the fail-closed half of the
// replay store: a database that cannot record the jti refuses the request with
// a retryable error and never treats the assertion as fresh.
func TestCIMD_JTIStoreErrorIsRetryableNeverAPass(t *testing.T) {
	conn, err := sql.Open("sqlite", "file::memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	_ = conn.Close() // every statement now fails with "database is closed"
	srv, err := New(context.Background(), Config{
		Issuer: testIssuer, JWTSecret: testJWTSecret, TelegramOIDC: newFakeAuthenticator(),
		AccessTokenTTL: time.Hour, CodeTTL: time.Minute, UseDBForOAuth: true,
	}, &db.Store{DB: conn})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !srv.useDB {
		t.Fatal("server is not using the database for OAuth state")
	}
	err = srv.consumeJTI(context.Background(), pkjwtClientID, cimd.Assertion{JTI: "store-down", RememberFor: time.Minute})
	if !errors.Is(err, errJTIStore) {
		t.Fatalf("consumeJTI with a failing store = %v, want errJTIStore", err)
	}
	rec := httptest.NewRecorder()
	writeCIMDTokenError(rec, cimdFailure("test", pkjwtClientID, err))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("store error answered %d (Retry-After %q), want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
}

// TestCIMD_InMemoryJTIMapIsBounded checks that a full in-memory jti map
// refuses a new jti with a retryable error instead of growing or forgetting.
func TestCIMD_InMemoryJTIMapIsBounded(t *testing.T) {
	srv := newTestServer(t)
	now := srv.clock()
	srv.mu.Lock()
	for i := 0; i < maxInMemoryJTIs; i++ {
		srv.jtis[fmt.Sprintf("k%d", i)] = now.Add(time.Minute)
	}
	srv.mu.Unlock()
	err := srv.consumeJTI(context.Background(), pkjwtClientID, cimd.Assertion{JTI: "one-more", RememberFor: time.Minute})
	if !errors.Is(err, errJTIStore) {
		t.Fatalf("consumeJTI on a full map = %v, want errJTIStore", err)
	}
	if len(srv.jtis) != maxInMemoryJTIs {
		t.Fatalf("map grew to %d past the cap %d", len(srv.jtis), maxInMemoryJTIs)
	}
}
