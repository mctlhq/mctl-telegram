package authn_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/mctlhq/mctl-telegram/internal/glovo/authn"
	"github.com/mctlhq/mctl-telegram/internal/glovo/contract"
	"github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi/fakeapi"
)

const (
	issuer   = "https://api.mctl.test"
	resource = "https://glovo.mctl.ai/mcp"
	metaURL  = "https://glovo.mctl.ai/.well-known/oauth-protected-resource/mcp"
)

type rig struct {
	fake *fakeapi.Fake
	jwks *httptest.Server
	v    *authn.Verifier
	h    http.Handler
	fail []string
	hits int
}

func newRig(t *testing.T) *rig {
	t.Helper()
	c, err := contract.Load()
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{fake: fakeapi.New(fakeapi.Options{Issuer: issuer, Resource: resource, Credential: "c"})}
	r.jwks = httptest.NewServer(r.fake.Handler())
	t.Cleanup(r.jwks.Close)
	r.v = authn.New(authn.Config{Issuer: issuer, Resource: resource, JWKSURL: r.jwks.URL + "/.well-known/jwks.json", GlovoScopes: c.Scopes})
	mw := authn.Middleware(r.v, metaURL, c.Scopes, func(reason string) { r.fail = append(r.fail, reason) })
	r.h = mw(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.hits++
		p := authn.FromContext(req.Context())
		_, _ = w.Write([]byte(p.Subject + "|" + p.Tenant + "|" + strings.Join(p.Scopes, ",")))
	}))
	return r
}

func (r *rig) do(auth, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp"+query, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

func hs256(t *testing.T) string {
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")},
		(&jose.SignerOptions{}).WithHeader("kid", "fake-kid-1"))
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := jwt.Signed(sg).Claims(jwt.Claims{Issuer: issuer, Subject: "x", Audience: jwt.Audience{resource}, Expiry: jwt.NewNumericDate(time.Now().Add(time.Hour))}).Serialize()
	return tok
}

func algNone() string {
	e := base64.RawURLEncoding.EncodeToString
	return e([]byte(`{"alg":"none","kid":"fake-kid-1"}`)) + "." + e([]byte(`{"iss":"`+issuer+`","sub":"x","aud":"`+resource+`","exp":4102444800}`)) + "."
}

func TestValidToken(t *testing.T) {
	r := newRig(t)
	tok := r.fake.Mint(fakeapi.MintOpts{Sub: fakeapi.Alice, Tenant: fakeapi.TeamAlpha, Scope: "glovo:read other:scope"})
	w := r.do("Bearer "+tok, "")
	if w.Code != 200 || w.Body.String() != "usr_alice|team-alpha|glovo:read" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if !r.v.JWKSLoaded() {
		t.Fatal("jwks not marked loaded")
	}
}

func TestRejections(t *testing.T) {
	r := newRig(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	mint := func(o fakeapi.MintOpts) string {
		o.Sub = fakeapi.Alice
		return r.fake.Mint(o)
	}
	now := time.Now()
	cases := []struct {
		name, auth, reason string
		status             int
	}{
		{"missing", "", authn.ReasonMissing, 401},
		{"wrong scheme", "Basic abc", authn.ReasonUnsupported, 401},
		{"malformed", "Bearer not-a-jwt", authn.ReasonMalformed, 401},
		{"alg none", "Bearer " + algNone(), authn.ReasonMalformed, 401},
		{"hs256", "Bearer " + hs256(t), authn.ReasonMalformed, 401},
		{"unknown kid", "Bearer " + mint(fakeapi.MintOpts{KID: "nope"}), authn.ReasonUnknownKey, 401},
		{"wrong signature", "Bearer " + mint(fakeapi.MintOpts{Key: other}), authn.ReasonSignature, 401},
		{"wrong iss", "Bearer " + mint(fakeapi.MintOpts{Iss: "https://evil.test"}), authn.ReasonIssuer, 401},
		{"aud origin only", "Bearer " + mint(fakeapi.MintOpts{Aud: []string{"https://glovo.mctl.ai"}}), authn.ReasonAudience, 401},
		{"aud trailing slash", "Bearer " + mint(fakeapi.MintOpts{Aud: []string{resource + "/"}}), authn.ReasonAudience, 401},
		{"aud tg", "Bearer " + mint(fakeapi.MintOpts{Aud: []string{"https://tg.mctl.ai/mcp"}}), authn.ReasonAudience, 401},
		{"aud array without resource", "Bearer " + mint(fakeapi.MintOpts{Aud: []string{"a", "b"}}), authn.ReasonAudience, 401},
		{"expired", "Bearer " + mint(fakeapi.MintOpts{Exp: now.Add(-time.Second)}), authn.ReasonExpired, 401},
		{"future nbf", "Bearer " + mint(fakeapi.MintOpts{NBF: now.Add(5 * time.Minute)}), authn.ReasonNotYetValid, 401},
		{"empty sub", "Bearer " + r.fake.Mint(fakeapi.MintOpts{Sub: " "}), authn.ReasonSubject, 401},
		{"no glovo scope", "Bearer " + mint(fakeapi.MintOpts{Scope: "openid email"}), authn.ReasonNoScope, 403},
	}
	for _, c := range cases {
		before := len(r.fail)
		w := r.do(c.auth, "")
		if w.Code != c.status {
			t.Errorf("%s: status %d want %d", c.name, w.Code, c.status)
		}
		if len(r.fail) != before+1 || r.fail[before] != c.reason {
			t.Errorf("%s: reason %v want %s", c.name, r.fail[before:], c.reason)
		}
		wa := w.Header().Get("WWW-Authenticate")
		if !strings.Contains(wa, `resource_metadata="`+metaURL+`"`) {
			t.Errorf("%s: WWW-Authenticate %q", c.name, wa)
		}
		if c.status == 401 && c.reason != authn.ReasonMissing && c.reason != authn.ReasonUnsupported && !strings.Contains(wa, `error="invalid_token"`) {
			t.Errorf("%s: want invalid_token in %q", c.name, wa)
		}
		if c.status == 403 && !strings.Contains(wa, `error="insufficient_scope"`) {
			t.Errorf("%s: want insufficient_scope in %q", c.name, wa)
		}
	}
	if r.hits != 0 {
		t.Fatalf("handler reached %d times by refused tokens", r.hits)
	}
}

func TestQueryAndFormTokensRefused(t *testing.T) {
	r := newRig(t)
	tok := r.fake.Mint(fakeapi.MintOpts{Sub: fakeapi.Alice})
	if w := r.do("Bearer "+tok, "?access_token="+tok); w.Code != 400 {
		t.Fatalf("query token: %d", w.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("access_token="+tok))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	if w.Code != 400 || r.hits != 0 {
		t.Fatalf("form token: %d hits=%d", w.Code, r.hits)
	}
}

func TestMetadata(t *testing.T) {
	c, _ := contract.Load()
	h := authn.MetadataHandler(resource, issuer, c.Scopes)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authn.MetadataPath, nil))
	want := `{"authorization_servers":["https://api.mctl.test"],"bearer_methods_supported":["header"],"resource":"https://glovo.mctl.ai/mcp","resource_name":"mctl Glovo MCP","scopes_supported":["glovo:read","glovo:basket:prepare"]}`
	if strings.TrimSpace(w.Body.String()) != want {
		t.Fatalf("metadata = %s", w.Body)
	}
}

func TestJWKSDown(t *testing.T) {
	r := newRig(t)
	r.jwks.Close()
	tok := r.fake.Mint(fakeapi.MintOpts{Sub: fakeapi.Alice})
	if w := r.do("Bearer "+tok, ""); w.Code != 401 || r.fail[0] != authn.ReasonJWKSDown {
		t.Fatalf("%d %v", w.Code, r.fail)
	}
}
