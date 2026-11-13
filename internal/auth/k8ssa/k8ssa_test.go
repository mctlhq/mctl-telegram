package k8ssa

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// Synthetic: the canary persona is Alice (id 11, as in internal/agent).
const (
	aliceTG  int64 = 11
	issuer         = "https://kubernetes.default.svc.cluster.local"
	audience       = "tg.example.test/canary"
	subject        = "system:serviceaccount:labs:labs-mctl-telegram-canary"
)

var t0 = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

type fakeKeys struct {
	sets      []*jose.JSONWebKeySet // returned in order; last one sticks
	refreshes int
	err       error
}

func (f *fakeKeys) Keys(_ context.Context, refresh bool) (*jose.JSONWebKeySet, error) {
	if f.err != nil {
		return nil, f.err
	}
	if refresh {
		f.refreshes++
	}
	i := f.refreshes
	if i >= len(f.sets) {
		i = len(f.sets) - 1
	}
	return f.sets[i], nil
}

type fakeStore struct{ calls int }

func (s *fakeStore) EnsureUserByTelegramID(_ context.Context, tgID int64, _, _ string) (int64, error) {
	s.calls++
	return tgID + 1000, nil
}

type nextProvider struct{ called int }

func (n *nextProvider) Authenticate(*http.Request) (*auth.Identity, error) {
	n.called++
	return &auth.Identity{Provider: "next"}, nil
}

type key struct {
	priv *rsa.PrivateKey
	kid  string
}

func newKey(t *testing.T, kid string) key {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key{priv: k, kid: kid}
}

func (k key) public() *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.priv.PublicKey, KeyID: k.kid, Algorithm: "RS256", Use: "sig"}}}
}

type tokenOpts struct {
	iss, sub string
	aud      []string
	iat, exp time.Time
	noPod    bool
	noExp    bool
}

func defaults() tokenOpts {
	return tokenOpts{iss: issuer, sub: subject, aud: []string{audience}, iat: t0.Add(-time.Minute), exp: t0.Add(9 * time.Minute)}
}

func sign(t *testing.T, k key, o tokenOpts) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k.priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", k.kid))
	if err != nil {
		t.Fatal(err)
	}
	std := jwt.Claims{Issuer: o.iss, Subject: o.sub, Audience: o.aud, IssuedAt: jwt.NewNumericDate(o.iat), NotBefore: jwt.NewNumericDate(o.iat), ID: "jti-1"}
	if !o.noExp {
		std.Expiry = jwt.NewNumericDate(o.exp)
	}
	k8s := map[string]any{"kubernetes.io": map[string]any{
		"namespace":      "labs",
		"serviceaccount": map[string]any{"name": "labs-mctl-telegram-canary", "uid": "sa-uid"},
	}}
	if !o.noPod {
		k8s["kubernetes.io"].(map[string]any)["pod"] = map[string]any{"name": "canary-abc", "uid": "pod-uid"}
	}
	raw, err := jwt.Signed(sig).Claims(std).Claims(k8s).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newProvider(t *testing.T, keys KeySource) (*Provider, *nextProvider, *fakeStore) {
	t.Helper()
	next, store := &nextProvider{}, &fakeStore{}
	p, err := Wrap(next, Config{Issuer: issuer, Audience: audience, Subject: subject, TelegramID: aliceTG, Keys: keys, Store: store, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	return p, next, store
}

func req(token string) *http.Request {
	r := httptest.NewRequest("POST", "/mcp", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func TestAuthenticate_ProjectedTokenMapsToReadOnlyCanary(t *testing.T) {
	k := newKey(t, "k1")
	p, next, store := newProvider(t, &fakeKeys{sets: []*jose.JSONWebKeySet{k.public()}})
	id, err := p.Authenticate(req(sign(t, k, defaults())))
	if err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	if next.called != 0 {
		t.Fatal("a token from the cluster issuer must not reach the next provider")
	}
	if id.TelegramID != aliceTG || id.Subject != "tg:11" || id.Provider != ProviderName || id.UserID != aliceTG+1000 || store.calls != 1 {
		t.Fatalf("unexpected identity %+v", id)
	}
	if strings.Join(id.Scopes, ",") != "telegram:dialogs:read,telegram:messages:read" {
		t.Fatalf("scopes must be read-only, got %v", id.Scopes)
	}
	for _, s := range id.Scopes {
		if strings.Contains(s, "send") || strings.HasPrefix(s, "admin") || s == "account:manage" {
			t.Fatalf("write or admin scope leaked: %s", s)
		}
	}
}

func TestAuthenticate_OtherCredentialsGoToNext(t *testing.T) {
	k := newKey(t, "k1")
	p, next, _ := newProvider(t, &fakeKeys{sets: []*jose.JSONWebKeySet{k.public()}})
	other := defaults()
	other.iss = "https://tg.example.test"
	for name, r := range map[string]*http.Request{
		"anonymous":     req(""),
		"opaque bearer": req("not-a-jwt"),
		"other issuer":  req(sign(t, k, other)),
	} {
		before := next.called
		id, err := p.Authenticate(r)
		if err != nil || id == nil || id.Provider != "next" || next.called != before+1 {
			t.Fatalf("%s: want delegation to next provider, got id=%+v err=%v", name, id, err)
		}
	}
}

func TestAuthenticate_Refusals(t *testing.T) {
	k := newKey(t, "k1")
	stranger := newKey(t, "k1") // same kid, different key: a forged signature
	cases := map[string]func() string{
		"wrong audience": func() string {
			o := defaults()
			o.aud = []string{"https://kubernetes.default.svc.cluster.local"}
			return sign(t, k, o)
		},
		"wrong subject": func() string {
			o := defaults()
			o.sub = "system:serviceaccount:labs:someone-else"
			return sign(t, k, o)
		},
		"expired": func() string {
			o := defaults()
			o.iat, o.exp = t0.Add(-2*time.Hour), t0.Add(-time.Hour)
			return sign(t, k, o)
		},
		"no exp":            func() string { o := defaults(); o.noExp = true; return sign(t, k, o) },
		"lifetime too long": func() string { o := defaults(); o.exp = t0.Add(48 * time.Hour); return sign(t, k, o) },
		"not pod bound":     func() string { o := defaults(); o.noPod = true; return sign(t, k, o) },
		"forged signature":  func() string { return sign(t, stranger, defaults()) },
	}
	for name, mk := range cases {
		p, next, store := newProvider(t, &fakeKeys{sets: []*jose.JSONWebKeySet{k.public()}})
		id, err := p.Authenticate(req(mk()))
		if err == nil || id != nil {
			t.Fatalf("%s: want refusal, got %+v", name, id)
		}
		if next.called != 0 || store.calls != 0 {
			t.Fatalf("%s: a refused cluster token must neither fall through nor provision a user", name)
		}
	}
}

func TestAuthenticate_HS256Refused(t *testing.T) {
	k := newKey(t, "k1")
	sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, nil)
	o := defaults()
	raw, _ := jwt.Signed(sig).Claims(jwt.Claims{Issuer: o.iss, Subject: o.sub, Audience: o.aud, IssuedAt: jwt.NewNumericDate(o.iat), Expiry: jwt.NewNumericDate(o.exp)}).Serialize()
	p, _, _ := newProvider(t, &fakeKeys{sets: []*jose.JSONWebKeySet{k.public()}})
	if _, err := p.Authenticate(req(raw)); err == nil {
		t.Fatal("HS256 token must be refused")
	}
}

func TestAuthenticate_UnknownKidRefreshesOnce(t *testing.T) {
	old, rotated := newKey(t, "old"), newKey(t, "new")
	keys := &fakeKeys{sets: []*jose.JSONWebKeySet{old.public(), rotated.public()}}
	p, _, _ := newProvider(t, keys)
	if _, err := p.Authenticate(req(sign(t, rotated, defaults()))); err != nil {
		t.Fatalf("rotated key should verify after one refresh: %v", err)
	}
	if keys.refreshes != 1 {
		t.Fatalf("want exactly one forced refresh, got %d", keys.refreshes)
	}
}

func TestAuthenticate_KeyFetchFailureIsRefusal(t *testing.T) {
	k := newKey(t, "k1")
	p, next, _ := newProvider(t, &fakeKeys{err: errors.New("api server unreachable")})
	if id, err := p.Authenticate(req(sign(t, k, defaults()))); err == nil || id != nil {
		t.Fatal("could not read the keys must refuse, not accept or fall through")
	}
	if next.called != 0 {
		t.Fatal("must not fall through on a key fetch failure")
	}
}

func TestWrap_ValidatesConfig(t *testing.T) {
	good := Config{Issuer: issuer, Audience: audience, Subject: subject, TelegramID: aliceTG, Keys: &fakeKeys{}, Store: &fakeStore{}}
	bad := map[string]func(c *Config){
		"no issuer":   func(c *Config) { c.Issuer = "" },
		"no audience": func(c *Config) { c.Audience = "" },
		"bad subject": func(c *Config) { c.Subject = "labs:canary" },
		"no tg id":    func(c *Config) { c.TelegramID = 0 },
		"no keys":     func(c *Config) { c.Keys = nil },
	}
	if _, err := Wrap(&nextProvider{}, good); err != nil {
		t.Fatalf("good config refused: %v", err)
	}
	for name, mut := range bad {
		c := good
		mut(&c)
		if _, err := Wrap(&nextProvider{}, c); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
}
