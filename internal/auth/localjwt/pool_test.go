package localjwt

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

func newPoolFixture(t *testing.T) (*PoolProvider, *Issuer, *RevocationCache) {
	t.Helper()
	store := newTestLocaljwtStore(t)
	cache := NewRevocationCache(store, time.Minute)
	p, err := NewPoolProvider(PoolProviderConfig{Secret: testSecret, ExpectedIssuer: testIssuer, RevocationCache: cache})
	if err != nil {
		t.Fatalf("new pool provider: %v", err)
	}
	iss, _ := NewIssuer(testSecret, testIssuer)
	return p, iss, cache
}

func TestNewPoolProvider_RefusesNilRevocationCache(t *testing.T) {
	if _, err := NewPoolProvider(PoolProviderConfig{Secret: testSecret, ExpectedIssuer: testIssuer}); err == nil {
		t.Fatal("a pool provider without a revocation cache must not exist")
	}
}

func TestPoolProvider_ValidToken(t *testing.T) {
	p, iss, _ := newPoolFixture(t)
	tok, err := iss.Mint(Claims{Subject: "pool:main", Audience: []string{PoolAudience}, Jti: "pj", OriginalIssuedAt: 1700000000}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	id, err := p.Authenticate(r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if id.UserID != 0 || id.TelegramID != 0 || id.Pool != "main" || id.Jti != "pj" || id.OriginalIssuedAt != 1700000000 || !id.IsPool() {
		t.Fatalf("unexpected identity %+v", id)
	}
}

func TestPoolProvider_RejectsAccountShapedClaims(t *testing.T) {
	p, iss, _ := newPoolFixture(t)
	base := func() Claims {
		return Claims{Subject: "pool:main", Audience: []string{PoolAudience}, Jti: "pj"}
	}
	cases := map[string]func(c *Claims){
		"telegram_id":  func(c *Claims) { c.TelegramID = 7 },
		"tg_username":  func(c *Claims) { c.TelegramUsername = "alice" },
		"job_id":       func(c *Claims) { c.JobID = 1 },
		"job_attempt":  func(c *Claims) { c.JobAttempt = 1 },
		"conv_id":      func(c *Claims) { c.ConversationID = 1 },
		"job_tools":    func(c *Claims) { c.JobTools = []string{"x"} },
		"no jti":       func(c *Claims) { c.Jti = "" },
		"tg subject":   func(c *Claims) { c.Subject = "tg:7" },
		"bad name":     func(c *Claims) { c.Subject = "pool:Bad_Name" },
		"empty name":   func(c *Claims) { c.Subject = "pool:" },
		"agent aud":    func(c *Claims) { c.Audience = []string{"agent"} },
		"device claim": func(c *Claims) { c.DeviceID = "d" },
	}
	for name, mod := range cases {
		c := base()
		mod(&c)
		tok, err := iss.Mint(c, time.Hour)
		if err != nil {
			t.Fatalf("%s: mint: %v", name, err)
		}
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		if id, err := p.Authenticate(r); err == nil {
			t.Errorf("%s: accepted, identity %+v", name, id)
		}
	}
}

func TestPoolToken_RefusedByAccountAndJobProviders(t *testing.T) {
	store := newTestLocaljwtStore(t)
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, _ := iss.Mint(Claims{Subject: "pool:main", Audience: []string{PoolAudience}, Jti: "pj"}, time.Hour)
	for _, aud := range []string{"agent", "agent-job"} {
		p, err := NewProvider(store, ProviderConfig{Secret: testSecret, ExpectedIssuer: testIssuer, ExpectedAudience: aud, AudienceRequired: true})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		if _, err := p.Authenticate(r); err == nil {
			t.Errorf("aud=%s provider accepted a pool token", aud)
		}
	}
}

func TestPoolProvider_RevokedJtiRejected_BlanketDoesNotRevokePool(t *testing.T) {
	store := newTestLocaljwtStore(t)
	ctx := context.Background()
	cache := NewRevocationCache(store, time.Minute)
	p, err := NewPoolProvider(PoolProviderConfig{Secret: testSecret, ExpectedIssuer: testIssuer, RevocationCache: cache})
	if err != nil {
		t.Fatal(err)
	}
	iss, _ := NewIssuer(testSecret, testIssuer)
	live, _ := iss.Mint(Claims{Subject: "pool:main", Audience: []string{PoolAudience}, Jti: "live", OriginalIssuedAt: time.Now().Add(-time.Hour).Unix()}, time.Hour)
	dead, _ := iss.Mint(Claims{Subject: "pool:main", Audience: []string{PoolAudience}, Jti: "dead"}, time.Hour)
	if err := store.RevokeWorkerToken(ctx, "dead", 0, "leak", 1); err != nil {
		t.Fatalf("revoke jti: %v", err)
	}
	if err := store.RevokeWorkerTokensForTelegramID(ctx, 42, "blanket", 1); err != nil {
		t.Fatalf("revoke blanket: %v", err)
	}
	auth := func(tok string) error {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		_, err := p.Authenticate(r)
		return err
	}
	if err := auth(dead); err == nil {
		t.Error("revoked pool jti must be rejected")
	}
	if err := auth(live); err != nil {
		t.Errorf("blanket revocation of an account must not revoke the pool: %v", err)
	}
	blanket, err := cache.IsBlanketRevoked(ctx, 42, time.Now().Add(-time.Hour))
	if err != nil || !blanket {
		t.Errorf("IsBlanketRevoked = %v, %v; want true", blanket, err)
	}
	if other, _ := cache.IsBlanketRevoked(ctx, 43, time.Now().Add(-time.Hour)); other {
		t.Error("IsBlanketRevoked must not match another telegram id")
	}
}

func TestPoolProvider_ColdCacheErrorFailsClosed(t *testing.T) {
	broken := newBrokenLocaljwtStore(t, "poolbroken")
	cache := NewRevocationCache(broken, time.Minute)
	p, _ := NewPoolProvider(PoolProviderConfig{Secret: testSecret, ExpectedIssuer: testIssuer, RevocationCache: cache})
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, _ := iss.Mint(Claims{Subject: "pool:main", Audience: []string{PoolAudience}, Jti: "pj"}, time.Hour)
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(r); err == nil {
		t.Fatal("a cold revocation cache error must reject the pool token")
	}
	if _, err := cache.IsBlanketRevoked(context.Background(), 1, time.Now()); err == nil {
		t.Fatal("IsBlanketRevoked must fail closed on a cold cache error")
	}
}
