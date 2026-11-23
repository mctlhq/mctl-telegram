package localjwt

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// pa-job tokens (issue #1313 slice d1): bound to one principal, one job
// attempt and one context digest; revocable through the pool credential
// that claimed the job and through the principal.

const paDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func paJob() PAJob {
	return PAJob{Principal: 555, JobID: 7, Attempt: 1, ContextDigest: paDigest, Tools: []string{"tg/get_messages"}}
}

func newPAJobFixture(t *testing.T) (*PAJobVerifier, *Issuer, *RevocationCache, func() error) {
	t.Helper()
	store := newTestLocaljwtStore(t)
	cache := NewRevocationCache(store, time.Minute)
	v, err := NewPAJobVerifier(testSecret, testIssuer, cache)
	if err != nil {
		t.Fatal(err)
	}
	iss, _ := NewIssuer(testSecret, testIssuer)
	return v, iss, cache, func() error {
		return store.RevokeWorkerTokensForTelegramID(context.Background(), 555, "test", 1)
	}
}

func TestPAJob_MintAndVerify(t *testing.T) {
	v, iss, _, _ := newPAJobFixture(t)
	tok, err := iss.MintPAJob(paJob(), "pool-jti", 1700000000, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Principal != 555 || got.JobID != 7 || got.Attempt != 1 || got.ContextDigest != paDigest ||
		len(got.Tools) != 1 || got.Tools[0] != "tg/get_messages" || got.Jti != "pool-jti" {
		t.Fatalf("got %+v", got)
	}
	r := httptest.NewRequest("POST", "/", nil)
	if _, err := v.VerifyRequest(r); err == nil {
		t.Fatal("no bearer accepted")
	}
	r.Header.Set("Cookie", "mctl_tg_session="+tok)
	if _, err := v.VerifyRequest(r); err == nil {
		t.Fatal("cookie accepted")
	}
}

func TestPAJob_MintRefusesBadShape(t *testing.T) {
	_, iss, _, _ := newPAJobFixture(t)
	cases := map[string]func(*PAJob){
		"no principal": func(j *PAJob) { j.Principal = 0 },
		"no job":       func(j *PAJob) { j.JobID = 0 },
		"no attempt":   func(j *PAJob) { j.Attempt = 0 },
		"bad digest":   func(j *PAJob) { j.ContextDigest = "ABC" },
		"upper digest": func(j *PAJob) { j.ContextDigest = strings.ToUpper(paDigest) },
	}
	for name, mut := range cases {
		j := paJob()
		mut(&j)
		if _, err := iss.MintPAJob(j, "pj", 0, time.Minute); err == nil {
			t.Errorf("%s: minted", name)
		}
	}
	if _, err := iss.MintPAJob(paJob(), "", 0, time.Minute); err == nil {
		t.Error("minted without a parent jti")
	}
	if _, err := iss.MintPAJob(paJob(), "pj", 0, MaxPAJobTTL+time.Second); err == nil {
		t.Error("minted past the max ttl")
	}
}

// TestPAJob_VerifierRefusesOtherShapes: a token is a pa-job token only
// with exactly that audience and the full binding; anything extra or
// missing is refused, so an account or pool token cannot pass for one.
func TestPAJob_VerifierRefusesOtherShapes(t *testing.T) {
	v, iss, _, _ := newPAJobFixture(t)
	base := func() Claims {
		return Claims{
			Subject: "pa:555", TelegramID: 555, PAPrincipal: 555, JobID: 7, JobAttempt: 1,
			ContextDigest: paDigest, Jti: "pj", Audience: []string{PAJobAudience},
		}
	}
	if tok, _ := iss.Mint(base(), time.Minute); func() error { _, err := v.Verify(context.Background(), tok); return err }() != nil {
		t.Fatal("the base shape must verify")
	}
	cases := map[string]func(*Claims){
		"pool audience":     func(c *Claims) { c.Audience = []string{PoolAudience} },
		"two audiences":     func(c *Claims) { c.Audience = []string{PAJobAudience, "agent"} },
		"principal differs": func(c *Claims) { c.TelegramID = 556 },
		"subject differs":   func(c *Claims) { c.Subject = "pa:556" },
		"tg subject":        func(c *Claims) { c.Subject = "tg:555" },
		"no digest":         func(c *Claims) { c.ContextDigest = "" },
		"no jti":            func(c *Claims) { c.Jti = "" },
		"conversation":      func(c *Claims) { c.ConversationID = 1 },
		"username":          func(c *Claims) { c.TelegramUsername = "alice" },
		"no principal":      func(c *Claims) { c.PAPrincipal = 0 },
	}
	for name, mut := range cases {
		c := base()
		mut(&c)
		tok, err := iss.Mint(c, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
	// Another issuer's key.
	other, _ := NewIssuer([]byte(strings.Repeat("z", 32)), testIssuer)
	tok, _ := other.MintPAJob(paJob(), "pj", 0, time.Minute)
	if _, err := v.Verify(context.Background(), tok); err == nil {
		t.Error("a token signed with another key verified")
	}
}

func TestPAJob_Revocation(t *testing.T) {
	t.Run("by principal", func(t *testing.T) {
		v, iss, _, revokeAll := newPAJobFixture(t)
		tok, _ := iss.MintPAJob(paJob(), "pool-jti", time.Now().Add(-time.Minute).Unix(), time.Minute)
		if err := revokeAll(); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Fatal("revoked principal's pa-job token verified")
		}
	})
	t.Run("by pool jti", func(t *testing.T) {
		store := newTestLocaljwtStore(t)
		cache := NewRevocationCache(store, time.Minute)
		v, _ := NewPAJobVerifier(testSecret, testIssuer, cache)
		iss, _ := NewIssuer(testSecret, testIssuer)
		tok, _ := iss.MintPAJob(paJob(), "pool-jti", 0, time.Minute)
		if err := store.RevokeWorkerToken(context.Background(), "pool-jti", 0, "test", 1); err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(context.Background(), tok); err == nil {
			t.Fatal("a pa-job token under a revoked pool credential verified")
		}
	})
	if _, err := NewPAJobVerifier(testSecret, testIssuer, nil); err == nil {
		t.Fatal("a verifier without a revocation cache must not exist")
	}
}

// TestProvider_RefusesPAJobTokens: the account provider (and so /mcp,
// where the audience check is optional) never accepts a pa-job token.
func TestProvider_RefusesPAJobTokens(t *testing.T) {
	store := newTestLocaljwtStore(t)
	p, err := NewProvider(store, ProviderConfig{Secret: testSecret, ExpectedIssuer: testIssuer})
	if err != nil {
		t.Fatal(err)
	}
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, err := iss.MintPAJob(paJob(), "pj", 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	if id, err := p.Authenticate(r); err == nil {
		t.Fatalf("account provider accepted a pa-job token: %+v", id)
	}
}
