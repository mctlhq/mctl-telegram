package localjwt

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

var testSecret = []byte("test-secret-bytes-32-bytes-long!!")

const testIssuer = "https://tg.mctl.ai"

func TestMint_Verify_Roundtrip(t *testing.T) {
	iss, err := NewIssuer(testSecret, testIssuer)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	tok, err := iss.Mint(Claims{
		Subject:          "tg:500100101",
		TelegramID:       500100101,
		TelegramUsername: "dana_tg",
		Groups:           []string{"platform-admins"},
		Scopes:           []string{"telegram:dialogs:read"},
	}, 1*time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	c, err := Verify(tok, testSecret, testIssuer)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.Subject != "tg:500100101" {
		t.Errorf("Subject = %q", c.Subject)
	}
	if c.TelegramID != 500100101 {
		t.Errorf("TelegramID = %d", c.TelegramID)
	}
	if c.TelegramUsername != "dana_tg" {
		t.Errorf("TelegramUsername = %q", c.TelegramUsername)
	}
	if len(c.Groups) != 1 || c.Groups[0] != "platform-admins" {
		t.Errorf("Groups = %v", c.Groups)
	}
	if c.Issuer != testIssuer {
		t.Errorf("Issuer = %q", c.Issuer)
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	iss, _ := NewIssuer(testSecret, testIssuer)
	// Mint a token already expired (1s ago).
	tok, err := iss.Mint(Claims{Subject: "tg:1"}, -1*time.Second)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := Verify(tok, testSecret, testIssuer); err == nil {
		t.Fatal("Verify accepted an expired token")
	}
}

func TestVerify_WrongSecret(t *testing.T) {
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, _ := iss.Mint(Claims{Subject: "tg:1"}, 1*time.Hour)
	if _, err := Verify(tok, []byte("different-secret"), testIssuer); err == nil {
		t.Fatal("Verify accepted token signed with different secret")
	}
}

func TestVerify_WrongIssuer(t *testing.T) {
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, _ := iss.Mint(Claims{Subject: "tg:1"}, 1*time.Hour)
	if _, err := Verify(tok, testSecret, "https://other.example"); err == nil {
		t.Fatal("Verify accepted token with different issuer")
	}
}

func TestVerify_MalformedToken(t *testing.T) {
	for _, tok := range []string{"", "a.b", "a.b.c.d", "not-a-jwt", strings.Repeat("a", 50)} {
		if _, err := Verify(tok, testSecret, testIssuer); err == nil {
			t.Errorf("Verify accepted malformed token: %q", tok)
		}
	}
}

func TestCheckAudience(t *testing.T) {
	cases := []struct {
		name     string
		aud      []string
		expected string
		required bool
		wantErr  bool
	}{
		{"no policy", nil, "", false, false},
		{"missing aud + required", nil, "claude", true, true},
		{"missing aud + transitional", nil, "claude", false, false},
		{"match", []string{"claude"}, "claude", true, false},
		{"mismatch", []string{"foo"}, "claude", false, true},
		{"multi match", []string{"foo", "claude"}, "claude", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckAudience(c.aud, c.expected, c.required)
			if (err != nil) != c.wantErr {
				t.Errorf("CheckAudience(%v, %q, %v) err = %v, wantErr=%v",
					c.aud, c.expected, c.required, err, c.wantErr)
			}
		})
	}
}

func TestProvider_AnonymousReturnsNil(t *testing.T) {
	p, err := NewProvider(nil, ProviderConfig{
		Secret:         testSecret,
		ExpectedIssuer: testIssuer,
	})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	id, err := p.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate anonymous: %v", err)
	}
	if id != nil {
		t.Errorf("Authenticate anonymous returned non-nil identity: %+v", id)
	}
}

func TestProvider_NonBearer(t *testing.T) {
	p, _ := NewProvider(nil, ProviderConfig{Secret: testSecret, ExpectedIssuer: testIssuer})
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	if _, err := p.Authenticate(r); err == nil {
		t.Fatal("Authenticate accepted non-Bearer scheme")
	}
}

func TestNewIssuer_Validates(t *testing.T) {
	if _, err := NewIssuer(nil, testIssuer); err == nil {
		t.Error("NewIssuer accepted empty secret")
	}
	if _, err := NewIssuer(testSecret, ""); err == nil {
		t.Error("NewIssuer accepted empty issuer")
	}
}

func TestNewProvider_Validates(t *testing.T) {
	if _, err := NewProvider(nil, ProviderConfig{ExpectedIssuer: testIssuer}); err == nil {
		t.Error("NewProvider accepted empty secret")
	}
	if _, err := NewProvider(nil, ProviderConfig{Secret: testSecret}); err == nil {
		t.Error("NewProvider accepted empty issuer")
	}
}

func TestMint_AudienceSingleAndMulti(t *testing.T) {
	iss, _ := NewIssuer(testSecret, testIssuer)

	tok, err := iss.Mint(Claims{
		Subject:  "tg:1",
		Audience: []string{"claude"},
	}, 1*time.Hour)
	if err != nil {
		t.Fatalf("Mint single aud: %v", err)
	}
	c, err := Verify(tok, testSecret, testIssuer)
	if err != nil {
		t.Fatalf("Verify single aud: %v", err)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "claude" {
		t.Errorf("single aud roundtrip: got %v", c.Audience)
	}

	tok, err = iss.Mint(Claims{
		Subject:  "tg:1",
		Audience: []string{"claude", "other"},
	}, 1*time.Hour)
	if err != nil {
		t.Fatalf("Mint multi aud: %v", err)
	}
	c, err = Verify(tok, testSecret, testIssuer)
	if err != nil {
		t.Fatalf("Verify multi aud: %v", err)
	}
	if len(c.Audience) != 2 {
		t.Errorf("multi aud roundtrip: got %v", c.Audience)
	}
}

func newTestLocaljwtStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &db.Store{DB: conn}
}

func TestProvider_CookieFallback(t *testing.T) {
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, err := iss.Mint(Claims{
		Subject:    "tg:42",
		TelegramID: 42,
	}, time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	store := newTestLocaljwtStore(t)
	p, _ := NewProvider(store, ProviderConfig{
		Secret:         testSecret,
		ExpectedIssuer: testIssuer,
	})

	r := httptest.NewRequest("GET", "/telegram/connect/manage", nil)
	r.AddCookie(&http.Cookie{Name: "mctl_connect_token", Value: tok})

	id, err := p.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate with cookie: %v", err)
	}
	if id == nil {
		t.Fatal("expected non-nil identity from cookie")
	}
	if id.TelegramID != 42 {
		t.Errorf("TelegramID = %d, want 42", id.TelegramID)
	}
}

func TestProvider_CookieFallback_AnonymousWithoutCookie(t *testing.T) {
	p, _ := NewProvider(nil, ProviderConfig{
		Secret:         testSecret,
		ExpectedIssuer: testIssuer,
	})
	r := httptest.NewRequest("GET", "/telegram/connect/manage", nil)
	id, err := p.Authenticate(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != nil {
		t.Errorf("expected nil identity without cookie or header, got %+v", id)
	}
}
