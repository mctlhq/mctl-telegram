package sharedhmac

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func newTestStore(t *testing.T) *db.Store {
	t.Helper()
	rawDB, err := db.Open(context.Background(), "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(context.Background(), rawDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	c, _ := crypto.New(nil)
	return db.NewStore(rawDB, c)
}

func TestAuthenticate_HappyPath(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, err := New(store, Config{Secret: secret, ExpectedIssuer: "https://api.mctl.ai"})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := IssueTestToken(secret, "https://api.mctl.ai", "mashkovd", []string{"platform-admins"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	id, err := p.Authenticate(req)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if id == nil || id.GitHubLogin != "mashkovd" {
		t.Fatalf("identity malformed: %+v", id)
	}
	if !id.HasScope("telegram:messages:send") || !id.HasScope("admin:users") {
		t.Fatalf("expected platform-admins scopes, got %v", id.Scopes)
	}
}

func TestAuthenticate_ExpiredToken(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, _ := New(store, Config{Secret: secret, ExpectedIssuer: "https://api.mctl.ai"})
	tok, _ := IssueTestToken(secret, "https://api.mctl.ai", "x", []string{"telegram-mcp-readers"}, -time.Second)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(req); err == nil {
		t.Fatal("expected expired error")
	}
}

func TestAuthenticate_WrongSecret(t *testing.T) {
	store := newTestStore(t)
	p, _ := New(store, Config{Secret: []byte("real-secret-xxxxxxxxxxxxxxxxxxxx"), ExpectedIssuer: "https://api.mctl.ai"})
	tok, _ := IssueTestToken([]byte("forged-xxxxxxxxxxxxxxxxxxxxxxxxxx"), "https://api.mctl.ai", "x", []string{"platform-admins"}, time.Minute)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(req); err == nil {
		t.Fatal("expected signature error")
	}
}

func TestAuthenticate_WrongIssuer(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, _ := New(store, Config{Secret: secret, ExpectedIssuer: "https://api.mctl.ai"})
	tok, _ := IssueTestToken(secret, "https://evil.example/", "x", nil, time.Minute)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(req); err == nil {
		t.Fatal("expected issuer error")
	}
}

func TestAuthenticate_NoBearer(t *testing.T) {
	store := newTestStore(t)
	p, _ := New(store, Config{Secret: []byte("x"), ExpectedIssuer: "https://api.mctl.ai"})
	req := httptest.NewRequest("POST", "/mcp", nil)
	id, err := p.Authenticate(req)
	if err != nil || id != nil {
		t.Fatalf("no header should yield (nil, nil); got (%+v, %v)", id, err)
	}
}

func TestAuthenticate_AudienceUnconfigured_AnyTokenPasses(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, _ := New(store, Config{Secret: secret, ExpectedIssuer: "https://api.mctl.ai"})
	tok, _ := IssueTestTokenWithAudience(secret, "https://api.mctl.ai", "x",
		[]string{"platform-admins"}, []string{"https://elsewhere/"}, time.Minute)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(req); err != nil {
		t.Fatalf("expected success when audience policy is disabled, got %v", err)
	}
}

func TestAuthenticate_AudienceTransitional_MissingTokenPasses(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, _ := New(store, Config{
		Secret:           secret,
		ExpectedIssuer:   "https://api.mctl.ai",
		ExpectedAudience: "https://tg.mctl.ai",
		AudienceRequired: false,
	})
	tok, _ := IssueTestToken(secret, "https://api.mctl.ai", "x",
		[]string{"platform-admins"}, time.Minute)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(req); err != nil {
		t.Fatalf("transitional mode should allow tokens without aud, got %v", err)
	}
}

func TestAuthenticate_AudienceTransitional_MismatchRejected(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, _ := New(store, Config{
		Secret:           secret,
		ExpectedIssuer:   "https://api.mctl.ai",
		ExpectedAudience: "https://tg.mctl.ai",
		AudienceRequired: false,
	})
	tok, _ := IssueTestTokenWithAudience(secret, "https://api.mctl.ai", "x",
		[]string{"platform-admins"}, []string{"https://elsewhere/"}, time.Minute)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(req); err == nil {
		t.Fatal("present-but-wrong audience must be rejected even in transitional mode")
	}
}

func TestAuthenticate_AudienceStrict_MissingRejected(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, _ := New(store, Config{
		Secret:           secret,
		ExpectedIssuer:   "https://api.mctl.ai",
		ExpectedAudience: "https://tg.mctl.ai",
		AudienceRequired: true,
	})
	tok, _ := IssueTestToken(secret, "https://api.mctl.ai", "x",
		[]string{"platform-admins"}, time.Minute)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(req); err == nil {
		t.Fatal("strict mode must reject tokens without aud claim")
	}
}

func TestAuthenticate_AudienceStrict_MatchPasses(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, _ := New(store, Config{
		Secret:           secret,
		ExpectedIssuer:   "https://api.mctl.ai",
		ExpectedAudience: "https://tg.mctl.ai",
		AudienceRequired: true,
	})
	tok, _ := IssueTestTokenWithAudience(secret, "https://api.mctl.ai", "x",
		[]string{"platform-admins"}, []string{"https://tg.mctl.ai"}, time.Minute)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(req); err != nil {
		t.Fatalf("expected success on matching audience, got %v", err)
	}
}

func TestAuthenticate_AudienceArray_AnyMatchPasses(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, _ := New(store, Config{
		Secret:           secret,
		ExpectedIssuer:   "https://api.mctl.ai",
		ExpectedAudience: "https://tg.mctl.ai",
		AudienceRequired: true,
	})
	// Multi-audience token: one of the values matches.
	tok, _ := IssueTestTokenWithAudience(secret, "https://api.mctl.ai", "x",
		[]string{"platform-admins"},
		[]string{"https://api.mctl.ai", "https://tg.mctl.ai"}, time.Minute)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(req); err != nil {
		t.Fatalf("expected success on multi-audience with match, got %v", err)
	}
}

// forgeJWTWithRawAudience signs a JWT body that already contains the desired
// `aud` JSON fragment verbatim — useful for forging malformed shapes the
// IssueTestToken*** helpers won't produce.
func forgeJWTWithRawAudience(t *testing.T, secret []byte, audRaw string) string {
	t.Helper()
	hdr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	body := fmt.Sprintf(
		`{"iss":"https://api.mctl.ai","sub":"x","groups":["platform-admins"],"iat":%d,"exp":%d,"aud":%s}`,
		time.Now().Unix(), time.Now().Add(time.Minute).Unix(), audRaw,
	)
	bodyB64 := base64.RawURLEncoding.EncodeToString([]byte(body))
	sigInput := hdr + "." + bodyB64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	return sigInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestAuthenticate_MalformedAudienceRejected(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, _ := New(store, Config{
		Secret:           secret,
		ExpectedIssuer:   "https://api.mctl.ai",
		ExpectedAudience: "https://tg.mctl.ai",
		// Even in transitional mode, malformed aud must NOT be treated as
		// absent — the policy says "if aud is present it must match",
		// and a number/object/mixed-array is "present, but unmatchable".
	})
	tok := forgeJWTWithRawAudience(t, secret, `42`)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(req); err == nil {
		t.Fatal("malformed aud (number) must be rejected, not silently treated as absent")
	}
}

func TestAuthenticate_MixedTypeAudienceArrayRejected(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, _ := New(store, Config{
		Secret:           secret,
		ExpectedIssuer:   "https://api.mctl.ai",
		ExpectedAudience: "https://tg.mctl.ai",
	})
	// Array contains a non-string even though the matching string is in
	// there too. The whole claim is malformed, must be rejected.
	tok := forgeJWTWithRawAudience(t, secret, `["https://tg.mctl.ai",7]`)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(req); err == nil {
		t.Fatal("mixed-type aud array must be rejected even if it contains the right string")
	}
}

// TestDefaultGroupScopes_AdminsIsReadOnly verifies the M2.6 invariant: users
// in the "admins" group must NOT receive write scopes by default.
func TestDefaultGroupScopes_AdminsIsReadOnly(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, err := New(store, Config{Secret: secret, ExpectedIssuer: "https://api.mctl.ai"})
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := IssueTestToken(secret, "https://api.mctl.ai", "someuser", []string{"admins"}, time.Minute)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	id, err := p.Authenticate(req)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if id.HasScope("telegram:messages:send") {
		t.Error("admins group must NOT have telegram:messages:send by default")
	}
	if id.HasScope("telegram:messages:pin") {
		t.Error("admins group must NOT have telegram:messages:pin by default")
	}
	if id.HasScope("admin:users") {
		t.Error("admins group must NOT have admin:users by default")
	}
	if !id.HasScope("telegram:dialogs:read") || !id.HasScope("telegram:messages:read") {
		t.Errorf("admins group must retain read scopes, got %v", id.Scopes)
	}
}

// TestDefaultGroupScopes_SendersHavePin verifies telegram-mcp-senders gets
// messages:pin in addition to messages:send (M2.6).
func TestDefaultGroupScopes_SendersHavePin(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, _ := New(store, Config{Secret: secret, ExpectedIssuer: "https://api.mctl.ai"})
	tok, _ := IssueTestToken(secret, "https://api.mctl.ai", "sender", []string{"telegram-mcp-senders"}, time.Minute)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	id, err := p.Authenticate(req)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !id.HasScope("telegram:messages:send") || !id.HasScope("telegram:messages:pin") {
		t.Errorf("telegram-mcp-senders must have send+pin, got %v", id.Scopes)
	}
	if id.HasScope("admin:users") {
		t.Error("telegram-mcp-senders must NOT have admin:users")
	}
}

func TestAuthenticate_GroupGate(t *testing.T) {
	store := newTestStore(t)
	secret := []byte("test-secret-32bytes-aaaaaaaaaaaaa")
	p, _ := New(store, Config{
		Secret:         secret,
		ExpectedIssuer: "https://api.mctl.ai",
		AllowedGroups:  []string{"telegram-mcp-readers", "platform-admins"},
	})
	tok, _ := IssueTestToken(secret, "https://api.mctl.ai", "x", []string{"some-other-tenant"}, time.Minute)
	req := httptest.NewRequest("POST", "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, err := p.Authenticate(req); err == nil {
		t.Fatal("expected group-gate rejection")
	}
}
