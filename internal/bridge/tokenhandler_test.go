package bridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

const (
	testHMACSecret      = "test-hmac-secret-bytes-32!!!!!!!"
	testBridgeIssuerURL = "https://tg.test"
)

// fakeProvider satisfies auth.Provider for tests by always returning the
// supplied Identity. The real handler in production reads from
// auth.From(ctx); this fixture seeds that context value directly.
type fakeProvider struct{ id *auth.Identity }

func (f *fakeProvider) Authenticate(r *http.Request) (*auth.Identity, error) {
	return f.id, nil
}

func TestBridgeToken_HonoursIssuerArgument(t *testing.T) {
	id := &auth.Identity{
		UserID:           42,
		Subject:          "tg:42",
		TelegramID:       42,
		TelegramUsername: "alice",
	}
	h := NewBridgeTokenHandler(&fakeProvider{id: id}, []byte(testHMACSecret), testBridgeIssuerURL)
	req := httptest.NewRequest("POST", "/api/bridge/token", nil)
	req = req.WithContext(auth.With(context.Background(), id))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handler status = %d body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		BridgeToken string `json:"bridge_token"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.BridgeToken == "" {
		t.Fatal("empty bridge_token in response")
	}
	parts := strings.Split(resp.BridgeToken, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT: %q", resp.BridgeToken)
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if !strings.Contains(string(body), `"iss":"`+testBridgeIssuerURL+`"`) {
		t.Errorf("token iss does not match supplied issuer: %s", body)
	}
	if !strings.Contains(string(body), `"sub":"tg:42"`) {
		t.Errorf("token sub does not echo Identity.Subject: %s", body)
	}
}

func TestBridgeToken_PrefersSubjectOverGitHubLogin(t *testing.T) {
	// When BOTH are populated, the canonical Subject must win — otherwise
	// localjwt-issued bridge tokens would silently fall back to the
	// legacy github_login claim and break /bridge auth in mixed deployments.
	id := &auth.Identity{
		UserID:      1,
		Subject:     "tg:1",
		GitHubLogin: "legacy-name",
	}
	h := NewBridgeTokenHandler(&fakeProvider{id: id}, []byte(testHMACSecret), testBridgeIssuerURL)
	req := httptest.NewRequest("POST", "/api/bridge/token", nil)
	req = req.WithContext(auth.With(context.Background(), id))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		BridgeToken string `json:"bridge_token"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	parts := strings.Split(resp.BridgeToken, ".")
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if !strings.Contains(string(body), `"sub":"tg:1"`) {
		t.Errorf("sub should be Subject, got %s", body)
	}
	if strings.Contains(string(body), `"sub":"legacy-name"`) {
		t.Errorf("sub should NOT be GitHubLogin when Subject is set: %s", body)
	}
}

func TestBridgeToken_AnonymousReturns401(t *testing.T) {
	h := NewBridgeTokenHandler(&fakeProvider{id: nil}, []byte(testHMACSecret), testBridgeIssuerURL)
	req := httptest.NewRequest("POST", "/api/bridge/token", nil)
	// no auth.With(...) — Identity stays nil
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 anonymous, got %d", rec.Code)
	}
}

// TestBridgeToken_CarriesParentRevocationIdentity pins the containment
// invariant: a bridge token is a delegation of the credential that asked for
// it, so it must inherit that credential's jti and orig_iat. Without the
// inheritance, revoking the parent worker token leaves every bridge token it
// already spawned valid for the rest of bridgeTokenTTL — so evicting a
// compromised daemon only makes it reconnect, and revoke_worker_token's
// promise of immediate containment is false for up to an hour.
func TestBridgeToken_CarriesParentRevocationIdentity(t *testing.T) {
	id := &auth.Identity{
		UserID:           7,
		Subject:          "tg:7",
		TelegramID:       7,
		Jti:              "parent-jti-abc",
		OriginalIssuedAt: 1700000000,
	}
	h := NewBridgeTokenHandler(&fakeProvider{id: id}, []byte(testHMACSecret), testBridgeIssuerURL)
	req := httptest.NewRequest("POST", "/api/bridge/token", nil)
	req = req.WithContext(auth.With(context.Background(), id))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handler status = %d body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		BridgeToken string `json:"bridge_token"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	parts := strings.Split(resp.BridgeToken, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT: %q", resp.BridgeToken)
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		Jti      string `json:"jti"`
		OrigIat  int64  `json:"orig_iat"`
		Audience string `json:"aud"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v (%s)", err, body)
	}
	if claims.Jti != "parent-jti-abc" {
		t.Errorf("bridge token jti = %q, want the parent's %q — revoking the parent would not reach this token", claims.Jti, "parent-jti-abc")
	}
	if claims.OrigIat != 1700000000 {
		t.Errorf("bridge token orig_iat = %d, want the parent's %d — a blanket revocation would anchor this token to its mint instead of to when the credential chain started", claims.OrigIat, 1700000000)
	}
	if claims.Audience != "bridge" {
		t.Errorf("bridge token aud = %q, want \"bridge\"", claims.Audience)
	}
}

// TestBridgeToken_OmitsRevocationClaimsForInteractiveParent is the other half
// of the pair: an interactive session carries neither claim, and the derived
// token must not invent them. A fabricated jti would denylist-match nothing
// and a fabricated orig_iat would misdate the credential chain.
func TestBridgeToken_OmitsRevocationClaimsForInteractiveParent(t *testing.T) {
	id := &auth.Identity{UserID: 8, Subject: "tg:8", TelegramID: 8}
	h := NewBridgeTokenHandler(&fakeProvider{id: id}, []byte(testHMACSecret), testBridgeIssuerURL)
	req := httptest.NewRequest("POST", "/api/bridge/token", nil)
	req = req.WithContext(auth.With(context.Background(), id))
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("handler status = %d body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		BridgeToken string `json:"bridge_token"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	body, err := base64.RawURLEncoding.DecodeString(strings.Split(resp.BridgeToken, ".")[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if strings.Contains(string(body), `"jti"`) || strings.Contains(string(body), `"orig_iat"`) {
		t.Errorf("derived token invented revocation claims for an interactive parent: %s", body)
	}
}
