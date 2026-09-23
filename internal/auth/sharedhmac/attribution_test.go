package sharedhmac

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

const (
	attrTestIssuer = "https://api.mctl.ai"
)

var attrTestSecret = []byte("test-secret-32bytes-aaaaaaaaaaaaa")

// TestVerifyJWT_NoPayloadAtOrBeforeSignature is the sharedhmac mirror of
// localjwt's TestVerifyWithClaims_NoClaimsAtOrBeforeSignature — the security
// assertion behind item 2 of issue-668: a token that fails at or before the
// hmac.Equal check must come back with a nil payload, because those bytes
// are unauthenticated attacker-controlled input. A refactor that moved the
// json.Unmarshal above the MAC check, or returned &p from the "malformed JWT
// payload" branch, fails here.
func TestVerifyJWT_NoPayloadAtOrBeforeSignature(t *testing.T) {
	tok, err := IssueTestToken(attrTestSecret, attrTestIssuer, "alice", []string{"telegram-mcp-readers"}, time.Hour)
	if err != nil {
		t.Fatalf("IssueTestToken: %v", err)
	}

	t.Run("malformed token", func(t *testing.T) {
		p, err := verifyJWT("not-a-jwt", attrTestSecret, attrTestIssuer)
		if err == nil {
			t.Fatal("expected an error for a malformed token")
		}
		if p != nil {
			t.Fatalf("expected nil payload for a malformed token, got %+v", p)
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		parts := strings.Split(tok, ".")
		tampered := parts[0] + "." + parts[1] + ".not-the-real-signature"
		p, err := verifyJWT(tampered, attrTestSecret, attrTestIssuer)
		if err == nil {
			t.Fatal("expected an error for a tampered signature")
		}
		if p != nil {
			t.Fatalf("expected nil payload for a tampered signature, got %+v", p)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		p, err := verifyJWT(tok, []byte("a-completely-different-secret!!"), attrTestIssuer)
		if err == nil {
			t.Fatal("expected an error for the wrong secret")
		}
		if p != nil {
			t.Fatalf("expected nil payload for the wrong secret, got %+v", p)
		}
	})
}

// TestVerifyJWT_PayloadPresentAfterSignature is the other half: a token whose
// signature verifies but is rejected for issuer or expiry must come back with
// a non-nil payload, since our own HMAC key vouched for it.
func TestVerifyJWT_PayloadPresentAfterSignature(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		tok, err := IssueTestToken(attrTestSecret, attrTestIssuer, "alice", nil, -time.Second)
		if err != nil {
			t.Fatalf("IssueTestToken: %v", err)
		}
		p, err := verifyJWT(tok, attrTestSecret, attrTestIssuer)
		if err == nil {
			t.Fatal("expected an error for an expired token")
		}
		if p == nil || p.Subject != "alice" || p.ExpiresAt == 0 {
			t.Fatalf("expected the signed payload alongside the expiry error, got %+v", p)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		tok, err := IssueTestToken(attrTestSecret, attrTestIssuer, "alice", nil, time.Hour)
		if err != nil {
			t.Fatalf("IssueTestToken: %v", err)
		}
		p, err := verifyJWT(tok, attrTestSecret, "https://other.example")
		if err == nil {
			t.Fatal("expected an error for the wrong issuer")
		}
		if p == nil || p.Subject != "alice" {
			t.Fatalf("expected the signed payload alongside the issuer error, got %+v", p)
		}
	})
}

// attributionFromProviderFailure drives Provider.Authenticate with tok and
// returns the AttributedError's attribution, if any.
func attributionFromProviderFailure(t *testing.T, p *Provider, tok string) (auth.TokenAttribution, bool, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	_, err := p.Authenticate(r)
	if err == nil {
		return auth.TokenAttribution{}, false, nil
	}
	attr, ok := auth.AttributionOf(err)
	return attr, ok, err
}

// TestProvider_AttributesPostSignatureFailuresOnly is the provider-level
// mirror of localjwt's test of the same name: an expired-but-signed token's
// failure carries sub and exp; a tampered-signature or wrong-secret token's
// failure carries no attribution at all.
func TestProvider_AttributesPostSignatureFailuresOnly(t *testing.T) {
	store := newTestStore(t)
	p, err := New(store, Config{Secret: attrTestSecret, ExpectedIssuer: attrTestIssuer})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("expired token is attributed", func(t *testing.T) {
		tok, err := IssueTestToken(attrTestSecret, attrTestIssuer, "alice", []string{"telegram-mcp-readers"}, -time.Second)
		if err != nil {
			t.Fatalf("IssueTestToken: %v", err)
		}
		attr, ok, err := attributionFromProviderFailure(t, p, tok)
		if err == nil {
			t.Fatal("expected an error for an expired token")
		}
		if !ok {
			t.Fatalf("expected an AttributedError, got a plain %v", err)
		}
		if attr.Subject != "alice" || attr.ExpiresAt == 0 {
			t.Errorf("attribution = %+v", attr)
		}
		// mctl-api's JWT shape has no client_id or jti; they must stay empty
		// rather than be filled from anything else.
		if attr.ClientID != "" || attr.Jti != "" {
			t.Errorf("client_id/jti must be empty for a shared-hmac token, got %+v", attr)
		}
	})

	t.Run("tampered signature is never attributed", func(t *testing.T) {
		tok, err := IssueTestToken(attrTestSecret, attrTestIssuer, "evil-controlled-subject", nil, time.Hour)
		if err != nil {
			t.Fatalf("IssueTestToken: %v", err)
		}
		parts := strings.Split(tok, ".")
		tampered := parts[0] + "." + parts[1] + ".not-the-real-signature"
		_, ok, err := attributionFromProviderFailure(t, p, tampered)
		if err == nil {
			t.Fatal("expected an error for a tampered signature")
		}
		if ok {
			t.Fatal("a tampered-signature token must never carry an attribution — its claims are attacker-controlled")
		}
	})

	t.Run("wrong secret is never attributed", func(t *testing.T) {
		tok, err := IssueTestToken([]byte("a-completely-different-secret!!"), attrTestIssuer, "evil-controlled-subject", nil, time.Hour)
		if err != nil {
			t.Fatalf("IssueTestToken: %v", err)
		}
		_, ok, err := attributionFromProviderFailure(t, p, tok)
		if err == nil {
			t.Fatal("expected an error for a token signed with the wrong secret")
		}
		if ok {
			t.Fatal("a wrong-secret token must never carry an attribution")
		}
	})
}
